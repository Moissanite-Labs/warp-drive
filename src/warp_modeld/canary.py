"""Stage 3 fail-closed gate: verifier-owned shadow-load canary runner."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Any, Sequence

from .errors import CanaryFailedError, ForgedCanaryError, WarpError
from .fingerprint import AdapterBundle
from .llama_client import LlamaClientError, LlamaServerClient

FORBIDDEN_ADAPTER_CANARY_KEYS = frozenset(
    {
        "canaries",
        "canary",
        "canary_suite",
        "canary_results",
        "canary_pass",
        "canary_passed",
        "canary_override",
        "skip_canaries",
        "self_reported_pass",
        "verifier_override",
        "expected_outputs",
    }
)


class CanaryConfigError(WarpError):
    code = "ERR_CANARY_CONFIG"
    stage = "stage3_canary"


def reject_adapter_supplied_canaries(payload: Any, path: str = "root") -> None:
    """Recursively reject any adapter manifest attempting to supply or override canaries."""
    if isinstance(payload, dict):
        for key, value in payload.items():
            norm = str(key).strip().lower()
            if norm in FORBIDDEN_ADAPTER_CANARY_KEYS:
                raise ForgedCanaryError(
                    f"adapter payload attempted to supply forbidden canary field '{key}' at {path}"
                )
            reject_adapter_supplied_canaries(value, f"{path}.{key}")
    elif isinstance(payload, (list, tuple)):
        for idx, item in enumerate(payload):
            reject_adapter_supplied_canaries(item, f"{path}[{idx}]")


def _strip_fenced_code_blocks(text: str) -> str:
    """Return only prose lines outside triple-backtick fenced code blocks."""
    out: list[str] = []
    in_fence = False
    for line in text.splitlines():
        if line.lstrip().startswith("```"):
            in_fence = not in_fence
            continue
        if not in_fence:
            out.append(line)
    return "\n".join(out)


@dataclass(frozen=True)
class CanarySpec:
    canary_id: str
    category: str  # "preservation" | "domain" | "cross_adapter"
    prompt: str
    domains: tuple[str, ...] = ()
    system_prompt: str | None = None
    must_contain: tuple[str, ...] = ()
    must_not_contain: tuple[str, ...] = ()
    prose_only_forbid: tuple[str, ...] = ()
    regex_must_match: tuple[str, ...] = ()
    regex_must_not_match: tuple[str, ...] = ()
    min_chars: int = 1
    max_chars: int | None = None

    def __post_init__(self) -> None:
        if self.category not in ("preservation", "domain", "cross_adapter"):
            raise CanaryConfigError(f"invalid canary category: {self.category}")
        if not self.canary_id.strip() or not self.prompt.strip():
            raise CanaryConfigError("canary_id and prompt must be non-empty")
        if self.category == "domain" and len(self.domains) != 1:
            raise CanaryConfigError(f"domain canary {self.canary_id} must specify exactly 1 domain")
        if self.category == "cross_adapter" and len(self.domains) < 2:
            raise CanaryConfigError(f"cross_adapter canary {self.canary_id} must specify at least 2 domains")

    def evaluate(self, response_text: str) -> list[str]:
        """Return a list of deterministic rule failure reasons (empty means pass)."""
        failures: list[str] = []
        if len(response_text) < self.min_chars:
            failures.append(f"output length {len(response_text)} < min_chars {self.min_chars}")
        if self.max_chars is not None and len(response_text) > self.max_chars:
            failures.append(f"output length {len(response_text)} > max_chars {self.max_chars}")

        for needle in self.must_contain:
            if needle not in response_text:
                failures.append(f"missing required substring {needle!r}")

        for forbidden in self.must_not_contain:
            if forbidden in response_text:
                failures.append(f"found forbidden substring {forbidden!r}")

        if self.prose_only_forbid:
            prose = _strip_fenced_code_blocks(response_text)
            for forbidden in self.prose_only_forbid:
                if forbidden in prose:
                    failures.append(f"found forbidden prose substring {forbidden!r}")

        for pattern in self.regex_must_match:
            if re.search(pattern, response_text, re.MULTILINE) is None:
                failures.append(f"did not match required regex {pattern!r}")

        for pattern in self.regex_must_not_match:
            if re.search(pattern, response_text, re.MULTILINE) is not None:
                failures.append(f"matched forbidden regex {pattern!r}")

        return failures

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CanarySpec:
        if not isinstance(data, dict):
            raise CanaryConfigError("canary entry must be a mapping")
        try:
            return cls(
                canary_id=str(data["canary_id"]),
                category=str(data["category"]),
                prompt=str(data["prompt"]),
                domains=tuple(str(d) for d in data.get("domains", ())),
                system_prompt=data.get("system_prompt"),
                must_contain=tuple(str(x) for x in data.get("must_contain", ())),
                must_not_contain=tuple(str(x) for x in data.get("must_not_contain", ())),
                prose_only_forbid=tuple(str(x) for x in data.get("prose_only_forbid", ())),
                regex_must_match=tuple(str(x) for x in data.get("regex_must_match", ())),
                regex_must_not_match=tuple(str(x) for x in data.get("regex_must_not_match", ())),
                min_chars=int(data.get("min_chars", 1)),
                max_chars=int(data["max_chars"]) if data.get("max_chars") is not None else None,
            )
        except KeyError as exc:
            raise CanaryConfigError(f"missing canary field: {exc}") from exc


@dataclass(frozen=True)
class CanarySuite:
    """OS-owned read-only suite of preservation, domain, and cross-adapter canaries."""

    suite_sha256: str
    canaries: tuple[CanarySpec, ...]
    source_path: str

    @classmethod
    def from_verifier_file(
        cls,
        path: str | Path,
        *,
        expected_sha256: str | None = None,
        min_preservation: int = 4,
        reject_world_writable: bool = True,
    ) -> CanarySuite:
        file_path = Path(path)
        if not file_path.is_file():
            raise CanaryConfigError(f"verifier canary file not found: {file_path}")

        if reject_world_writable and os.name == "posix":
            mode = file_path.stat().st_mode
            if mode & stat.S_IWOTH:
                raise CanaryConfigError(f"verifier canary file must not be world-writable: {file_path}")

        raw_bytes = file_path.read_bytes()
        actual_sha = hashlib.sha256(raw_bytes).hexdigest()
        if expected_sha256 is not None and not hmac.compare_digest(actual_sha, expected_sha256):
            raise CanaryConfigError(
                f"verifier canary suite digest mismatch: got {actual_sha}, expected {expected_sha256}"
            )

        try:
            parsed = json.loads(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise CanaryConfigError(f"invalid verifier canary JSON: {exc}") from exc

        if not isinstance(parsed, dict) or not isinstance(parsed.get("canaries"), list):
            raise CanaryConfigError("verifier canary file must contain a 'canaries' list")

        specs = tuple(CanarySpec.from_dict(item) for item in parsed["canaries"])
        preservation_count = sum(1 for spec in specs if spec.category == "preservation")
        if preservation_count < min_preservation:
            raise CanaryConfigError(
                f"verifier canary suite requires at least {min_preservation} preservation canaries "
                f"(found {preservation_count})"
            )

        return cls(suite_sha256=actual_sha, canaries=specs, source_path=str(file_path))

    def select_for_domains(self, domains: Sequence[str]) -> list[CanarySpec]:
        domain_set = set(domains)
        preservation = [c for c in self.canaries if c.category == "preservation"]
        domain_matches = [c for c in self.canaries if c.category == "domain" and c.domains[0] in domain_set]
        cross_matches = [
            c
            for c in self.canaries
            if c.category == "cross_adapter" and len(domain_set) > 1 and set(c.domains).issubset(domain_set)
        ]

        # Every requested adapter domain must have at least one verifier-owned domain canary.
        covered_domains = {c.domains[0] for c in domain_matches}
        missing_domains = sorted(domain_set - covered_domains)
        if missing_domains:
            raise CanaryFailedError(
                f"no verifier-owned domain canaries configured for domains: {missing_domains}"
            )

        preservation.sort(key=lambda c: c.canary_id)
        domain_matches.sort(key=lambda c: c.canary_id)
        cross_matches.sort(key=lambda c: c.canary_id)
        return preservation + domain_matches + cross_matches


@dataclass(frozen=True)
class CanaryCheckOutcome:
    canary_id: str
    category: str
    passed: bool
    failures: tuple[str, ...]


@dataclass(frozen=True)
class CanaryResult:
    suite_sha256: str
    outcomes: tuple[CanaryCheckOutcome, ...]
    preservation_passed: int
    preservation_total: int
    canary_slot_flushed: bool


def _extract_chat_content(response: dict[str, Any]) -> str:
    choices = response.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            msg = first.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]
            if isinstance(first.get("text"), str):
                return first["text"]
    if isinstance(response.get("content"), str):
        return response["content"]
    raise CanaryFailedError("llama-server returned response without assistant text content")


class CanaryRunner:
    """Executes shadow-loaded verifier-owned canaries against llama-server."""

    def __init__(
        self,
        llama_client: LlamaServerClient,
        suite: CanarySuite,
        *,
        canary_slot_id: int = 0,
        seed: int = 42,
        max_tokens: int = 256,
    ) -> None:
        self.llama_client = llama_client
        self.suite = suite
        self.canary_slot_id = canary_slot_id
        self.seed = seed
        self.max_tokens = max_tokens

    def run(
        self,
        bundles: Sequence[AdapterBundle],
        *,
        allowed_active_ids: frozenset[int] = frozenset(),
    ) -> CanaryResult:
        if not bundles:
            raise CanaryFailedError("cannot run shadow canaries on an empty adapter list")

        # Verify all candidate llama_adapter_ids are loaded on llama-server and
        # no unverified adapter has a non-zero global scale (--lora-init-without-apply invariant).
        try:
            loaded = self.llama_client.list_lora_adapters()
        except LlamaClientError as exc:
            raise CanaryFailedError(f"failed to inspect loaded llama-server adapters: {exc}") from exc

        for item in loaded:
            if item.id not in allowed_active_ids and abs(item.scale) > 0.0:
                raise CanaryFailedError(
                    f"unverified adapter id {item.id} already has non-zero scale {item.scale}; "
                    f"llama-server must start with --lora-init-without-apply",
                    code="ERR_UNSAFE_RUNTIME_FLAGS",
                )

        loaded_ids = {item.id for item in loaded}
        requested_ids = {b.llama_adapter_id for b in bundles}
        missing = sorted(requested_ids - loaded_ids)
        if missing:
            raise CanaryFailedError(f"candidate adapter ids not loaded in llama-server: {missing}")

        # Ensure zero global scales are left active during shadow testing if not already mounted.
        lora_payload = [{"id": b.llama_adapter_id, "scale": b.scale_float} for b in bundles]
        selected = self.suite.select_for_domains([b.domain for b in bundles])

        outcomes: list[CanaryCheckOutcome] = []
        preservation_total = 0
        preservation_passed = 0
        slot_flushed = False

        try:
            for spec in selected:
                # Isolate each canary from any previous KV or DeltaNet recurrent state.
                self.llama_client.erase_slot(self.canary_slot_id)
                messages: list[dict[str, str]] = []
                if spec.system_prompt:
                    messages.append({"role": "system", "content": spec.system_prompt})
                messages.append({"role": "user", "content": spec.prompt})

                resp = self.llama_client.chat_completion(
                    messages,
                    lora=lora_payload,
                    temperature=0.0,
                    seed=self.seed,
                    max_tokens=self.max_tokens,
                    cache_prompt=False,
                    id_slot=self.canary_slot_id,
                )
                text = _extract_chat_content(resp)
                failures = tuple(spec.evaluate(text))
                passed = len(failures) == 0
                if spec.category == "preservation":
                    preservation_total += 1
                    if passed:
                        preservation_passed += 1
                outcomes.append(
                    CanaryCheckOutcome(
                        canary_id=spec.canary_id,
                        category=spec.category,
                        passed=passed,
                        failures=failures,
                    )
                )
        except LlamaClientError as exc:
            raise CanaryFailedError(f"shadow canary execution failed: {exc}") from exc
        finally:
            try:
                self.llama_client.erase_slot(self.canary_slot_id)
                slot_flushed = True
            except LlamaClientError:
                slot_flushed = False

        failed = [o for o in outcomes if not o.passed]
        if preservation_passed != preservation_total:
            detail = "; ".join(f"{o.canary_id}: {list(o.failures)}" for o in failed if o.category == "preservation")
            raise CanaryFailedError(
                f"preservation canary gate failed ({preservation_passed}/{preservation_total}): {detail}"
            )
        if failed:
            detail = "; ".join(f"{o.canary_id}({o.category}): {list(o.failures)}" for o in failed)
            raise CanaryFailedError(f"verifier canary gate failed ({len(failed)}/{len(outcomes)}): {detail}")
        if not slot_flushed:
            raise CanaryFailedError("failed to flush canary slot after shadow evaluation")

        return CanaryResult(
            suite_sha256=self.suite.suite_sha256,
            outcomes=tuple(outcomes),
            preservation_passed=preservation_passed,
            preservation_total=preservation_total,
            canary_slot_flushed=slot_flushed,
        )
