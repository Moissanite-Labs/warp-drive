"""Stage 3 fail-closed gate: verifier-owned shadow-load canary runner."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import time
from typing import Any, Sequence

from .errors import CanaryFailedError, ForgedCanaryError, WarpError
from .fingerprint import AdapterBundle, SHA256_RE
from .llama_client import LlamaClientError, LlamaServerClient


def _reject_dup_json_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError(f"duplicate JSON key rejected: {key!r}")
        out[key] = value
    return out


def _loads_strict_json(raw_text: str) -> Any:
    def _reject_const(tok: str) -> Any:
        raise ValueError(f"non-standard JSON constant rejected: {tok!r}")

    return json.loads(
        raw_text,
        object_pairs_hook=_reject_dup_json_keys,
        parse_constant=_reject_const,
    )

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


def _strip_fenced_code_blocks_checked(text: str) -> tuple[str, bool]:
    """Return (prose_outside_balanced_fences, has_unclosed_fence) for ``` and ~~~ blocks."""
    out: list[str] = []
    open_fence: str | None = None
    for line in text.splitlines():
        stripped = line.lstrip()
        if open_fence is None:
            if stripped.startswith("```"):
                open_fence = "```"
                continue
            if stripped.startswith("~~~"):
                open_fence = "~~~"
                continue
            out.append(line)
        else:
            if stripped.startswith(open_fence):
                open_fence = None
    return "\n".join(out), open_fence is not None


def _strip_fenced_code_blocks(text: str) -> str:
    """Return only prose lines outside balanced ```/~~~ fenced code blocks."""
    prose, _ = _strip_fenced_code_blocks_checked(text)
    return prose


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
    max_tokens: int | None = None

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
            prose, has_unclosed = _strip_fenced_code_blocks_checked(response_text)
            if has_unclosed:
                failures.append("unclosed fenced code block evading prose_only_forbid check")
            if self.min_chars > 0 and len(prose.strip()) < self.min_chars:
                failures.append(
                    f"prose outside fenced code blocks length {len(prose.strip())} < min_chars {self.min_chars}"
                )
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
                max_tokens=int(data["max_tokens"]) if data.get("max_tokens") is not None else None,
            )
        except KeyError as exc:
            raise CanaryConfigError(f"missing canary field: {exc}") from exc


# Explicit JSONL categories, and the explicit `family` values that mark a safety /
# general-capability preservation canary. Classification never looks at the canary ID.
_JSONL_CATEGORIES = frozenset({"preservation", "domain", "cross_adapter"})
_JSONL_PRESERVATION_FAMILIES = frozenset({"safety", "general", "preservation", "s", "g"})


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
            parsed = _loads_strict_json(raw_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
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

    @classmethod
    def from_jsonl_file(
        cls,
        path: str | Path,
        *,
        expected_sha256: str | None = None,
        min_preservation: int = 4,
        reject_world_writable: bool = True,
        default_domain: str = "formal-verification",
    ) -> CanarySuite:
        """Load a verifier-owned JSONL canary suite (e.g. Phase 1.3 canaries_16.jsonl)."""
        file_path = Path(path)
        if not file_path.is_file():
            raise CanaryConfigError(f"verifier canary JSONL file not found: {file_path}")
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

        specs: list[CanarySpec] = []
        seen_ids: set[str] = set()
        for idx, raw_line in enumerate(raw_bytes.decode("utf-8").splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            try:
                row = _loads_strict_json(line)
            except (json.JSONDecodeError, ValueError) as exc:
                raise CanaryConfigError(f"invalid JSON on line {idx} of {file_path}: {exc}") from exc
            if not isinstance(row, dict):
                raise CanaryConfigError(f"line {idx} of {file_path} must be a JSON object")

            # Canary identity and category must be explicit. The preservation floor is the
            # safety gate, so a row is never classified from substrings of its ID
            # (e.g. "lean-express-1" must not count as a preservation canary).
            raw_id = row.get("canary_id", row.get("id"))
            if not isinstance(raw_id, str) or not raw_id.strip():
                raise CanaryConfigError(
                    f"line {idx} of {file_path} must carry an explicit non-empty 'canary_id' or 'id'"
                )
            cid = raw_id.strip()
            if cid in seen_ids:
                raise CanaryConfigError(f"duplicate canary_id {cid!r} on line {idx} of {file_path}")
            seen_ids.add(cid)

            raw_cat = str(row.get("category") or "").strip().lower()
            raw_fam = str(row.get("family") or "").strip().lower()
            if raw_cat:
                if raw_cat not in _JSONL_CATEGORIES:
                    raise CanaryConfigError(
                        f"canary {cid!r} on line {idx} of {file_path} has unknown category {raw_cat!r}; "
                        f"expected one of {sorted(_JSONL_CATEGORIES)}"
                    )
                cat = raw_cat
            elif raw_fam:
                cat = "preservation" if raw_fam in _JSONL_PRESERVATION_FAMILIES else "domain"
            else:
                raise CanaryConfigError(
                    f"canary {cid!r} on line {idx} of {file_path} must declare an explicit "
                    f"'category' {sorted(_JSONL_CATEGORIES)} or 'family'"
                )

            raw_domains = row.get("domains")
            if isinstance(raw_domains, list) and raw_domains:
                domains = tuple(str(d) for d in raw_domains)
            elif cat == "domain":
                domains = (str(row.get("domain") or default_domain),)
            else:
                domains = ()

            specs.append(
                CanarySpec(
                    canary_id=cid,
                    category=cat,
                    prompt=str(row["prompt"]),
                    domains=domains,
                    system_prompt=row.get("system_prompt"),
                    must_contain=tuple(str(x) for x in row.get("must_contain", ())),
                    must_not_contain=tuple(str(x) for x in row.get("must_not_contain", ())),
                    prose_only_forbid=tuple(str(x) for x in row.get("prose_only_forbid", ())),
                    regex_must_match=tuple(str(x) for x in row.get("regex_must_match", ())),
                    regex_must_not_match=tuple(str(x) for x in row.get("regex_must_not_match", ())),
                    min_chars=int(row.get("min_chars", 1)),
                    max_chars=int(row["max_chars"]) if row.get("max_chars") is not None else None,
                    max_tokens=int(row["max_tokens"]) if row.get("max_tokens") is not None else None,
                )
            )

        preservation_count = sum(1 for spec in specs if spec.category == "preservation")
        if preservation_count < min_preservation:
            raise CanaryConfigError(
                f"verifier canary JSONL requires at least {min_preservation} preservation canaries "
                f"(found {preservation_count})"
            )
        return cls(suite_sha256=actual_sha, canaries=tuple(specs), source_path=str(file_path))

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
    elapsed_ms: float = 0.0


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


def _is_slot_clean_for_banks(
    llama_client: LlamaServerClient,
    sid: int,
    expected_banks: tuple[str, ...],
) -> bool:
    """Verify post-erase slot cleanliness across every expected and reported state bank."""
    if not hasattr(llama_client, "list_slots"):
        return False
    try:
        slots_now = llama_client.list_slots()
    except LlamaClientError:
        return False
    by_id = {int(s.id): s for s in slots_now}
    s_info = by_id.get(sid)
    if s_info is None:
        return False
    if (
        getattr(s_info, "is_processing", False)
        or getattr(s_info, "recurrent_state_tainted", False)
        or getattr(s_info, "lattice_state_tainted", False)
        or getattr(s_info, "ssm_state_tainted", False)
        or getattr(s_info, "lattice_layers_tainted", 0) > 0
        or bool(getattr(s_info, "active_lora_ids", ()))
        or getattr(s_info, "n_decoded", 0) > 0
        or getattr(s_info, "n_prompt_tokens_cache", 0) > 0
    ):
        return False
    sbanks = s_info.state_banks
    if not isinstance(sbanks, dict):
        return False
    for req_b in expected_banks:
        st_b = sbanks.get(req_b)
        if st_b is None or not st_b.is_clean:
            return False
    for st_b in sbanks.values():
        if not st_b.is_clean:
            return False
    return True


def _erase_slot_and_confirm(
    llama_client: LlamaServerClient,
    sid: int,
    *,
    erase_banks: tuple[str, ...] | None,
    expected_banks: tuple[str, ...],
    allow_legacy_implicit_kv_flush: bool = False,
) -> bool:
    """Erase one slot, confirm required banks, and verify post-erase cleanliness."""
    resp = llama_client.erase_slot(sid, banks=erase_banks)
    if not isinstance(resp, dict):
        return False
    confirmed = resp.get("banks_flushed")
    if isinstance(confirmed, list):
        confirmed_set = {str(b) for b in confirmed}
    elif (
        confirmed is None
        and expected_banks == ("kv_cache",)
        and allow_legacy_implicit_kv_flush
    ):
        confirmed_set = {"kv_cache"}
    else:
        return False
    if any(b not in confirmed_set for b in expected_banks):
        return False
    return _is_slot_clean_for_banks(llama_client, sid, expected_banks)


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
        top_p: float = 1.0,
        allow_legacy_implicit_kv_flush: bool = False,
    ) -> None:
        self.llama_client = llama_client
        self.suite = suite
        self.canary_slot_id = canary_slot_id
        self.seed = seed
        self.max_tokens = max_tokens
        self.top_p = float(top_p)
        self.allow_legacy_implicit_kv_flush = bool(allow_legacy_implicit_kv_flush)

    def run(
        self,
        bundles: Sequence[AdapterBundle],
        *,
        allowed_active_ids: frozenset[int] = frozenset(),
        required_state_banks: Sequence[str] | None = None,
    ) -> CanaryResult:
        t0 = time.perf_counter()
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

        erase_banks = tuple(required_state_banks) if required_state_banks and len(required_state_banks) > 1 else None

        slot_ids: tuple[int, ...] = (self.canary_slot_id,)
        if hasattr(self.llama_client, "list_slots"):
            try:
                listed_slots = self.llama_client.list_slots()
                if len(listed_slots) > 1:
                    slot_ids = tuple(int(s.id) for s in listed_slots)
            except LlamaClientError:
                slot_ids = (self.canary_slot_id,)

        expected_banks: tuple[str, ...] = (
            tuple(str(b) for b in required_state_banks)
            if required_state_banks
            else ("kv_cache",)
        )

        def _erase_and_confirm(sid: int) -> bool:
            return _erase_slot_and_confirm(
                self.llama_client,
                sid,
                erase_banks=erase_banks,
                expected_banks=expected_banks,
                allow_legacy_implicit_kv_flush=self.allow_legacy_implicit_kv_flush,
            )

        try:
            if len(slot_ids) == 1:
                for spec in selected:
                    if not _erase_and_confirm(self.canary_slot_id):
                        raise CanaryFailedError(
                            f"canary slot {self.canary_slot_id} erase failed to confirm required banks {list(expected_banks)}"
                        )
                    messages: list[dict[str, str]] = []
                    if spec.system_prompt:
                        messages.append({"role": "system", "content": spec.system_prompt})
                    messages.append({"role": "user", "content": spec.prompt})

                    resp = self.llama_client.chat_completion(
                        messages,
                        lora=lora_payload,
                        temperature=0.0,
                        top_p=self.top_p,
                        seed=self.seed,
                        max_tokens=spec.max_tokens if spec.max_tokens is not None else self.max_tokens,
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
            else:
                # LPT load-balanced deterministic partitioning across parallel server slots for <3s Stage 3 execution
                buckets: dict[int, list[tuple[int, CanarySpec]]] = {sid: [] for sid in slot_ids}
                slot_loads: dict[int, int] = {sid: 0 for sid in slot_ids}
                ordered_specs = sorted(
                    enumerate(selected),
                    key=lambda pair: (
                        -(pair[1].max_tokens if pair[1].max_tokens is not None else self.max_tokens),
                        0 if pair[1].category != "preservation" else 1,
                        pair[0],
                    ),
                )
                for orig_idx, spec in ordered_specs:
                    best_sid = min(slot_ids, key=lambda s: (slot_loads[s], s))
                    buckets[best_sid].append((orig_idx, spec))
                    slot_loads[best_sid] += spec.max_tokens if spec.max_tokens is not None else self.max_tokens

                def _run_slot_bucket(sid: int, items: list[tuple[int, CanarySpec]]) -> list[tuple[int, CanaryCheckOutcome]]:
                    if not items:
                        return []
                    bucket_out: list[tuple[int, CanaryCheckOutcome]] = []
                    for orig_idx, spec in items:
                        if not _erase_and_confirm(sid):
                            raise CanaryFailedError(
                                f"canary slot {sid} erase failed to confirm required banks {list(expected_banks)}"
                            )
                        msgs: list[dict[str, str]] = []
                        if spec.system_prompt:
                            msgs.append({"role": "system", "content": spec.system_prompt})
                        msgs.append({"role": "user", "content": spec.prompt})
                        r = self.llama_client.chat_completion(
                            msgs,
                            lora=lora_payload,
                            temperature=0.0,
                            top_p=self.top_p,
                            seed=self.seed,
                            max_tokens=spec.max_tokens if spec.max_tokens is not None else self.max_tokens,
                            cache_prompt=False,
                            id_slot=sid,
                        )
                        txt = _extract_chat_content(r)
                        fails = tuple(spec.evaluate(txt))
                        bucket_out.append(
                            (
                                orig_idx,
                                CanaryCheckOutcome(
                                    canary_id=spec.canary_id,
                                    category=spec.category,
                                    passed=(len(fails) == 0),
                                    failures=fails,
                                ),
                            )
                        )
                    return bucket_out

                indexed_outcomes: list[tuple[int, CanaryCheckOutcome]] = []
                with ThreadPoolExecutor(max_workers=len(slot_ids)) as pool:
                    futs = [pool.submit(_run_slot_bucket, sid, buckets[sid]) for sid in slot_ids]
                    for fut in futs:
                        indexed_outcomes.extend(fut.result())

                indexed_outcomes.sort(key=lambda pair: pair[0])
                for _, out_item in indexed_outcomes:
                    if out_item.category == "preservation":
                        preservation_total += 1
                        if out_item.passed:
                            preservation_passed += 1
                    outcomes.append(out_item)
        except LlamaClientError as exc:
            raise CanaryFailedError(f"shadow canary execution failed: {exc}") from exc
        finally:
            all_flushed = True
            if len(slot_ids) <= 1:
                for sid in slot_ids:
                    try:
                        if not _erase_and_confirm(sid):
                            all_flushed = False
                    except LlamaClientError:
                        all_flushed = False
            else:
                def _safe_erase(sid: int) -> bool:
                    try:
                        return _erase_and_confirm(sid)
                    except LlamaClientError:
                        return False

                with ThreadPoolExecutor(max_workers=len(slot_ids)) as pool:
                    all_flushed = all(pool.map(_safe_erase, slot_ids))
            slot_flushed = all_flushed

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
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
            elapsed_ms=elapsed_ms,
        )


class ExternalCommandCanaryRunner:
    """Executes an opaque verifier-owned canary command without reading private canary plaintext.

    The command receives `--llama-url <url> --lora-json <json> --domains-json <json> --slot-id <id>`
    and must exit 0 with a JSON object on stdout containing:
      - `suite_sha256`: 64-char hex digest of the sealed canary file
      - `preservation_passed`: int
      - `preservation_total`: int (>= 4, must equal `preservation_passed`)
      - `outcomes`: list of `{"canary_id": str, "category": str, "passed": bool, "failures": [...]}`
    """

    def __init__(
        self,
        llama_client: LlamaServerClient,
        command: Sequence[str],
        *,
        suite_sha256_hint: str | None = None,
        canary_slot_id: int = 0,
        timeout_seconds: float = 30.0,
        min_preservation: int = 4,
        allow_legacy_implicit_kv_flush: bool = False,
    ) -> None:
        if not command:
            raise CanaryConfigError("external canary command must be non-empty")
        if min_preservation < 1:
            raise CanaryConfigError("min_preservation must be >= 1")
        self.llama_client = llama_client
        self.command = tuple(str(c) for c in command)
        self._pinned_suite_sha256: str | None = None
        if suite_sha256_hint is not None:
            if not isinstance(suite_sha256_hint, str) or not SHA256_RE.match(suite_sha256_hint):
                raise CanaryConfigError("suite_sha256_hint must be a 64-char lowercase hex sha256 digest")
            self._pinned_suite_sha256 = suite_sha256_hint
        self.suite_sha256 = suite_sha256_hint or hashlib.sha256(" ".join(self.command).encode("utf-8")).hexdigest()
        self.canary_slot_id = canary_slot_id
        self.timeout_seconds = float(timeout_seconds)
        self.min_preservation = int(min_preservation)
        self.allow_legacy_implicit_kv_flush = bool(allow_legacy_implicit_kv_flush)

    def run(
        self,
        bundles: Sequence[AdapterBundle],
        *,
        allowed_active_ids: frozenset[int] = frozenset(),
        required_state_banks: Sequence[str] | None = None,
    ) -> CanaryResult:
        t0 = time.perf_counter()
        if not bundles:
            raise CanaryFailedError("cannot run shadow canaries on an empty adapter list")

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

        lora_payload = [{"id": b.llama_adapter_id, "scale": b.scale_float} for b in bundles]
        domains = [b.domain for b in bundles]
        erase_banks = tuple(required_state_banks) if required_state_banks and len(required_state_banks) > 1 else None

        lora_json_str = json.dumps(lora_payload, separators=(",", ":"))
        domains_json_str = json.dumps(domains, separators=(",", ":"))
        has_placeholders = any(
            tok_p in arg
            for arg in self.command
            for tok_p in ("{server_url}", "{llama_url}", "{lora_json}", "{domains_json}", "{slot_id}")
        )
        if has_placeholders:
            cmd = [
                arg.replace("{server_url}", self.llama_client.base_url)
                .replace("{llama_url}", self.llama_client.base_url)
                .replace("{lora_json}", lora_json_str)
                .replace("{domains_json}", domains_json_str)
                .replace("{slot_id}", str(self.canary_slot_id))
                for arg in self.command
            ]
        else:
            cmd = [
                *self.command,
                "--llama-url",
                self.llama_client.base_url,
                "--lora-json",
                lora_json_str,
                "--domains-json",
                domains_json_str,
                "--slot-id",
                str(self.canary_slot_id),
            ]
        run_env = dict(os.environ)
        run_env["WARP_SERVER_URL"] = self.llama_client.base_url
        run_env["WARP_LORA_JSON"] = lora_json_str

        slot_ids: tuple[int, ...] = (self.canary_slot_id,)
        if hasattr(self.llama_client, "list_slots"):
            try:
                listed = self.llama_client.list_slots()
                if listed:
                    slot_ids = tuple(int(s.id) for s in listed)
            except LlamaClientError:
                slot_ids = (self.canary_slot_id,)

        expected_banks: tuple[str, ...] = (
            tuple(str(b) for b in required_state_banks)
            if required_state_banks
            else ("kv_cache",)
        )

        def _ext_erase_and_verify(sid: int) -> bool:
            return _erase_slot_and_confirm(
                self.llama_client,
                sid,
                erase_banks=erase_banks,
                expected_banks=expected_banks,
                allow_legacy_implicit_kv_flush=self.allow_legacy_implicit_kv_flush,
            )

        slot_flushed = False
        try:
            for sid in slot_ids:
                if not _ext_erase_and_verify(sid):
                    raise CanaryFailedError(
                        f"opaque canary pre-run erase failed to confirm clean slot {sid} for banks {list(expected_banks)}"
                    )
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=run_env,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError, LlamaClientError) as exc:
            raise CanaryFailedError(f"opaque verifier canary command failed to execute: {exc}") from exc
        finally:
            all_ok = True
            for sid in slot_ids:
                try:
                    if not _ext_erase_and_verify(sid):
                        all_ok = False
                except LlamaClientError:
                    all_ok = False
            slot_flushed = all_ok

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        if not slot_flushed:
            raise CanaryFailedError("failed to flush canary slot after opaque canary command")
        if proc.returncode != 0:
            raise CanaryFailedError(
                f"opaque verifier canary command rejected candidate (exit={proc.returncode}): "
                f"{(proc.stderr or proc.stdout).strip()[:300]}"
            )
        try:
            parsed = _loads_strict_json(proc.stdout)
        except (json.JSONDecodeError, ValueError) as exc:
            raise CanaryFailedError(f"opaque verifier canary command returned invalid JSON: {exc}") from exc
        if not isinstance(parsed, dict):
            raise CanaryFailedError("opaque verifier canary command output must be a JSON object")

        raw_suite_sha = parsed.get("suite_sha256")
        if raw_suite_sha is None:
            raw_suite_sha = parsed.get("canaries_sha256")
        if raw_suite_sha is not None:
            if not isinstance(raw_suite_sha, str) or not SHA256_RE.match(raw_suite_sha):
                raise CanaryFailedError(f"opaque verifier returned invalid suite_sha256: {raw_suite_sha!r}")
            suite_sha = raw_suite_sha
        elif self._pinned_suite_sha256 is not None:
            raise CanaryFailedError(
                "opaque verifier output omitted required 'suite_sha256' while suite_sha256_hint is pinned"
            )
        else:
            suite_sha = self.suite_sha256
        if self._pinned_suite_sha256 is not None and not hmac.compare_digest(suite_sha, self._pinned_suite_sha256):
            raise CanaryFailedError(
                f"opaque verifier suite_sha256 mismatch: got {suite_sha}, expected {self._pinned_suite_sha256}"
            )
        raw_outcomes = parsed.get("outcomes")
        if raw_outcomes is None:
            raw_outcomes = parsed.get("results")
        if raw_outcomes is None:
            raw_outcomes = parsed.get("canaries")

        if not isinstance(raw_outcomes, list) or len(raw_outcomes) == 0:
            raise CanaryFailedError(
                "opaque verifier canary command must return a non-empty per-canary 'outcomes' list; "
                "aggregate-only reports are rejected"
            )

        parsed_outcomes: list[CanaryCheckOutcome] = []
        seen_ids: set[str] = set()
        domain_outcome_count = 0
        explicit_domains_covered: set[str] = set()
        for idx, item in enumerate(raw_outcomes):
            if not isinstance(item, dict) or not isinstance(item.get("passed"), bool):
                raise CanaryFailedError(
                    f"opaque verifier canary outcome #{idx} must be an object with boolean 'passed'"
                )
            raw_id = item.get("canary_id") if item.get("canary_id") is not None else item.get("id")
            cid = str(raw_id or "").strip()
            if not cid:
                raise CanaryFailedError(f"opaque verifier canary outcome #{idx} is missing a non-empty 'canary_id'")
            if cid in seen_ids:
                raise CanaryFailedError(f"duplicate canary_id in opaque verifier outcomes: {cid!r}")
            seen_ids.add(cid)

            raw_cat = str(item.get("category") or "").strip().lower()
            if raw_cat == "preservation":
                cat = "preservation"
            elif raw_cat in ("domain", "formal"):
                cat = "domain"
                domain_outcome_count += 1
                dom_label = item.get("domain")
                if isinstance(dom_label, str) and dom_label.strip():
                    explicit_domains_covered.add(dom_label.strip())
            elif raw_cat == "cross_adapter":
                cat = "cross_adapter"
            else:
                raise CanaryFailedError(
                    f"invalid category {item.get('category')!r} for canary {cid!r}; "
                    f"expected preservation, domain, or cross_adapter"
                )

            raw_failures = item.get("failures")
            if not isinstance(raw_failures, list):
                raw_failures = item.get("failure_codes", ())
            fail_tuple = tuple(str(f) for f in raw_failures)
            if item["passed"] is True and len(fail_tuple) > 0:
                raise CanaryFailedError(
                    f"opaque verifier outcome {cid!r} is contradictory: passed=True with non-empty failures"
                )
            parsed_outcomes.append(
                CanaryCheckOutcome(
                    canary_id=cid,
                    category=cat,
                    passed=bool(item["passed"]),
                    failures=fail_tuple,
                )
            )

        outcomes = tuple(parsed_outcomes)
        pres_items = [o for o in outcomes if o.category == "preservation"]
        pres_total = len(pres_items)
        pres_passed = sum(1 for o in pres_items if o.passed)

        if parsed.get("preservation_total") is not None:
            raw_pt = parsed["preservation_total"]
            if type(raw_pt) is not int or raw_pt != pres_total:
                raise CanaryFailedError(
                    f"opaque verifier preservation_total ({raw_pt!r}) disagrees with outcomes count ({pres_total})"
                )
        if parsed.get("preservation_passed") is not None:
            raw_pp = parsed["preservation_passed"]
            if type(raw_pp) is not int or raw_pp != pres_passed:
                raise CanaryFailedError(
                    f"opaque verifier preservation_passed ({raw_pp!r}) disagrees with outcomes count ({pres_passed})"
                )
        if pres_total < self.min_preservation:
            raise CanaryFailedError(
                f"opaque verifier canary gate requires at least {self.min_preservation} preservation canaries "
                f"(found {pres_total})"
            )
        if domain_outcome_count < 1:
            raise CanaryFailedError("opaque verifier canary gate requires at least 1 domain canary outcome")
        required_domains = sorted(set(domains))
        if len(required_domains) > 1 or explicit_domains_covered:
            missing_doms = sorted(set(required_domains) - explicit_domains_covered)
            if missing_doms:
                raise CanaryFailedError(
                    f"opaque verifier canary outcomes omitted required domains: {missing_doms}"
                )

        failed = [o for o in outcomes if not o.passed]
        verdict_str = str(parsed.get("verdict") or "").strip().lower()
        if (
            pres_passed != pres_total
            or failed
            or parsed.get("passed") is False
            or parsed.get("all_passed") is False
            or verdict_str in ("reject", "fail", "failed")
        ):
            raise CanaryFailedError(
                f"opaque verifier canary gate failed (preservation {pres_passed}/{pres_total}, failed={len(failed)})"
            )
        return CanaryResult(
            suite_sha256=suite_sha,
            outcomes=outcomes,
            preservation_passed=pres_passed,
            preservation_total=pres_total,
            canary_slot_flushed=True,
            elapsed_ms=elapsed_ms,
        )
