"""Cerebras Kimi K3.1 Pro client for the bounded experiment loop (lane 6).

The client connects the controller in lane 5 to Kimi K3.1 Pro on Cerebras
for three calls only: propose a candidate, diagnose a structured failure,
and compare two fixed textual outputs. It never touches weights, never
compiles, never harvests activations, never verifies an adapter, and never
decides acceptance. Candidates are selected only after deterministic local
gates pass. Deterministic task scores and local retention measurements stay
authoritative. A model comparison is advisory only.

Transport: OpenAI-compatible chat completions at
``https://api.cerebras.ai/v1/chat/completions`` with a bearer key. The key
comes from the environment only. This module never creates a credential and
never enables paid work. Without ``CEREBRAS_API_KEY`` the client refuses
to call and the caller must use the mocked contract instead.

Model record: the requested model id is ``kimi-k3.1-pro``. The receipt
records the model id the server actually returned in the response. If the
served id differs, the receipt shows the difference. Nothing is silently
substituted. Note the Cerebras shared-inference catalog checked
2026-11-18 lists only ``gpt-oss-120b`` and ``qwen-3.8-27b``. Kimi K3.1 Pro
is listed in the Dedicated model catalog, so a live call needs a dedicated
endpoint id. Pass it with ``CEREBRAS_MODEL_ID``. Whether shared inference
serves ``kimi-k3.1-pro`` is UNVERIFIED. The live path is UNVERIFIED until
a credentialed call succeeds and its receipt is filed.

Candidate bounds below are provisional. Lane 4 freezes the experiment
contract. Until that freeze lands, these bounds are the interface the
controller targets. A frozen manifest may narrow them. It must not widen
them without a lane 4 change.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hmac
import json
import math
import os
import time
from typing import Any
import urllib.error
import urllib.parse
import urllib.request

from .cerebras_prompts import (
    PROMPT_SET_VERSION,
    build_compare_messages,
    build_diagnose_messages,
    build_propose_messages,
    prompt_sha256,
)
from .errors import (
    CerebrasClientError,
    CerebrasCredentialsMissingError,
    CerebrasSchemaError,
    CerebrasTransportError,
)
from .server import loads_strict_json

PROVIDER_NAME = "cerebras"
CEREBRAS_BASE_URL = "https://api.cerebras.ai/v1"
CEREBRAS_CHAT_COMPLETIONS_PATH = "/v1/chat/completions"
DEFAULT_MODEL_ID = "kimi-k3.1-pro"
DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_MAX_RETRIES = 2
DEFAULT_TEMPERATURE = 0.0
DEFAULT_SEED = 42
DEFAULT_MAX_COMPLETION_TOKENS = 1024
DEFAULT_REASONING_EFFORT = "low"

# Provisional candidate bounds, pending the lane 4 freeze.
PINNED_TARGET_LAYER = "last"
ALLOWED_RANKS = (4, 8, 16, 32)
ALLOWED_QUANTIZATIONS = ("q8_0", "q4_0", "bf16")
MAX_STRENGTH = 1.0
MAX_REPAIR_ROUNDS = 3
FAILED_GATES = ("task", "retention_iid", "retention_shifted", "safety", "logprob_margin")
MAX_MEASUREMENTS = 32
MAX_TEXT_CHARS = 4000
MAX_TASK_ID_CHARS = 128
MAX_TASK_SUMMARY_CHARS = 500
MAX_REASON_CHARS = 280
RETRYABLE_HTTP_CODES = (408, 429, 500, 502, 503, 504)


@dataclass(frozen=True)
class CandidateConfig:
    """One schema-valid candidate for the pinned last-layer target."""

    target_layer: str
    strength: float
    rank: int
    quantization: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_layer": self.target_layer,
            "strength": self.strength,
            "rank": self.rank,
            "quantization": self.quantization,
        }


@dataclass(frozen=True)
class ComparisonVerdict:
    """Advisory model comparison. Never an acceptance gate on its own."""

    preference: str
    reason: str
    confidence: str

    def to_dict(self) -> dict[str, str]:
        return {"preference": self.preference, "reason": self.reason, "confidence": self.confidence}


@dataclass(frozen=True)
class ProviderReceipt:
    """Redacted receipt for one provider call.

    Carries the prompt hash, never the prompt text. Carries the served
    model id, never the key. Token counts and latency come from the live
    response when present and are None when the server omits them.
    """

    call_kind: str
    provider: str
    requested_model: str
    served_model: str | None
    prompt_sha256: str
    prompt_set_version: str
    temperature: float
    seed: int | None
    max_completion_tokens: int
    reasoning_effort: str
    prompt_tokens: int | None
    completion_tokens: int | None
    total_tokens: int | None
    latency_ms: float
    retries: int
    timeouts: int
    failures: tuple[str, ...] = ()
    status: str = "ok"
    error_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "call_kind": self.call_kind,
            "provider": self.provider,
            "requested_model": self.requested_model,
            "served_model": self.served_model,
            "prompt_sha256": self.prompt_sha256,
            "prompt_set_version": self.prompt_set_version,
            "temperature": self.temperature,
            "seed": self.seed,
            "max_completion_tokens": self.max_completion_tokens,
            "reasoning_effort": self.reasoning_effort,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "latency_ms": self.latency_ms,
            "retries": self.retries,
            "timeouts": self.timeouts,
            "failures": list(self.failures),
            "status": self.status,
            "error_code": self.error_code,
        }


def _is_number(value: Any) -> bool:
    if type(value) is int:
        # Bound the size first: float() on a huge int raises OverflowError.
        return value.bit_length() <= 1023
    return type(value) is float and math.isfinite(value)


def _describe_value(value: Any) -> str:
    """Short description for error messages; never prints huge values."""
    if type(value) is int and value.bit_length() > 1023:
        return "int with %d bits" % value.bit_length()
    if type(value) is str and len(value) > 100:
        return "str of %d characters" % len(value)
    return repr(value)


def _is_timeout(exc: BaseException) -> bool:
    """True for a timeout, including one wrapped in a URLError."""
    if isinstance(exc, TimeoutError):
        return True
    return isinstance(getattr(exc, "reason", None), TimeoutError)


def _is_int(value: Any) -> bool:
    return type(value) is int


def validate_candidate(payload: Any) -> CandidateConfig:
    """Validate a candidate dict strictly. Reject anything outside the schema."""
    if not isinstance(payload, dict):
        raise CerebrasSchemaError(f"candidate must be an object, got {type(payload).__name__}")
    if set(payload.keys()) != {"target_layer", "strength", "rank", "quantization"}:
        raise CerebrasSchemaError(
            f"candidate keys must be exactly target_layer, strength, rank, quantization, got {sorted(payload.keys())}"
        )
    if payload["target_layer"] != PINNED_TARGET_LAYER:
        raise CerebrasSchemaError(
            f"target_layer must be {PINNED_TARGET_LAYER!r}, got {_describe_value(payload['target_layer'])}"
        )
    strength = payload["strength"]
    if not _is_number(strength) or not 0.0 < float(strength) <= MAX_STRENGTH:
        raise CerebrasSchemaError(f"strength must be a number in (0, {MAX_STRENGTH}], got {_describe_value(strength)}")
    rank = payload["rank"]
    if not _is_int(rank) or rank not in ALLOWED_RANKS:
        raise CerebrasSchemaError(f"rank must be one of {list(ALLOWED_RANKS)}, got {_describe_value(rank)}")
    quantization = payload["quantization"]
    if quantization not in ALLOWED_QUANTIZATIONS:
        raise CerebrasSchemaError(
            f"quantization must be one of {list(ALLOWED_QUANTIZATIONS)}, got {_describe_value(quantization)}"
        )
    return CandidateConfig(
        target_layer=PINNED_TARGET_LAYER,
        strength=float(strength),
        rank=int(rank),
        quantization=str(quantization),
    )


def validate_failure_report(report: Any) -> dict[str, Any]:
    """Validate a structured failure report and enforce the repair budget."""
    if not isinstance(report, dict):
        raise CerebrasSchemaError(f"failure report must be an object, got {type(report).__name__}")
    if set(report.keys()) != {"failed_candidate", "failed_gate", "measurements", "rounds_used"}:
        raise CerebrasSchemaError(
            f"failure report keys must be exactly failed_candidate, failed_gate, "
            f"measurements, rounds_used, got {sorted(report.keys())}"
        )
    failed = validate_candidate(report["failed_candidate"])
    if report["failed_gate"] not in FAILED_GATES:
        raise CerebrasSchemaError(f"failed_gate must be one of {list(FAILED_GATES)}, got {_describe_value(report['failed_gate'])}")
    measurements = report["measurements"]
    if not isinstance(measurements, dict) or not measurements or len(measurements) > MAX_MEASUREMENTS:
        raise CerebrasSchemaError("measurements must be a non-empty object with at most 32 entries")
    for key, value in measurements.items():
        if not isinstance(key, str) or not key or not _is_number(value):
            raise CerebrasSchemaError(f"measurement {key!r} must map to a finite number, got {_describe_value(value)}")
    rounds_used = report["rounds_used"]
    if not _is_int(rounds_used) or not 0 <= rounds_used <= MAX_REPAIR_ROUNDS:
        raise CerebrasSchemaError(f"rounds_used must be an integer in 0..{MAX_REPAIR_ROUNDS}, got {_describe_value(rounds_used)}")
    if rounds_used >= MAX_REPAIR_ROUNDS:
        raise CerebrasSchemaError(
            f"repair budget exhausted: rounds_used {rounds_used} reaches the {MAX_REPAIR_ROUNDS} round limit"
        )
    return {
        "failed_candidate": failed.to_dict(),
        "failed_gate": str(report["failed_gate"]),
        "measurements": {str(k): float(v) for k, v in measurements.items()},
        "rounds_used": int(rounds_used),
        "rounds_remaining": MAX_REPAIR_ROUNDS - int(rounds_used),
    }


def validate_comparison_inputs(*, baseline_text: Any, adapted_text: Any, task_id: Any) -> dict[str, str]:
    """Validate fixed comparison texts. Only fixed text is compared."""
    for name, value in (("baseline_text", baseline_text), ("adapted_text", adapted_text)):
        if not isinstance(value, str) or not value.strip() or len(value) > MAX_TEXT_CHARS:
            raise CerebrasSchemaError(f"{name} must be non-empty text of at most {MAX_TEXT_CHARS} characters")
    if not isinstance(task_id, str) or not task_id.strip() or len(task_id) > MAX_TASK_ID_CHARS:
        raise CerebrasSchemaError(f"task_id must be non-empty text of at most {MAX_TASK_ID_CHARS} characters")
    return {"baseline_text": baseline_text, "adapted_text": adapted_text, "task_id": task_id}


def validate_comparison_verdict(payload: Any) -> ComparisonVerdict:
    if not isinstance(payload, dict):
        raise CerebrasSchemaError(f"comparison verdict must be an object, got {type(payload).__name__}")
    if set(payload.keys()) != {"preference", "reason", "confidence"}:
        raise CerebrasSchemaError(
            f"comparison keys must be exactly preference, reason, confidence, got {sorted(payload.keys())}"
        )
    if payload["preference"] not in ("baseline", "adapted", "tie"):
        raise CerebrasSchemaError(f"preference must be baseline, adapted, or tie, got {_describe_value(payload['preference'])}")
    reason = payload["reason"]
    if not isinstance(reason, str) or not reason.strip() or len(reason) > MAX_REASON_CHARS:
        raise CerebrasSchemaError(f"reason must be non-empty text of at most {MAX_REASON_CHARS} characters")
    if payload["confidence"] not in ("low", "medium", "high"):
        raise CerebrasSchemaError(f"confidence must be low, medium, or high, got {_describe_value(payload['confidence'])}")
    return ComparisonVerdict(
        preference=str(payload["preference"]), reason=reason, confidence=str(payload["confidence"])
    )


def validate_propose_context(context: Any) -> dict[str, Any]:
    if not isinstance(context, dict):
        raise CerebrasSchemaError(f"propose context must be an object, got {type(context).__name__}")
    if set(context.keys()) - {"task_summary", "baseline_metrics", "constraints"}:
        raise CerebrasSchemaError(
            f"propose context keys must be a subset of task_summary, baseline_metrics, constraints, "
            f"got {sorted(context.keys())}"
        )
    cleaned: dict[str, Any] = {}
    summary = context.get("task_summary")
    if summary is not None:
        if not isinstance(summary, str) or not summary.strip() or len(summary) > MAX_TASK_SUMMARY_CHARS:
            raise CerebrasSchemaError(
                f"task_summary must be non-empty text of at most {MAX_TASK_SUMMARY_CHARS} characters"
            )
        cleaned["task_summary"] = summary
    metrics = context.get("baseline_metrics")
    if metrics is not None:
        if not isinstance(metrics, dict) or not metrics or len(metrics) > MAX_MEASUREMENTS:
            raise CerebrasSchemaError("baseline_metrics must be a non-empty object with at most 32 entries")
        for key, value in metrics.items():
            if not isinstance(key, str) or not key or not _is_number(value):
                raise CerebrasSchemaError(f"baseline metric {key!r} must map to a finite number, got {_describe_value(value)}")
        cleaned["baseline_metrics"] = {str(k): float(v) for k, v in metrics.items()}
    constraints = context.get("constraints")
    if constraints is not None:
        if not isinstance(constraints, dict):
            raise CerebrasSchemaError("constraints must be an object")
        for key, value in constraints.items():
            if not isinstance(key, str) or not isinstance(value, (str, int, float, bool)):
                raise CerebrasSchemaError(f"constraint {key!r} must map to a plain scalar, got {_describe_value(value)}")
        cleaned["constraints"] = dict(constraints)
    return cleaned


class CerebrasKimiClient:
    """Bounded client for Kimi K3.1 Pro on Cerebras.

    The controller calls ``propose_candidate``, ``diagnose_failure``, and
    ``compare_outputs``. Each returns a validated result plus a redacted
    receipt. No method accepts weights, file paths, or private data.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = CEREBRAS_BASE_URL,
        model_id: str = DEFAULT_MODEL_ID,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        retry_delay_seconds: float = 0.5,
        temperature: float = DEFAULT_TEMPERATURE,
        seed: int | None = DEFAULT_SEED,
        max_completion_tokens: int = DEFAULT_MAX_COMPLETION_TOKENS,
        reasoning_effort: str = DEFAULT_REASONING_EFFORT,
    ) -> None:
        if not isinstance(api_key, str) or not api_key.strip():
            raise CerebrasCredentialsMissingError("Cerebras API key is missing or empty")
        parsed = urllib.parse.urlparse(base_url)
        if parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1"):
            pass  # Local mock endpoints in tests use plain http on localhost.
        elif parsed.scheme != "https" or not parsed.hostname:
            raise CerebrasClientError(f"Cerebras base URL must be an https URL, got {base_url!r}")
        elif parsed.hostname != "api.cerebras.ai":
            # The bearer key is attached to whatever host this names, so
            # an https URL to any other host is a credential-exfiltration
            # path when the environment is attacker-influenced.
            raise CerebrasClientError(
                "Cerebras base URL host must be api.cerebras.ai, "
                f"got {parsed.hostname!r}"
            )
        if timeout_seconds <= 0:
            raise CerebrasClientError("timeout_seconds must be positive")
        if max_retries < 0:
            raise CerebrasClientError("max_retries must be zero or more")
        if not 0.0 <= temperature <= 2.0:
            raise CerebrasClientError("temperature must be in 0..2")
        if reasoning_effort not in ("low", "medium", "high", "max"):
            raise CerebrasClientError("reasoning_effort must be low, medium, high, or max")
        self._api_key = api_key
        self.base_url = base_url.rstrip("/")
        self.model_id = model_id
        self.timeout_seconds = float(timeout_seconds)
        self.max_retries = int(max_retries)
        self.retry_delay_seconds = float(retry_delay_seconds)
        self.temperature = float(temperature)
        self.seed = seed
        self.max_completion_tokens = int(max_completion_tokens)
        self.reasoning_effort = reasoning_effort

    @classmethod
    def from_env(cls, environ: Any = None) -> "CerebrasKimiClient":
        """Build a client from the environment. Creates no credential.

        ``CEREBRAS_API_KEY`` is required. ``CEREBRAS_BASE_URL`` overrides
        the endpoint for tests. ``CEREBRAS_MODEL_ID`` overrides the model
        id, for example with a dedicated endpoint id.
        """
        env = os.environ if environ is None else environ
        api_key = env.get("CEREBRAS_API_KEY")
        if not api_key:
            raise CerebrasCredentialsMissingError(
                "CEREBRAS_API_KEY is not set. No credential will be created. "
                "Use the mocked contract until an authorized key exists."
            )
        return cls(
            api_key,
            base_url=env.get("CEREBRAS_BASE_URL", CEREBRAS_BASE_URL),
            model_id=env.get("CEREBRAS_MODEL_ID", DEFAULT_MODEL_ID),
        )

    def _chat(
        self, *, call_kind: str, messages: list[dict[str, str]]
    ) -> tuple[str, ProviderReceipt]:
        prompt_hash = prompt_sha256(messages)
        payload: dict[str, Any] = {
            "model": self.model_id,
            "messages": messages,
            "temperature": self.temperature,
            "max_completion_tokens": self.max_completion_tokens,
            "reasoning_effort": self.reasoning_effort,
            "reasoning_format": "parsed",
            "response_format": {"type": "json_object"},
            "stream": False,
        }
        if self.seed is not None:
            payload["seed"] = int(self.seed)
        body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        url = f"{self.base_url}{CEREBRAS_CHAT_COMPLETIONS_PATH}"
        failures: list[str] = []
        retries = 0
        timeouts = 0
        started = time.monotonic()
        last_error: CerebrasClientError | None = None
        for attempt in range(self.max_retries + 1):
            try:
                req = urllib.request.Request(
                    url,
                    data=body,
                    headers={
                        "Authorization": f"Bearer {self._api_key}",
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                    raw = resp.read()
                latency_ms = (time.monotonic() - started) * 1000.0
                return self._parse_response(call_kind, raw, prompt_hash, latency_ms, retries, timeouts, failures)
            except CerebrasSchemaError as exc:
                # A malformed provider response is not retryable. File a
                # failure receipt inside the raised error, preserving typed
                # error codes (e.g. ERR_CEREBRAS_MODEL_SUBSTITUTION) and the
                # validated printable-ASCII served_model when present.
                latency_ms = (time.monotonic() - started) * 1000.0
                err_code = exc.code or "ERR_CEREBRAS_SCHEMA"
                observed_model = getattr(exc, "served_model", None)
                receipt = ProviderReceipt(
                    call_kind=call_kind,
                    provider=PROVIDER_NAME,
                    requested_model=self.model_id,
                    served_model=observed_model,
                    prompt_sha256=prompt_hash,
                    prompt_set_version=PROMPT_SET_VERSION,
                    temperature=self.temperature,
                    seed=self.seed,
                    max_completion_tokens=self.max_completion_tokens,
                    reasoning_effort=self.reasoning_effort,
                    prompt_tokens=None,
                    completion_tokens=None,
                    total_tokens=None,
                    latency_ms=latency_ms,
                    retries=retries,
                    timeouts=timeouts,
                    failures=(str(exc),),
                    status="error",
                    error_code=err_code,
                )
                err = CerebrasSchemaError(
                    f"{exc} (receipt: {json.dumps(receipt.to_dict(), sort_keys=True)})",
                    code=err_code,
                )
                err.served_model = observed_model  # type: ignore[attr-defined]
                raise err from exc
            except urllib.error.HTTPError as exc:
                # The error body is provider-controlled text: never copy
                # it into a receipt or an exception. Record only the code.
                try:
                    exc.read()
                except Exception:
                    pass
                finally:
                    exc.close()
                failures.append(f"HTTP {exc.code}")
                last_error = CerebrasTransportError(f"Cerebras HTTP {exc.code} on {call_kind}")
                if exc.code not in RETRYABLE_HTTP_CODES or attempt >= self.max_retries:
                    break
                retries += 1
                time.sleep(self.retry_delay_seconds)
            except (TimeoutError, urllib.error.URLError, OSError) as exc:
                if _is_timeout(exc):
                    timeouts += 1
                    failures.append(f"timeout after {self.timeout_seconds}s")
                else:
                    failures.append(f"transport error: {exc}")
                last_error = CerebrasTransportError(f"Cerebras transport failure on {call_kind}: {exc}")
                if attempt >= self.max_retries:
                    break
                retries += 1
                time.sleep(self.retry_delay_seconds)
        latency_ms = (time.monotonic() - started) * 1000.0
        receipt = ProviderReceipt(
            call_kind=call_kind,
            provider=PROVIDER_NAME,
            requested_model=self.model_id,
            served_model=None,
            prompt_sha256=prompt_hash,
            prompt_set_version=PROMPT_SET_VERSION,
            temperature=self.temperature,
            seed=self.seed,
            max_completion_tokens=self.max_completion_tokens,
            reasoning_effort=self.reasoning_effort,
            prompt_tokens=None,
            completion_tokens=None,
            total_tokens=None,
            latency_ms=latency_ms,
            retries=retries,
            timeouts=timeouts,
            failures=tuple(failures),
            status="error",
            error_code=last_error.code if last_error is not None else "ERR_CEREBRAS_TRANSPORT",
        )
        raise CerebrasTransportError(
            f"{last_error} (receipt: {json.dumps(receipt.to_dict(), sort_keys=True)})"
        ) from last_error

    def _parse_response(
        self,
        call_kind: str,
        raw: bytes,
        prompt_hash: str,
        latency_ms: float,
        retries: int,
        timeouts: int,
        failures: list[str],
    ) -> tuple[str, ProviderReceipt]:
        try:
            parsed = loads_strict_json(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise CerebrasSchemaError(f"Cerebras returned a non-JSON body on {call_kind}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise CerebrasSchemaError(f"Cerebras response must be an object on {call_kind}")
        choices = parsed.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise CerebrasSchemaError(f"Cerebras response must carry exactly one choice on {call_kind}")
        message = choices[0].get("message") if isinstance(choices[0], dict) else None
        if not isinstance(message, dict):
            raise CerebrasSchemaError(f"Cerebras choice must carry a message object on {call_kind}")
        content = message.get("content")
        if not isinstance(content, str) or not content.strip():
            raise CerebrasSchemaError(f"Cerebras message content must be non-empty text on {call_kind}")
        served_model = parsed.get("model")
        if served_model is None:
            raise CerebrasSchemaError(
                f"Cerebras response omitted required model field on {call_kind} (requested {self.model_id!r})",
                code="ERR_CEREBRAS_MODEL_MISSING",
            )
        if (
            not isinstance(served_model, str)
            or not served_model
            or served_model != served_model.strip()
            or len(served_model) > 128
            or any(ord(ch) < 32 or ord(ch) > 126 for ch in served_model)
        ):
            raise CerebrasSchemaError(
                f"Cerebras response model must be a non-empty trimmed printable ASCII string (<= 128 chars) on {call_kind}",
                code="ERR_CEREBRAS_MODEL_INVALID",
            )
        if not hmac.compare_digest(served_model, self.model_id):
            err = CerebrasSchemaError(
                f"Cerebras served model {_describe_value(served_model)} does not match requested "
                f"model {self.model_id!r} on {call_kind}",
                code="ERR_CEREBRAS_MODEL_SUBSTITUTION",
            )
            err.served_model = served_model  # type: ignore[attr-defined]
            raise err
        usage = parsed.get("usage")
        prompt_tokens = completion_tokens = total_tokens = None
        if isinstance(usage, dict):
            prompt_tokens = usage.get("prompt_tokens") if _is_int(usage.get("prompt_tokens")) else None
            completion_tokens = (
                usage.get("completion_tokens") if _is_int(usage.get("completion_tokens")) else None
            )
            total_tokens = usage.get("total_tokens") if _is_int(usage.get("total_tokens")) else None
        receipt = ProviderReceipt(
            call_kind=call_kind,
            provider=PROVIDER_NAME,
            requested_model=self.model_id,
            served_model=served_model,
            prompt_sha256=prompt_hash,
            prompt_set_version=PROMPT_SET_VERSION,
            temperature=self.temperature,
            seed=self.seed,
            max_completion_tokens=self.max_completion_tokens,
            reasoning_effort=self.reasoning_effort,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            total_tokens=total_tokens,
            latency_ms=latency_ms,
            retries=retries,
            timeouts=timeouts,
            failures=tuple(failures),
            status="ok",
        )
        return content, receipt

    def _parse_json_object(self, content: str, call_kind: str) -> dict[str, Any]:
        try:
            parsed = loads_strict_json(content)
        except ValueError as exc:
            raise CerebrasSchemaError(f"model reply was not valid JSON on {call_kind}: {exc}") from exc
        if not isinstance(parsed, dict):
            raise CerebrasSchemaError(f"model reply must be a JSON object on {call_kind}")
        return parsed

    def propose_candidate(self, context: dict[str, Any]) -> tuple[CandidateConfig, ProviderReceipt]:
        """Ask the model for one schema-valid candidate. Returns only valid candidates."""
        cleaned = validate_propose_context(context)
        context_json = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        messages = build_propose_messages(context_json)
        content, receipt = self._chat(call_kind="propose", messages=messages)
        try:
            return validate_candidate(self._parse_json_object(content, "propose")), receipt
        except CerebrasSchemaError as exc:
            raise CerebrasSchemaError(
                f"{exc} (receipt: {json.dumps(receipt.to_dict(), sort_keys=True)})"
            ) from exc

    def diagnose_failure(self, report: dict[str, Any]) -> tuple[CandidateConfig, ProviderReceipt]:
        """Ask the model for one repair candidate inside the remaining budget."""
        cleaned = validate_failure_report(report)
        report_json = json.dumps(cleaned, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        messages = build_diagnose_messages(report_json)
        content, receipt = self._chat(call_kind="diagnose", messages=messages)
        try:
            repair = validate_candidate(self._parse_json_object(content, "diagnose"))
        except CerebrasSchemaError as exc:
            raise CerebrasSchemaError(
                f"{exc} (receipt: {json.dumps(receipt.to_dict(), sort_keys=True)})"
            ) from exc
        if repair.to_dict() == cleaned["failed_candidate"]:
            raise CerebrasSchemaError(
                "repair candidate repeats the failed candidate unchanged "
                f"(receipt: {json.dumps(receipt.to_dict(), sort_keys=True)})"
            )
        return repair, receipt

    def compare_outputs(
        self, *, baseline_text: str, adapted_text: str, task_id: str
    ) -> tuple[ComparisonVerdict, ProviderReceipt]:
        """Ask the model to compare two fixed texts. Advisory only."""
        cleaned = validate_comparison_inputs(
            baseline_text=baseline_text, adapted_text=adapted_text, task_id=task_id
        )
        messages = build_compare_messages(
            task_id=cleaned["task_id"],
            baseline_text=cleaned["baseline_text"],
            adapted_text=cleaned["adapted_text"],
        )
        content, receipt = self._chat(call_kind="compare", messages=messages)
        try:
            return validate_comparison_verdict(self._parse_json_object(content, "compare")), receipt
        except CerebrasSchemaError as exc:
            raise CerebrasSchemaError(
                f"{exc} (receipt: {json.dumps(receipt.to_dict(), sort_keys=True)})"
            ) from exc
