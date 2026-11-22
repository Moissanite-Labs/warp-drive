"""Fail-closed intake for ``gameplay-evidence/v0.1`` artifacts.

The artifact, its raw source, labels, statuses, and negative-control assertions are
untrusted.  This module parses data and verifies commitments; it never parses the
raw source as instructions and never executes a model replay, proof, or game.

``OBSERVED`` is the only badge derived by structural validation alone.  Higher
badges additionally require results from a caller-trusted domain verifier.  Each
result is bound to the artifact digest and to the canonical digest of the exact
check or negative control.  Thus ``VERIFIED`` text and self-asserted ``PASS`` are
source findings, not independent proof.  The caller and its domain verifier are
inside the TCB for higher badges; this intake gate does not make an untrusted
producer part of that TCB.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import hashlib
import hmac
import json
import re
from typing import Any, Callable, Mapping, Sequence

SCHEMA = "gameplay-evidence/v0.1"
OBSERVED = "OBSERVED"
REPLAYED = "REPLAYED"
MODEL_PROVEN = "MODEL_PROVEN"
LIVE_CONFIRMED = "LIVE_CONFIRMED"
BADGE_ORDER = (OBSERVED, REPLAYED, MODEL_PROVEN, LIVE_CONFIRMED)

INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1
ZERO_SHA256 = "0" * 64
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
ASCII_ID_RE = re.compile(r"^[\x21-\x7e]+$")
REPOSITORY_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
MAX_GATE_FINDINGS = 128

_TOP_LEVEL_KEYS = frozenset(
    {"schema", "artifact_sha256", "producer", "claim", "mechanics", "payload", "evidence", "source"}
)
_PAYLOAD_KEYS = frozenset(
    {
        "domain",
        "model",
        "model_sha256",
        "initial_state",
        "initial_state_sha256",
        "actions",
        "actions_sha256",
        "trajectory",
        "trajectory_sha256",
        "outcome",
    }
)
_CHECK_KEYS = frozenset(
    {"kind", "status", "checker", "source_labels", "initial_state_sha256", "actions_sha256", "trajectory_sha256"}
)
_CONTROL_KEYS = frozenset({"name", "mutation", "observed", "passed"})
_CLAIM_KINDS = frozenset({"route", "state_transition", "goal", "counterexample", "observation"})
_CHECK_KINDS = frozenset({"model_replay", "model_proof", "live_execution"})
_DIGEST_FIELDS = ("initial_state_sha256", "actions_sha256", "trajectory_sha256")


@dataclass(frozen=True)
class GateLimits:
    """Resource ceilings applied before canonicalization or domain verification."""

    max_bytes: int = 1_048_576
    max_depth: int = 32
    max_array_items: int = 4096
    max_total_items: int = 16_384
    max_object_keys: int = 256
    max_string_bytes: int = 262_144
    max_total_string_bytes: int = 1_048_576
    max_checks: int = 64
    max_negative_controls: int = 64
    max_mechanics: int = 64
    max_verifier_findings: int = 256

    def __post_init__(self) -> None:
        for name, value in self.__dict__.items():
            if type(value) is not int or value <= 0:
                raise ValueError(f"{name} must be a positive exact integer")

    def to_dict(self) -> dict[str, int]:
        return {name: value for name, value in self.__dict__.items()}


DEFAULT_LIMITS = GateLimits()


@dataclass(frozen=True)
class Finding:
    """A stable, path-qualified validation or verification observation."""

    code: str
    path: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"code": self.code, "path": self.path, "message": self.message}


@dataclass(frozen=True)
class TrustedCheckResult:
    """A domain verdict bound to one complete canonical evidence check."""

    check_sha256: str
    passed: bool
    findings: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class TrustedNegativeControlResult:
    """A domain verdict bound to one complete canonical negative control."""

    control_sha256: str
    passed: bool
    findings: tuple[str, ...] = ()
    error: str | None = None


@dataclass(frozen=True)
class TrustedDomainVerification:
    """Caller-trusted results for an exact artifact.

    ``artifact_sha256`` binds the complete envelope, including model, payload,
    checker pins, raw source, and limitations.  Passing one check does not make
    other checks disappear.  ``error`` denotes verifier failure, not a valid
    negative result.  At least one source-passing control must also independently
    pass before any higher badge is admitted.
    """

    artifact_sha256: str
    checks: tuple[TrustedCheckResult | Mapping[str, Any], ...]
    negative_controls: tuple[TrustedNegativeControlResult | Mapping[str, Any], ...]
    findings: tuple[str, ...] = ()


@dataclass(frozen=True)
class GameplayGateResult:
    """Separated source assertions, independent admissions, and differences."""

    envelope_valid: bool
    artifact_sha256: str | None
    source_badges: tuple[str, ...]
    admitted_badges: tuple[str, ...]
    source_findings: tuple[Finding, ...]
    findings: tuple[Finding, ...]
    unresolved_differences: tuple[Finding, ...]
    limits: GateLimits
    verification_valid: bool | None = None

    @property
    def valid(self) -> bool:
        return self.envelope_valid

    @property
    def badges(self) -> tuple[str, ...]:
        """Alias emphasizing that only independently admitted badges are returned here."""

        return self.admitted_badges

    def to_dict(self) -> dict[str, Any]:
        return {
            "envelope_valid": self.envelope_valid,
            "artifact_sha256": self.artifact_sha256,
            "source_badges": list(self.source_badges),
            "admitted_badges": list(self.admitted_badges),
            "source_findings": [finding.to_dict() for finding in self.source_findings],
            "findings": [finding.to_dict() for finding in self.findings],
            "unresolved_differences": [finding.to_dict() for finding in self.unresolved_differences],
            "verification_valid": self.verification_valid,
            "limits": self.limits.to_dict(),
        }


class _DuplicateJsonKey(ValueError):
    pass


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(f"duplicate JSON key rejected: {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON number rejected: {value}")


def _validate_json_values(value: Any, limits: GateLimits) -> list[Finding]:
    """Iteratively bound generic JSON values and enforce canonical number rules."""

    findings: list[Finding] = []
    stack: list[tuple[Any, str, int]] = [(value, "$", 1)]
    total_items = 0
    total_string_bytes = 0

    def add(code: str, path: str, message: str) -> None:
        if len(findings) < MAX_GATE_FINDINGS:
            findings.append(Finding(code, path, message))

    while stack:
        current, path, depth = stack.pop()
        if depth > limits.max_depth:
            add("DEPTH_LIMIT", path, f"nesting exceeds {limits.max_depth} levels")
            continue

        if type(current) is dict:
            if len(current) > limits.max_object_keys:
                add("OBJECT_KEY_LIMIT", path, f"object exceeds {limits.max_object_keys} keys")
            total_items += len(current)
            for key, child in current.items():
                if type(key) is not str:
                    add("NON_STRING_OBJECT_KEY", path, f"object key {key!r} is not a string")
                    continue
                try:
                    key_size = len(key.encode("utf-8"))
                except UnicodeEncodeError:
                    add("INVALID_UNICODE", path, "object key contains an unpaired surrogate")
                    continue
                total_string_bytes += key_size
                if key_size > limits.max_string_bytes:
                    add("STRING_LIMIT", path, f"object key exceeds {limits.max_string_bytes} UTF-8 bytes")
                stack.append((child, f"{path}.{key}", depth + 1))
        elif type(current) is list:
            if len(current) > limits.max_array_items:
                add("ARRAY_LIMIT", path, f"array exceeds {limits.max_array_items} items")
            total_items += len(current)
            for index, child in enumerate(current):
                stack.append((child, f"{path}[{index}]", depth + 1))
        elif type(current) is str:
            try:
                string_size = len(current.encode("utf-8"))
            except UnicodeEncodeError:
                add("INVALID_UNICODE", path, "string contains an unpaired surrogate")
                continue
            total_string_bytes += string_size
            if string_size > limits.max_string_bytes:
                add("STRING_LIMIT", path, f"string exceeds {limits.max_string_bytes} UTF-8 bytes")
        elif type(current) is int:
            if not INT64_MIN <= current <= INT64_MAX:
                add("INT64_RANGE", path, "integer is outside the signed 64-bit range")
        elif type(current) is float:
            add("FLOAT_NUMBER", path, "every floating-point value is forbidden, including integer-valued floats")
        elif current is None or type(current) is bool:
            pass
        else:
            add("JSON_TYPE", path, f"unsupported JSON value type {type(current).__name__}")

        if total_items > limits.max_total_items:
            add("TOTAL_ITEM_LIMIT", "$", f"document exceeds {limits.max_total_items} container entries")
            break
        if total_string_bytes > limits.max_total_string_bytes:
            add("TOTAL_STRING_LIMIT", "$", f"document exceeds {limits.max_total_string_bytes} string bytes")
            break

    return findings


def _canonical_bytes_unchecked(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def canonical_json_bytes(value: Any) -> bytes:
    """Return contract-canonical JSON or raise ``ValueError`` on invalid values."""

    findings = _validate_json_values(value, DEFAULT_LIMITS)
    if findings:
        finding = findings[0]
        raise ValueError(f"{finding.code} at {finding.path}: {finding.message}")
    try:
        return _canonical_bytes_unchecked(value)
    except (TypeError, ValueError, RecursionError) as exc:  # defensive for caller-supplied objects
        raise ValueError(f"value is not canonical JSON: {exc}") from exc


def canonical_sha256(value: Any) -> str:
    """Hash a canonical check, control, payload component, or other JSON value."""

    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _canonical_sha256_unchecked(value: Any) -> str:
    """Hash an already bounded and strictly validated envelope value."""

    return hashlib.sha256(_canonical_bytes_unchecked(value)).hexdigest()


class _EnvelopeValidator:
    def __init__(self, limits: GateLimits) -> None:
        self.limits = limits
        self.findings: list[Finding] = []

    def add(self, code: str, path: str, message: str) -> None:
        if len(self.findings) < MAX_GATE_FINDINGS:
            self.findings.append(Finding(code, path, message))

    def object(self, value: Any, path: str, keys: frozenset[str]) -> bool:
        if type(value) is not dict:
            self.add("OBJECT_REQUIRED", path, f"expected object, got {type(value).__name__}")
            return False
        actual = set(value)
        missing = sorted(keys - actual)
        unknown = sorted(actual - keys)
        if missing or unknown:
            details = []
            if missing:
                details.append(f"missing keys {missing}")
            if unknown:
                details.append(f"unknown keys {unknown}")
            self.add("OBJECT_KEYS", path, "; ".join(details))
            return False
        return True

    def array(self, value: Any, path: str, *, nonempty: bool = False, maximum: int | None = None) -> bool:
        if type(value) is not list:
            self.add("ARRAY_REQUIRED", path, f"expected array, got {type(value).__name__}")
            return False
        if nonempty and not value:
            self.add("NONEMPTY_ARRAY", path, "array must not be empty")
            return False
        ceiling = self.limits.max_array_items if maximum is None else maximum
        if len(value) > ceiling:
            self.add("ARRAY_LIMIT", path, f"array exceeds {ceiling} items")
            return False
        return True

    def text(self, value: Any, path: str, *, identifier: bool = False) -> bool:
        if type(value) is not str or not value.strip():
            self.add("NONEMPTY_STRING", path, "expected a nonempty string")
            return False
        if identifier and not ASCII_ID_RE.fullmatch(value):
            self.add("ASCII_IDENTIFIER", path, "expected a nonempty ASCII identifier without whitespace")
            return False
        return True

    def sha(self, value: Any, path: str) -> bool:
        if type(value) is not str or not SHA256_RE.fullmatch(value) or value == ZERO_SHA256:
            self.add("SHA256", path, "expected a nonzero, 64-character lowercase SHA-256 digest")
            return False
        return True

    def commit(self, value: Any, path: str) -> bool:
        if type(value) is not str or not COMMIT_RE.fullmatch(value):
            self.add("COMMIT", path, "expected a 40-character lowercase source commit")
            return False
        return True

    def validate(self, document: Any) -> bool:
        if not self.object(document, "$", _TOP_LEVEL_KEYS):
            return False
        if document["schema"] != SCHEMA:
            self.add("SCHEMA", "$.schema", f"expected {SCHEMA!r}")
        self.sha(document["artifact_sha256"], "$.artifact_sha256")

        producer = document["producer"]
        if self.object(producer, "$.producer", frozenset({"repository", "revision", "adapter"})):
            repository = producer["repository"]
            if type(repository) is not str or not REPOSITORY_RE.fullmatch(repository):
                self.add("REPOSITORY", "$.producer.repository", "expected owner/repository")
            self.commit(producer["revision"], "$.producer.revision")
            self.text(producer["adapter"], "$.producer.adapter")

        claim = document["claim"]
        if self.object(claim, "$.claim", frozenset({"id", "kind", "statement"})):
            self.text(claim["id"], "$.claim.id", identifier=True)
            if type(claim["kind"]) is not str or claim["kind"] not in _CLAIM_KINDS:
                self.add("CLAIM_KIND", "$.claim.kind", "unsupported claim kind")
            self.text(claim["statement"], "$.claim.statement")

        mechanics = document["mechanics"]
        if self.array(mechanics, "$.mechanics", maximum=self.limits.max_mechanics):
            for index, mechanic in enumerate(mechanics):
                path = f"$.mechanics[{index}]"
                if not self.object(mechanic, path, frozenset({"id", "path", "source_revision", "raw_sha256"})):
                    continue
                self.text(mechanic["id"], f"{path}.id", identifier=True)
                yaml_path = mechanic["path"]
                if not self._repository_yaml_path(yaml_path):
                    self.add("MECHANIC_PATH", f"{path}.path", "expected a safe repository-relative YAML path")
                self.commit(mechanic["source_revision"], f"{path}.source_revision")
                self.sha(mechanic["raw_sha256"], f"{path}.raw_sha256")

        payload = document["payload"]
        if self.object(payload, "$.payload", _PAYLOAD_KEYS):
            self.text(payload["domain"], "$.payload.domain", identifier=True)
            for field in ("model", "initial_state", "outcome"):
                if type(payload[field]) is not dict:
                    self.add("OBJECT_REQUIRED", f"$.payload.{field}", "expected an object")
            for field in ("actions", "trajectory"):
                self.array(payload[field], f"$.payload.{field}")
            for field in ("model_sha256", "initial_state_sha256", "actions_sha256", "trajectory_sha256"):
                self.sha(payload[field], f"$.payload.{field}")

        evidence = document["evidence"]
        if self.object(evidence, "$.evidence", frozenset({"checks", "negative_controls", "limitations"})):
            limitations = evidence["limitations"]
            if self.array(limitations, "$.evidence.limitations", nonempty=True):
                for index, limitation in enumerate(limitations):
                    self.text(limitation, f"$.evidence.limitations[{index}]")

            controls = evidence["negative_controls"]
            if self.array(
                controls, "$.evidence.negative_controls", maximum=self.limits.max_negative_controls
            ):
                for index, control in enumerate(controls):
                    path = f"$.evidence.negative_controls[{index}]"
                    if not self.object(control, path, _CONTROL_KEYS):
                        continue
                    self.text(control["name"], f"{path}.name")
                    if type(control["passed"]) is not bool:
                        self.add("BOOLEAN_REQUIRED", f"{path}.passed", "expected a real boolean")

            checks = evidence["checks"]
            if self.array(checks, "$.evidence.checks", maximum=self.limits.max_checks):
                for index, check in enumerate(checks):
                    path = f"$.evidence.checks[{index}]"
                    if not self.object(check, path, _CHECK_KEYS):
                        continue
                    if type(check["kind"]) is not str or check["kind"] not in _CHECK_KINDS:
                        self.add("CHECK_KIND", f"{path}.kind", "unsupported evidence check kind")
                    if type(check["status"]) is not str or check["status"] not in {"PASS", "FAIL"}:
                        self.add("CHECK_STATUS", f"{path}.status", "status must be PASS or FAIL")
                    checker = check["checker"]
                    if self.object(checker, f"{path}.checker", frozenset({"name", "revision", "artifact_sha256"})):
                        self.text(checker["name"], f"{path}.checker.name")
                        self.text(checker["revision"], f"{path}.checker.revision")
                        self.sha(checker["artifact_sha256"], f"{path}.checker.artifact_sha256")
                    labels = check["source_labels"]
                    if self.array(labels, f"{path}.source_labels"):
                        for label_index, label in enumerate(labels):
                            self.text(label, f"{path}.source_labels[{label_index}]")
                    for field in _DIGEST_FIELDS:
                        self.sha(check[field], f"{path}.{field}")

        source = document["source"]
        if self.object(source, "$.source", frozenset({"media_type", "raw_sha256", "raw"})):
            self.text(source["media_type"], "$.source.media_type")
            self.sha(source["raw_sha256"], "$.source.raw_sha256")
            if type(source["raw"]) is not str or not source["raw"]:
                self.add("SOURCE_RAW", "$.source.raw", "raw source must be a nonempty string")

        if self.findings:
            return False
        self._verify_commitments(document)
        return not self.findings

    @staticmethod
    def _repository_yaml_path(value: Any) -> bool:
        if type(value) is not str or not value or "\\" in value or value.startswith("/"):
            return False
        if not (value.endswith(".yaml") or value.endswith(".yml")):
            return False
        parts = value.split("/")
        return all(part not in {"", ".", ".."} for part in parts)

    def _digest_mismatch(self, path: str, expected: Any, actual: str) -> None:
        if type(expected) is not str or not hmac.compare_digest(expected, actual):
            self.add("DIGEST_MISMATCH", path, f"stored digest does not match computed {actual}")

    def _verify_commitments(self, document: dict[str, Any]) -> None:
        body = {key: value for key, value in document.items() if key != "artifact_sha256"}
        self._digest_mismatch("$.artifact_sha256", document["artifact_sha256"], _canonical_sha256_unchecked(body))

        source = document["source"]
        raw_digest = hashlib.sha256(source["raw"].encode("utf-8")).hexdigest()
        self._digest_mismatch("$.source.raw_sha256", source["raw_sha256"], raw_digest)

        payload = document["payload"]
        for field in ("model", "initial_state", "actions", "trajectory"):
            self._digest_mismatch(
                f"$.payload.{field}_sha256", payload[f"{field}_sha256"], _canonical_sha256_unchecked(payload[field])
            )

        for index, check in enumerate(document["evidence"]["checks"]):
            for field in _DIGEST_FIELDS:
                if not hmac.compare_digest(check[field], payload[field]):
                    self.add(
                        "CHECK_COMMITMENT_MISMATCH",
                        f"$.evidence.checks[{index}].{field}",
                        "check commitment differs from the gameplay payload",
                    )


def _source_summary(document: dict[str, Any]) -> tuple[tuple[str, ...], tuple[Finding, ...]]:
    evidence = document["evidence"]
    findings: list[Finding] = []
    passing_kinds: set[str] = set()
    passing_control = any(control["passed"] for control in evidence["negative_controls"])

    for index, check in enumerate(evidence["checks"]):
        if check["status"] == "PASS":
            passing_kinds.add(check["kind"])
        labels = ",".join(check["source_labels"]) if check["source_labels"] else "none"
        findings.append(
            Finding(
                "SOURCE_CHECK",
                f"$.evidence.checks[{index}]",
                f"{check['kind']} source status {check['status']}; labels {labels}; "
                f"checker {check['checker']['name']}@{check['checker']['revision']}",
            )
        )
    for index, control in enumerate(evidence["negative_controls"]):
        findings.append(
            Finding(
                "SOURCE_NEGATIVE_CONTROL",
                f"$.evidence.negative_controls[{index}]",
                f"{control['name']}: source {'PASS' if control['passed'] else 'FAIL'}",
            )
        )
    for index, limitation in enumerate(evidence["limitations"]):
        findings.append(Finding("SOURCE_LIMITATION", f"$.evidence.limitations[{index}]", limitation))

    badges = [OBSERVED]
    # A single source failure is an aggregation veto, not merely an absent
    # passing check.  Otherwise a passing replay could hide a failing proof or
    # live execution that covers the same payload commitments.
    if any(check["status"] == "FAIL" for check in evidence["checks"]):
        return tuple(badges), tuple(findings)
    if passing_control and "model_replay" in passing_kinds:
        badges.append(REPLAYED)
    if passing_control and "model_proof" in passing_kinds:
        badges.append(MODEL_PROVEN)
    if passing_control and "live_execution" in passing_kinds and passing_kinds.intersection(
        {"model_replay", "model_proof"}
    ):
        badges.append(LIVE_CONFIRMED)
    return tuple(badges), tuple(findings)


def _dataclass_or_object(value: Any, expected_type: type[Any], fields: Sequence[str]) -> dict[str, Any] | None:
    if type(value) is expected_type:
        return {field: getattr(value, field) for field in fields}
    if type(value) is dict:
        return value
    return None


class _TrustedResultsValidator:
    def __init__(self, document: dict[str, Any], limits: GateLimits) -> None:
        self.document = document
        self.limits = limits
        self.findings: list[Finding] = []
        self.differences: list[Finding] = []
        self.fatal = False
        self.check_results: dict[str, TrustedCheckResult] = {}
        self.control_results: dict[str, TrustedNegativeControlResult] = {}
        self.known_checks = {
            _canonical_sha256_unchecked(check): (index, check)
            for index, check in enumerate(document["evidence"]["checks"])
        }
        self.known_controls = {
            _canonical_sha256_unchecked(control): (index, control)
            for index, control in enumerate(document["evidence"]["negative_controls"])
        }

    def add(self, code: str, path: str, message: str, *, fatal: bool = False) -> None:
        if len(self.findings) < MAX_GATE_FINDINGS:
            self.findings.append(Finding(code, path, message))
        if fatal:
            self.fatal = True

    def difference(self, code: str, path: str, message: str) -> None:
        if len(self.differences) < MAX_GATE_FINDINGS:
            self.differences.append(Finding(code, path, message))

    def _exact_keys(self, value: dict[str, Any], path: str, required: set[str], optional: set[str]) -> bool:
        actual = set(value)
        missing = sorted(required - actual)
        unknown = sorted(actual - required - optional)
        if missing or unknown:
            self.add("VERIFIER_RESULT_KEYS", path, f"missing keys {missing}; unknown keys {unknown}", fatal=True)
            return False
        return True

    def _findings(self, value: Any, path: str) -> tuple[str, ...]:
        if type(value) not in {list, tuple} or len(value) > self.limits.max_verifier_findings:
            self.add("VERIFIER_FINDINGS", path, "expected a bounded array of findings", fatal=True)
            return ()
        for index, finding in enumerate(value):
            if type(finding) is not str or not finding.strip():
                self.add("VERIFIER_FINDINGS", f"{path}[{index}]", "finding must be a nonempty string", fatal=True)
                return ()
            try:
                finding_size = len(finding.encode("utf-8"))
            except UnicodeEncodeError:
                self.add("VERIFIER_FINDINGS", f"{path}[{index}]", "finding contains an unpaired surrogate", fatal=True)
                return ()
            if finding_size > self.limits.max_string_bytes:
                self.add("VERIFIER_FINDINGS", f"{path}[{index}]", "finding exceeds string ceiling", fatal=True)
                return ()
        return tuple(value)

    def _error(self, value: Any, path: str) -> str | None:
        if value is not None and (type(value) is not str or not value.strip()):
            self.add("VERIFIER_ERROR", path, "error must be null or a nonempty string", fatal=True)
            return None
        return value

    def _entry(
        self, value: Any, path: str, digest_field: str
    ) -> tuple[str, bool, tuple[str, ...], str | None] | None:
        expected_type = TrustedCheckResult if digest_field == "check_sha256" else TrustedNegativeControlResult
        entry = _dataclass_or_object(value, expected_type, (digest_field, "passed", "findings", "error"))
        if entry is None:
            self.add("VERIFIER_RESULT_OBJECT", path, "expected a trusted result object", fatal=True)
            return None
        if not self._exact_keys(entry, path, {digest_field, "passed"}, {"findings", "error"}):
            return None
        digest = entry[digest_field]
        if type(digest) is not str or not SHA256_RE.fullmatch(digest) or digest == ZERO_SHA256:
            self.add("VERIFIER_RESULT_DIGEST", f"{path}.{digest_field}", "invalid binding digest", fatal=True)
            return None
        if type(entry["passed"]) is not bool:
            self.add("VERIFIER_RESULT_BOOLEAN", f"{path}.passed", "passed must be a real boolean", fatal=True)
            return None
        findings = self._findings(entry.get("findings", ()), f"{path}.findings")
        error = self._error(entry.get("error"), f"{path}.error")
        if error is not None:
            if entry["passed"]:
                self.add("VERIFIER_RESULT_CONTRADICTION", path, "an errored result cannot pass", fatal=True)
            self.add("VERIFIER_ERROR", f"{path}.error", error, fatal=True)
        return digest, entry["passed"], findings, error

    def validate(self, raw: Any) -> bool:
        root = _dataclass_or_object(
            raw, TrustedDomainVerification, ("artifact_sha256", "checks", "negative_controls", "findings")
        )
        if root is None:
            self.add("VERIFIER_RESULT_OBJECT", "$.trusted_verification", "expected a verification object", fatal=True)
            return False
        if not self._exact_keys(
            root, "$.trusted_verification", {"artifact_sha256", "checks", "negative_controls"}, {"findings"}
        ):
            return False

        artifact_digest = root["artifact_sha256"]
        if (
            type(artifact_digest) is not str
            or not SHA256_RE.fullmatch(artifact_digest)
            or not hmac.compare_digest(artifact_digest, self.document["artifact_sha256"])
        ):
            self.add(
                "VERIFIER_ARTIFACT_MISMATCH",
                "$.trusted_verification.artifact_sha256",
                "trusted results are not bound to this exact artifact",
                fatal=True,
            )
        domain_findings = self._findings(root.get("findings", ()), "$.trusted_verification.findings")
        for index, message in enumerate(domain_findings):
            self.add("DOMAIN_VERIFIER_FINDING", f"$.trusted_verification.findings[{index}]", message)

        checks = root["checks"]
        if type(checks) not in {list, tuple} or len(checks) > self.limits.max_checks:
            self.add("VERIFIER_CHECKS", "$.trusted_verification.checks", "expected a bounded check result array", fatal=True)
            return False
        for index, value in enumerate(checks):
            path = f"$.trusted_verification.checks[{index}]"
            parsed = self._entry(value, path, "check_sha256")
            if parsed is None:
                continue
            digest, passed, messages, error = parsed
            if digest in self.check_results:
                self.add("DUPLICATE_VERIFIER_RESULT", path, "duplicate check binding", fatal=True)
                continue
            if digest not in self.known_checks:
                self.add("UNKNOWN_VERIFIER_CHECK", path, "result does not match any canonical source check", fatal=True)
                continue
            source_index, source_check = self.known_checks[digest]
            result = TrustedCheckResult(digest, passed, messages, error)
            self.check_results[digest] = result
            for message_index, message in enumerate(messages):
                self.add("DOMAIN_CHECK_FINDING", f"{path}.findings[{message_index}]", message)
            if source_check["status"] == "FAIL" and passed:
                self.add("SOURCE_IMPORTER_CONFLICT", path, "importer PASS cannot replace source FAIL", fatal=True)
                self.difference(
                    "SOURCE_IMPORTER_CONFLICT",
                    f"$.evidence.checks[{source_index}]",
                    "source FAIL conflicts with trusted verifier PASS",
                )
            elif source_check["status"] == "PASS" and not passed and error is None:
                self.difference(
                    "CHECK_VERDICT_DIFFERENCE",
                    f"$.evidence.checks[{source_index}]",
                    "source PASS is not independently reproduced",
                )

        controls = root["negative_controls"]
        if type(controls) not in {list, tuple} or len(controls) > self.limits.max_negative_controls:
            self.add(
                "VERIFIER_CONTROLS",
                "$.trusted_verification.negative_controls",
                "expected a bounded negative-control result array",
                fatal=True,
            )
            return False
        for index, value in enumerate(controls):
            path = f"$.trusted_verification.negative_controls[{index}]"
            parsed = self._entry(value, path, "control_sha256")
            if parsed is None:
                continue
            digest, passed, messages, error = parsed
            if digest in self.control_results:
                self.add("DUPLICATE_VERIFIER_RESULT", path, "duplicate negative-control binding", fatal=True)
                continue
            if digest not in self.known_controls:
                self.add("UNKNOWN_VERIFIER_CONTROL", path, "result does not match any canonical source control", fatal=True)
                continue
            source_index, source_control = self.known_controls[digest]
            result = TrustedNegativeControlResult(digest, passed, messages, error)
            self.control_results[digest] = result
            for message_index, message in enumerate(messages):
                self.add("DOMAIN_CONTROL_FINDING", f"{path}.findings[{message_index}]", message)
            if not source_control["passed"] and passed:
                self.add("SOURCE_IMPORTER_CONFLICT", path, "importer PASS cannot replace source FAIL", fatal=True)
                self.difference(
                    "SOURCE_IMPORTER_CONFLICT",
                    f"$.evidence.negative_controls[{source_index}]",
                    "source FAIL conflicts with trusted verifier PASS",
                )
            elif source_control["passed"] and not passed and error is None:
                self.difference(
                    "CONTROL_VERDICT_DIFFERENCE",
                    f"$.evidence.negative_controls[{source_index}]",
                    "source negative-control PASS is not independently reproduced",
                )
        return not self.fatal

    def passing_control(self) -> bool:
        return any(
            result.passed and result.error is None and self.known_controls[digest][1]["passed"]
            for digest, result in self.control_results.items()
        )

    def all_checks_pass(self, kinds: set[str]) -> tuple[bool, list[Finding], list[Finding]]:
        """Require every selected source check to have an independently passing result."""

        findings: list[Finding] = []
        differences: list[Finding] = []
        selected = [
            (digest, index, check)
            for digest, (index, check) in self.known_checks.items()
            if check["kind"] in kinds
        ]
        if not selected or not any(check["status"] == "PASS" for _, _, check in selected):
            return False, findings, differences
        ok = True
        for digest, index, check in selected:
            path = f"$.evidence.checks[{index}]"
            if check["status"] != "PASS":
                ok = False
                differences.append(Finding("SOURCE_CHECK_FAILURE", path, "a selected source check is FAIL"))
                continue
            result = self.check_results.get(digest)
            if result is None:
                ok = False
                findings.append(Finding("MISSING_CHECK_VERIFICATION", path, "trusted result is missing for this check"))
            elif not result.passed or result.error is not None:
                ok = False
                findings.append(Finding("CHECK_NOT_INDEPENDENTLY_PASSED", path, "trusted verifier did not pass this check"))
        return ok, findings, differences


def _short_exception(exc: Exception) -> str:
    message = str(exc).replace("\r", " ").replace("\n", " ")
    if len(message) > 400:
        message = message[:400] + "..."
    return f"{type(exc).__name__}: {message}"


def _differences_for_unadmitted(
    source_badges: Sequence[str], admitted_badges: set[str], existing: Sequence[Finding]
) -> tuple[Finding, ...]:
    differences = list(existing)
    for badge in source_badges:
        if badge != OBSERVED and badge not in admitted_badges:
            differences.append(
                Finding(
                    "SOURCE_BADGE_NOT_ADMITTED",
                    "$.evidence",
                    f"{badge} remains source-asserted; independent admission requirements were not met",
                )
            )
    return tuple(differences[:MAX_GATE_FINDINGS])


def intake_gameplay_evidence(
    document: str | bytes,
    *,
    verifier_results: TrustedDomainVerification | Mapping[str, Any] | None = None,
    verifier: Callable[[dict[str, Any]], TrustedDomainVerification | Mapping[str, Any]] | None = None,
    limits: GateLimits = DEFAULT_LIMITS,
) -> GameplayGateResult:
    """Validate an untrusted JSON artifact and admit only independently earned badges.

    With neither ``verifier_results`` nor ``verifier``, a valid envelope receives
    exactly ``('OBSERVED',)``.  A verifier callback receives a deep copy of parsed
    data and runs only *after* envelope validation.  Its exceptions become explicit
    findings and suppress every higher badge.  Passing precomputed results avoids
    invoking any code in this module beyond validation and hashing.

    The function returns findings instead of raising for malformed artifacts,
    verifier failures, or conflicting evidence.  Invalid ``GateLimits`` are caller
    configuration errors and raise at construction time.
    """

    if type(limits) is not GateLimits:
        raise TypeError("limits must be a GateLimits instance")

    parse_findings: list[Finding] = []

    def invalid_result() -> GameplayGateResult:
        return GameplayGateResult(
            envelope_valid=False,
            artifact_sha256=None,
            source_badges=(),
            admitted_badges=(),
            source_findings=(),
            findings=tuple(parse_findings[:MAX_GATE_FINDINGS]),
            unresolved_differences=(),
            limits=limits,
            verification_valid=None,
        )

    if type(document) not in {str, bytes}:
        parse_findings.append(Finding("DOCUMENT_TYPE", "$", "document must be UTF-8 JSON text or bytes"))
        return invalid_result()
    try:
        raw = document.encode("utf-8") if type(document) is str else document
    except UnicodeEncodeError as exc:
        parse_findings.append(Finding("INVALID_UTF8", "$", f"document is not valid UTF-8: {exc}"))
        return invalid_result()
    if len(raw) > limits.max_bytes:
        parse_findings.append(Finding("BYTE_LIMIT", "$", f"document exceeds {limits.max_bytes} bytes"))
        return invalid_result()
    try:
        text = raw.decode("utf-8")
        parsed = json.loads(text, object_pairs_hook=_object_without_duplicates, parse_constant=_reject_json_constant)
    except _DuplicateJsonKey as exc:
        parse_findings.append(Finding("DUPLICATE_JSON_KEY", "$", str(exc)))
        return invalid_result()
    except json.JSONDecodeError as exc:
        parse_findings.append(
            Finding("MALFORMED_JSON", "$", f"JSON error at line {exc.lineno}, column {exc.colno}: {exc.msg}")
        )
        return invalid_result()
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        parse_findings.append(Finding("MALFORMED_JSON", "$", f"JSON parsing failed: {_short_exception(exc)}"))
        return invalid_result()

    parse_findings.extend(_validate_json_values(parsed, limits))
    if parse_findings:
        return invalid_result()
    envelope_validator = _EnvelopeValidator(limits)
    if not envelope_validator.validate(parsed):
        parse_findings.extend(envelope_validator.findings)
        return invalid_result()

    artifact = parsed
    artifact_digest = artifact["artifact_sha256"]
    source_badges, source_findings = _source_summary(artifact)
    admitted = {OBSERVED}
    findings: list[Finding] = []
    differences: list[Finding] = []

    if verifier is None and verifier_results is None:
        differences.extend(_differences_for_unadmitted(source_badges, admitted, ()))
        return GameplayGateResult(
            True,
            artifact_digest,
            source_badges,
            tuple(badge for badge in BADGE_ORDER if badge in admitted),
            source_findings,
            (),
            tuple(differences),
            limits,
            None,
        )

    supplied_results: TrustedDomainVerification | Mapping[str, Any] | None = verifier_results
    verification_valid = True
    if verifier is not None and verifier_results is not None:
        findings.append(
            Finding("VERIFIER_CONFIGURATION", "$.trusted_verification", "supply verifier or verifier_results, not both")
        )
        supplied_results = None
        verification_valid = False
    elif verifier is not None:
        try:
            supplied_results = verifier(deepcopy(artifact))
        except Exception as exc:  # trusted-domain failures close every higher badge
            findings.append(Finding("VERIFIER_EXCEPTION", "$.trusted_verification", _short_exception(exc)))
            supplied_results = None
            verification_valid = False

    result_validator = _TrustedResultsValidator(artifact, limits)
    if not verification_valid or supplied_results is None:
        if supplied_results is None and not findings:
            findings.append(Finding("VERIFIER_RESULT_MISSING", "$.trusted_verification", "trusted results were not supplied"))
            verification_valid = False
    else:
        verification_valid = result_validator.validate(supplied_results)
        findings.extend(result_validator.findings)
        differences.extend(result_validator.differences)

    source_failure = any(check["status"] == "FAIL" for check in artifact["evidence"]["checks"])
    if verification_valid and source_failure:
        # Independent PASS results for other checks cannot aggregate around a
        # source FAIL.  Keep OBSERVED and the preserved source findings, but
        # suppress every higher admission for this artifact.
        findings.append(
            Finding(
                "SOURCE_FAIL_VETO",
                "$.evidence.checks",
                "a source FAIL suppresses every higher badge; independent PASS results cannot replace it",
            )
        )

    if verification_valid and not source_failure:
        has_control = result_validator.passing_control()
        if source_badges != (OBSERVED,) and not has_control:
            findings.append(
                Finding(
                    "MISSING_NEGATIVE_CONTROL_VERIFICATION",
                    "$.evidence.negative_controls",
                    "at least one source-passing negative control must independently pass",
                )
            )

        if has_control:
            if REPLAYED in source_badges:
                ok, new_findings, new_differences = result_validator.all_checks_pass({"model_replay"})
                findings.extend(new_findings)
                differences.extend(new_differences)
                if ok:
                    admitted.add(REPLAYED)
            if MODEL_PROVEN in source_badges:
                ok, new_findings, new_differences = result_validator.all_checks_pass({"model_proof"})
                findings.extend(new_findings)
                differences.extend(new_differences)
                if ok:
                    admitted.add(MODEL_PROVEN)
            if LIVE_CONFIRMED in source_badges:
                live_ok, live_findings, live_differences = result_validator.all_checks_pass({"live_execution"})
                live_routes: list[tuple[bool, list[Finding], list[Finding]]] = []
                if live_ok:
                    for model_kind in ("model_replay", "model_proof"):
                        model_ok, model_findings, model_differences = result_validator.all_checks_pass({model_kind})
                        live_routes.append(
                            (
                                model_ok,
                                live_findings + model_findings,
                                live_differences + model_differences,
                            )
                        )
                else:
                    live_routes.append((False, live_findings, live_differences))
                successful_route = next((route for route in live_routes if route[0]), None)
                if successful_route is not None:
                    admitted.add(LIVE_CONFIRMED)
                else:
                    for _, route_findings, route_differences in live_routes:
                        findings.extend(route_findings)
                        differences.extend(route_differences)

    final_differences = _differences_for_unadmitted(source_badges, admitted, differences)
    return GameplayGateResult(
        envelope_valid=True,
        artifact_sha256=artifact_digest,
        source_badges=source_badges,
        admitted_badges=tuple(badge for badge in BADGE_ORDER if badge in admitted),
        source_findings=source_findings,
        findings=tuple(findings[:MAX_GATE_FINDINGS]),
        unresolved_differences=final_differences,
        limits=limits,
        verification_valid=verification_valid,
    )


# Explicit alias for callers that prefer validation terminology.
validate_gameplay_artifact = intake_gameplay_evidence


__all__ = [
    "BADGE_ORDER",
    "DEFAULT_LIMITS",
    "Finding",
    "GateLimits",
    "GameplayGateResult",
    "LIVE_CONFIRMED",
    "MODEL_PROVEN",
    "OBSERVED",
    "REPLAYED",
    "TrustedCheckResult",
    "TrustedDomainVerification",
    "TrustedNegativeControlResult",
    "canonical_json_bytes",
    "canonical_sha256",
    "intake_gameplay_evidence",
    "validate_gameplay_artifact",
]
