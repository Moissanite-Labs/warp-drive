"""Verifier-owned SiliQuant bridge to Stage 2 fixed-radix certificates.

All arithmetic is exact integer arithmetic. Floats are rejected at every input boundary.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import types
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Mapping

from .certificate import (
    WEFT_RADIX_EXP2_MAX,
    WEFT_RADIX_EXP2_MIN,
    SHA256_RE,
    CertificateBounds,
    CertificateVerificationResult,
    FixedRadixCertificate,
    _require_exact_int,
    verify_division_free,
)
from .errors import CertificateError

DEFAULT_RADIX_EXP2 = 32
SILIQUANT_QUANTIZATIONS = frozenset(("siliquant_4_5", "siliquant_e8", "siliquant_ballpack"))
SILIQUANT_ARMS = frozenset(("X", "Z8:p1", "Z8:p2", "E8:p1", "E8:p2"))
WEFT_BODY_FIELDS = (
    "radix_scale_exp2", "frobenius_sq_scaled", "spectral_norm_sq_scaled",
    "leakage_energy_scaled", "max_safety_dot_sq_scaled", "projector_epoch",
    "factor_digest", "quant_dtype",
)
RECEIPT_KEYS = frozenset(("budget", "candidates", "pick"))
CANDIDATE_KEYS = frozenset(("arm", "size", "codewords", "terms"))
TERM_KEYS = frozenset(("count", "groups", "sum_sq", "top_cube", "top_ball", "top_cross"))
PAYLOAD_KEYS = frozenset(WEFT_BODY_FIELDS) | {
    "adapter_id", "adapter_sha256", "base_weights_sha256", "weft_sha256"
}


@dataclass(frozen=True)
class CodebookPickVerification:
    pick: int
    receipt_sha256: str
    checker_sha256: str
    arm: str
    budget: tuple[int, int] | None

    def to_dict(self) -> dict[str, Any]:
        out = asdict(self)
        out["budget"] = list(self.budget) if self.budget is not None else None
        return out


@dataclass(frozen=True)
class SiliquantExpectations:
    quant_dtype: str
    projector_epoch: int
    factor_digest: str
    weft_sha256: str
    arm: str
    budget: tuple[int, int]
    receipt_sha256: str
    checker_sha256: str

    def __post_init__(self) -> None:
        if self.quant_dtype not in SILIQUANT_QUANTIZATIONS:
            raise CertificateError(f"unsupported SiliQuant quantization: {self.quant_dtype!r}")
        _require_exact_int(self.projector_epoch, "projector_epoch", allow_zero=True)
        for name, value in (
            ("factor_digest", self.factor_digest),
            ("weft_sha256", self.weft_sha256),
            ("receipt_sha256", self.receipt_sha256),
            ("checker_sha256", self.checker_sha256),
        ):
            _require_sha256(value, f"expected_{name}")
        if self.arm not in SILIQUANT_ARMS:
            raise CertificateError(f"unsupported SiliQuant arm: {self.arm!r}")
        _validate_budget(self.budget, "expected_budget")


@dataclass(frozen=True)
class SiliquantBridgeVerification:
    stage2: CertificateVerificationResult
    codebook: CodebookPickVerification
    quant_dtype: str
    projector_epoch: int
    factor_digest: str
    weft_sha256: str

    @property
    def passed(self) -> bool:
        return self.stage2.passed


def _require_sha256(value: Any, name: str) -> str:
    if not isinstance(value, str) or not SHA256_RE.match(value):
        raise CertificateError(f"{name} must be a 64-char lowercase hex digest")
    return value


def _exact_integer(value: Any, name: str, *, allow_zero: bool = True) -> int:
    if type(value) is int:
        number = value
    elif isinstance(value, str) and value.isascii() and value.isdecimal() and (value == "0" or not value.startswith("0")):
        number = int(value)
    else:
        raise CertificateError(f"{name} must be an exact integer or canonical decimal string")
    if number < 0 or (not allow_zero and number == 0):
        raise CertificateError(f"{name} is outside the allowed range")
    return number


def _validate_budget(budget: Any, name: str) -> tuple[int, int]:
    if not isinstance(budget, (list, tuple)) or len(budget) != 2:
        raise CertificateError(f"{name} must be a numerator/denominator pair")
    numerator, denominator = budget
    if type(numerator) is not int or type(denominator) is not int or denominator <= 0:
        raise CertificateError(f"{name} must contain exact integers with a positive denominator")
    return numerator, denominator


def _validate_receipt(receipt: Any) -> dict[str, Any]:
    if not isinstance(receipt, Mapping) or set(receipt) != {"certificate"}:
        raise CertificateError("codebook receipt must have exactly a 'certificate' key")
    cert = receipt["certificate"]
    if not isinstance(cert, Mapping) or set(cert) != RECEIPT_KEYS:
        raise CertificateError("codebook certificate must have exactly budget, candidates and pick")
    if type(cert["pick"]) is not int:
        raise CertificateError("codebook pick must be an exact integer, not a boolean, float or string")
    if cert["budget"] is not None:
        _validate_budget(cert["budget"], "codebook budget")
    candidates = cert["candidates"]
    if not isinstance(candidates, list) or not candidates:
        raise CertificateError("codebook candidates must be a nonempty list")
    for index, candidate in enumerate(candidates):
        if not isinstance(candidate, Mapping) or set(candidate) != CANDIDATE_KEYS:
            raise CertificateError(f"candidate {index} must have exactly arm, size, codewords and terms")
        if candidate["arm"] not in SILIQUANT_ARMS:
            raise CertificateError(f"candidate {index} has an unsupported arm")
        size = _exact_integer(candidate["size"], f"candidate {index} size", allow_zero=False)
        if size % 8:
            raise CertificateError(f"candidate {index} size must be a multiple of 8")
        _exact_integer(candidate["codewords"], f"candidate {index} codewords", allow_zero=False)
        terms = candidate["terms"]
        if not isinstance(terms, Mapping) or set(terms) != TERM_KEYS:
            raise CertificateError(f"candidate {index} terms must have exactly the six receipt fields")
        for term_name in TERM_KEYS:
            _exact_integer(terms[term_name], f"candidate {index} {term_name}", allow_zero=True)
        for positive in ("count", "groups", "sum_sq"):
            if _exact_integer(terms[positive], f"candidate {index} {positive}", allow_zero=False) <= 0:
                raise CertificateError(f"candidate {index} {positive} must be positive")
    if not 0 <= cert["pick"] < len(candidates):
        raise CertificateError("codebook pick is outside the candidate list")
    return dict(cert)


def codebook_receipt_sha256(receipt: Any) -> str:
    cert = _validate_receipt(receipt)
    raw = json.dumps(cert, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def checker_sha256(checker_path: str | Path) -> str:
    path = Path(checker_path)
    if not path.is_file():
        raise CertificateError(f"SiliQuant checker not found: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _weft_body(exp2: int, frob: int, spec: int, leak: int, safety: int, epoch: int,
               factor_digest: str, quant_dtype: str) -> dict[str, Any]:
    return {
        "radix_scale_exp2": exp2,
        "frobenius_sq_scaled": frob,
        "spectral_norm_sq_scaled": spec,
        "leakage_energy_scaled": leak,
        "max_safety_dot_sq_scaled": safety,
        "projector_epoch": epoch,
        "factor_digest": factor_digest,
        "quant_dtype": quant_dtype,
    }


def weft_body_sha256(body: Mapping[str, Any]) -> str:
    if not isinstance(body, Mapping) or set(body) != set(WEFT_BODY_FIELDS):
        raise CertificateError("weft body must contain exactly the documented body fields")
    raw = json.dumps(dict(body), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def generate_fixed_radix_certificate(
    adapter_id: str, adapter_sha256: str, base_weights_sha256: str,
    frobenius_sq: int, spectral_norm_sq: int, leakage_energy: int, max_safety_dot_sq: int,
    radix_scale_exp2: int = DEFAULT_RADIX_EXP2, *, projector_epoch: int,
    factor_digest: str, quant_dtype: str,
) -> dict[str, Any]:
    exp2 = _require_exact_int(radix_scale_exp2, "radix_scale_exp2", allow_zero=False)
    if not (WEFT_RADIX_EXP2_MIN <= exp2 <= WEFT_RADIX_EXP2_MAX):
        raise CertificateError(
            f"radix_scale_exp2 must be in [{WEFT_RADIX_EXP2_MIN}, {WEFT_RADIX_EXP2_MAX}] (got {exp2})"
        )
    frob = _require_exact_int(frobenius_sq, "frobenius_sq", allow_zero=True)
    spec = _require_exact_int(spectral_norm_sq, "spectral_norm_sq", allow_zero=True)
    leak = _require_exact_int(leakage_energy, "leakage_energy", allow_zero=True)
    safety = _require_exact_int(max_safety_dot_sq, "max_safety_dot_sq", allow_zero=True)
    epoch = _require_exact_int(projector_epoch, "projector_epoch", allow_zero=True)
    if spec > frob:
        raise CertificateError(
            f"spectral_norm_sq ({spec}) > frobenius_sq ({frob}) is impossible for a real matrix"
        )
    if quant_dtype not in SILIQUANT_QUANTIZATIONS:
        raise CertificateError(f"unsupported SiliQuant quantization: {quant_dtype!r}")
    _require_sha256(factor_digest, "factor_digest")
    body = _weft_body(exp2, frob, spec, leak, safety, epoch, factor_digest, quant_dtype)
    payload: dict[str, Any] = dict(body)
    payload["adapter_id"] = adapter_id
    payload["adapter_sha256"] = adapter_sha256
    payload["base_weights_sha256"] = base_weights_sha256
    payload["weft_sha256"] = weft_body_sha256(body)
    ingest_weft_certificate(payload)
    return payload


def ingest_weft_certificate(
    payload: Mapping[str, Any], *, expected_weft_sha256: str | None = None
) -> FixedRadixCertificate:
    if not isinstance(payload, Mapping) or set(payload) != PAYLOAD_KEYS:
        raise CertificateError("certificate payload has missing or unexpected fields")
    if expected_weft_sha256 is not None:
        _require_sha256(expected_weft_sha256, "expected_weft_sha256")
        if not hmac.compare_digest(payload["weft_sha256"], expected_weft_sha256):
            raise CertificateError("weft digest does not match the verifier's expected digest")
    return FixedRadixCertificate.from_weft_dict(
        payload,
        adapter_id=payload["adapter_id"],
        adapter_sha256=payload["adapter_sha256"],
        base_weights_sha256=payload["base_weights_sha256"],
        expected_weft_sha256=payload["weft_sha256"],
    )


def load_siliquant_checker(
    checker_path: str | Path, *, expected_checker_sha256: str | None = None
) -> tuple[Any, str]:
    path = Path(checker_path)
    if not path.is_file():
        raise CertificateError(f"SiliQuant checker not found: {path}")
    source = path.read_bytes()
    digest = hashlib.sha256(source).hexdigest()
    if expected_checker_sha256 is not None:
        _require_sha256(expected_checker_sha256, "expected_checker_sha256")
        if not hmac.compare_digest(digest, expected_checker_sha256):
            raise CertificateError(f"SiliQuant checker digest mismatch: computed {digest}")
    module = types.ModuleType("siliquant_check_certificate")
    module.__file__ = str(path)
    try:
        exec(compile(source, str(path), "exec"), module.__dict__)
    except Exception as exc:
        raise CertificateError(f"SiliQuant checker failed to import: {exc}") from exc
    for name in ("check", "identities", "pi_bounds_hold"):
        if not callable(getattr(module, name, None)):
            raise CertificateError(f"SiliQuant checker lacks callable '{name}'")
    return module, digest


def verify_codebook_pick(
    receipt: Any, checker_path: str | Path, *, expected_checker_sha256: str,
    expected_receipt_sha256: str, expected_arm: str | None = None,
    expected_budget: tuple[int, int] | None = None,
) -> CodebookPickVerification:
    cert = _validate_receipt(receipt)
    digest = codebook_receipt_sha256(receipt)
    _require_sha256(expected_receipt_sha256, "expected_receipt_sha256")
    if not hmac.compare_digest(digest, expected_receipt_sha256):
        raise CertificateError("codebook receipt digest does not match the verifier's expected digest")
    checker, checker_digest = load_siliquant_checker(
        checker_path, expected_checker_sha256=expected_checker_sha256
    )
    try:
        if not checker.identities():
            raise CertificateError("SiliQuant identities do not hold")
        if not checker.pi_bounds_hold():
            raise CertificateError("SiliQuant pi bounds do not hold")
        findings = checker.check(cert)
    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"SiliQuant checker error: {exc}") from exc
    if findings:
        raise CertificateError("SiliQuant codebook pick rejected: " + "; ".join(str(x) for x in findings[:4]))
    pick = cert["pick"]
    arm = cert["candidates"][pick]["arm"]
    budget = _validate_budget(cert["budget"], "codebook budget") if cert["budget"] is not None else None
    if expected_arm is not None and arm != expected_arm:
        raise CertificateError(f"codebook arm mismatch: receipt picked {arm}, expected {expected_arm}")
    if expected_budget is not None and budget != _validate_budget(expected_budget, "expected_budget"):
        raise CertificateError("codebook budget mismatch")
    return CodebookPickVerification(
        pick=pick,
        receipt_sha256=digest,
        checker_sha256=checker_digest,
        arm=arm,
        budget=budget,
    )


def verify_siliquant_bridge(
    payload: Mapping[str, Any], bounds: CertificateBounds, *,
    expected: SiliquantExpectations, expected_adapter_id: str,
    expected_adapter_sha256: str, expected_base_weights_sha256: str,
    codebook_receipt: Mapping[str, Any] | None, checker_path: str | Path | None,
    scale_num: int = 1, scale_den: int = 1,
) -> SiliquantBridgeVerification:
    if not isinstance(expected, SiliquantExpectations):
        raise CertificateError("expected must be a SiliquantExpectations instance")
    if codebook_receipt is None or checker_path is None:
        raise CertificateError("a SiliQuant bridge requires both a codebook receipt and a checker path")
    cert = ingest_weft_certificate(payload, expected_weft_sha256=expected.weft_sha256)
    if cert.adapter_id != expected_adapter_id:
        raise CertificateError("weft adapter_id does not match the expected adapter")
    body = {field: payload[field] for field in WEFT_BODY_FIELDS}
    if body["quant_dtype"] != expected.quant_dtype: raise CertificateError("weft quant_dtype mismatch")
    if body["projector_epoch"] != expected.projector_epoch: raise CertificateError("weft projector_epoch mismatch")
    if body["factor_digest"] != expected.factor_digest: raise CertificateError("weft factor_digest mismatch")
    stage2 = verify_division_free(cert, bounds, scale_num=scale_num, scale_den=scale_den, expected_adapter_id=expected_adapter_id, expected_adapter_sha256=expected_adapter_sha256, expected_base_weights_sha256=expected_base_weights_sha256)
    codebook = verify_codebook_pick(
        codebook_receipt, checker_path,
        expected_checker_sha256=expected.checker_sha256,
        expected_receipt_sha256=expected.receipt_sha256,
        expected_arm=expected.arm, expected_budget=expected.budget,
    )
    return SiliquantBridgeVerification(
        stage2=stage2, codebook=codebook, quant_dtype=expected.quant_dtype,
        projector_epoch=expected.projector_epoch, factor_digest=expected.factor_digest,
        weft_sha256=expected.weft_sha256,
    )
