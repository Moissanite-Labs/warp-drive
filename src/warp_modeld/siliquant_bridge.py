"""Bridge between Siliquant codebook picks and warp-drive Stage 2 fixed-radix certificates.

All arithmetic is exact integer arithmetic. No floats are used in this module. Floats are
rejected at every input boundary.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any, Mapping

from .certificate import (
    WEFT_RADIX_EXP2_MAX,
    WEFT_RADIX_EXP2_MIN,
    CertificateBounds,
    CertificateVerificationResult,
    FixedRadixCertificate,
    _canonical_sha256,
    _require_exact_int,
    verify_division_free,
)
from .errors import CertificateError

DEFAULT_RADIX_EXP2 = 32

# Fields hashed into weft_sha256. These match the canonical weft body in from_weft_dict.
_WEFT_BODY_FIELDS = (
    "radix_scale_exp2",
    "frobenius_sq_scaled",
    "spectral_norm_sq_scaled",
    "leakage_energy_scaled",
    "max_safety_dot_sq_scaled",
    "projector_epoch",
    "factor_digest",
    "quant_dtype",
)

_PAYLOAD_IDENTITY_FIELDS = ("adapter_id", "adapter_sha256", "base_weights_sha256", "weft_sha256")


def _weft_body(
    exp2: int,
    frob: int,
    spec: int,
    leak: int,
    safety: int,
    epoch: int,
    factor_digest: str,
    quant_dtype: str,
) -> dict[str, Any]:
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


def generate_fixed_radix_certificate(
    adapter_id: str,
    adapter_sha256: str,
    base_weights_sha256: str,
    frobenius_sq: int,
    spectral_norm_sq: int,
    leakage_energy: int,
    max_safety_dot_sq: int,
    radix_scale_exp2: int = DEFAULT_RADIX_EXP2,
    *,
    projector_epoch: int,
    factor_digest: str,
    quant_dtype: str,
) -> dict[str, Any]:
    """Build an L2 weft certificate payload that from_weft_dict accepts.

    The four norm arguments are already-scaled exact integers (the value times 2**radix_scale_exp2),
    the same units as the frobenius_sq_scaled family in FixedRadixCertificate. Floats are rejected.

    projector_epoch, factor_digest and quant_dtype are required by from_weft_dict but are not in the
    default signature. Callers must pass them explicitly.

    Returns a dict holding the weft body, the adapter identity fields, and weft_sha256, the canonical
    SHA-256 of the weft body. Any change to a body field without recomputing weft_sha256 is rejected.
    """
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

    body = _weft_body(exp2, frob, spec, leak, safety, epoch, factor_digest, quant_dtype)
    payload: dict[str, Any] = dict(body)
    payload["adapter_id"] = adapter_id
    payload["adapter_sha256"] = adapter_sha256
    payload["base_weights_sha256"] = base_weights_sha256
    payload["weft_sha256"] = _canonical_sha256(body)

    # Self-check: the payload must ingest cleanly, or the caller gets the error now.
    ingest_weft_certificate(payload)
    return payload


def ingest_weft_certificate(payload: Mapping[str, Any]) -> FixedRadixCertificate:
    """Ingest a payload from generate_fixed_radix_certificate through from_weft_dict.

    Checks the weft digest, the integer types, the radix range and spectral <= frobenius.
    """
    if not isinstance(payload, Mapping):
        raise CertificateError("certificate payload must be a mapping")
    for key in _PAYLOAD_IDENTITY_FIELDS:
        if key not in payload:
            raise CertificateError(f"missing certificate payload field: '{key}'")
    return FixedRadixCertificate.from_weft_dict(
        payload,
        adapter_id=payload["adapter_id"],
        adapter_sha256=payload["adapter_sha256"],
        base_weights_sha256=payload["base_weights_sha256"],
        expected_weft_sha256=payload["weft_sha256"],
    )


def load_siliquant_checker(checker_path: str | Path) -> Any:
    """Load Siliquant's shape/check_certificate.py as a module from a file path.

    The module is not vendored into warp-drive. The path must point at a checkout of Siliquant.
    """
    path = Path(checker_path)
    if not path.is_file():
        raise CertificateError(f"siliquant checker not found: {path}")
    spec = importlib.util.spec_from_file_location("siliquant_check_certificate", path)
    if spec is None or spec.loader is None:
        raise CertificateError(f"cannot load siliquant checker: {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        raise CertificateError(f"siliquant checker failed to import: {exc}") from exc
    for name in ("check", "identities", "pi_bounds_hold"):
        if not callable(getattr(module, name, None)):
            raise CertificateError(f"siliquant checker lacks callable '{name}'")
    return module


def verify_codebook_pick(receipt: Mapping[str, Any], checker_path: str | Path) -> int:
    """Run Siliquant's exact checker on a codebook pick receipt. Returns the pick index.

    receipt is the shape/certified.py output: {"budget", "candidates", "pick"}, wrapped as
    {"certificate": {...}}. Fails closed on any finding, error, or missing checker.
    """
    if not isinstance(receipt, Mapping) or not isinstance(receipt.get("certificate"), Mapping):
        raise CertificateError("codebook receipt must be a mapping with a 'certificate' mapping")
    cert = dict(receipt["certificate"])
    checker = load_siliquant_checker(checker_path)
    try:
        if not checker.identities():
            raise CertificateError("siliquant identities do not hold")
        if not checker.pi_bounds_hold():
            raise CertificateError("siliquant pi bounds do not hold")
        findings = checker.check(cert)
    except CertificateError:
        raise
    except Exception as exc:
        raise CertificateError(f"siliquant checker error: {exc}") from exc
    if findings:
        raise CertificateError("siliquant codebook pick rejected: " + "; ".join(findings[:4]))
    try:
        return int(cert["pick"])
    except (KeyError, TypeError, ValueError) as exc:
        raise CertificateError("codebook receipt has no integer pick") from exc


def verify_siliquant_bridge(
    payload: Mapping[str, Any],
    bounds: CertificateBounds,
    *,
    expected_adapter_id: str,
    expected_adapter_sha256: str,
    expected_base_weights_sha256: str,
    codebook_receipt: Mapping[str, Any] | None = None,
    checker_path: str | Path | None = None,
    scale_num: int = 1,
    scale_den: int = 1,
) -> CertificateVerificationResult:
    """Stage 2 gate for a Siliquant-backed adapter.

    Ingests the weft payload (digest and integer checks), verifies it against the bounds with exact
    cross-multiplication, and binds it to the expected adapter and base weights. If a codebook receipt
    is attached, it must also pass Siliquant's checker. Any failure raises CertificateError.
    """
    cert = ingest_weft_certificate(payload)
    result = verify_division_free(
        cert,
        bounds,
        scale_num=scale_num,
        scale_den=scale_den,
        expected_adapter_id=expected_adapter_id,
        expected_adapter_sha256=expected_adapter_sha256,
        expected_base_weights_sha256=expected_base_weights_sha256,
    )
    if codebook_receipt is not None:
        if checker_path is None:
            raise CertificateError("a codebook receipt requires checker_path")
        verify_codebook_pick(codebook_receipt, checker_path)
    return result
