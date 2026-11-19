"""Stage 2 fail-closed gate: exact integer division-free FixedRadixCertificate verifier."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
import time
from typing import Any, Sequence

from .errors import CertificateError

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def _require_exact_int(value: Any, name: str, *, allow_zero: bool = True) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise CertificateError(f"{name} must be an exact integer (got {type(value).__name__})")
    if allow_zero:
        if value < 0:
            raise CertificateError(f"{name} must be non-negative (got {value})")
    else:
        if value <= 0:
            raise CertificateError(f"{name} must be positive (got {value})")
    return value


def _canonical_sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


@dataclass(frozen=True)
class RationalBound:
    """Exact non-negative rational upper bound num / den (den > 0)."""

    num: int
    den: int = 1

    def __post_init__(self) -> None:
        _require_exact_int(self.num, "bound.num", allow_zero=True)
        _require_exact_int(self.den, "bound.den", allow_zero=False)

    def to_dict(self) -> dict[str, int]:
        return {"num": self.num, "den": self.den}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RationalBound:
        if not isinstance(data, dict):
            raise CertificateError("rational bound must be a mapping")
        try:
            return cls(num=data["num"], den=data["den"])
        except KeyError as exc:
            raise CertificateError(f"missing rational bound field: {exc}") from exc


@dataclass(frozen=True)
class CertificateBounds:
    """Exact rational policy limits for all four post-quantization certificate metrics."""

    max_frobenius_sq: RationalBound
    max_spectral_norm_sq: RationalBound
    max_leakage_energy: RationalBound
    max_safety_dot_sq: RationalBound

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CertificateBounds:
        if not isinstance(data, dict):
            raise CertificateError("certificate bounds must be a mapping")
        try:
            return cls(
                max_frobenius_sq=RationalBound.from_dict(data["max_frobenius_sq"]),
                max_spectral_norm_sq=RationalBound.from_dict(data["max_spectral_norm_sq"]),
                max_leakage_energy=RationalBound.from_dict(data["max_leakage_energy"]),
                max_safety_dot_sq=RationalBound.from_dict(data["max_safety_dot_sq"]),
            )
        except KeyError as exc:
            raise CertificateError(f"missing certificate bounds field: {exc}") from exc


@dataclass(frozen=True)
class FixedRadixCertificate:
    """Post-quantization integer certificate checked without floating-point division."""

    adapter_id: str
    adapter_sha256: str
    base_weights_sha256: str
    radix_scale: int
    frobenius_sq_scaled: int
    spectral_norm_sq_scaled: int
    leakage_energy_scaled: int
    max_safety_dot_sq_scaled: int
    cert_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.adapter_id, str) or not self.adapter_id.strip():
            raise CertificateError("certificate adapter_id must be non-empty")
        if not isinstance(self.adapter_sha256, str) or not SHA256_RE.match(self.adapter_sha256):
            raise CertificateError("certificate adapter_sha256 must be a 64-char lowercase hex digest")
        if not isinstance(self.base_weights_sha256, str) or not SHA256_RE.match(self.base_weights_sha256):
            raise CertificateError("certificate base_weights_sha256 must be a 64-char lowercase hex digest")
        _require_exact_int(self.radix_scale, "radix_scale", allow_zero=False)
        _require_exact_int(self.frobenius_sq_scaled, "frobenius_sq_scaled", allow_zero=True)
        _require_exact_int(self.spectral_norm_sq_scaled, "spectral_norm_sq_scaled", allow_zero=True)
        _require_exact_int(self.leakage_energy_scaled, "leakage_energy_scaled", allow_zero=True)
        _require_exact_int(self.max_safety_dot_sq_scaled, "max_safety_dot_sq_scaled", allow_zero=True)
        if not isinstance(self.cert_sha256, str) or not SHA256_RE.match(self.cert_sha256):
            raise CertificateError("certificate cert_sha256 must be a 64-char lowercase hex digest")

    def body_dict(self) -> dict[str, Any]:
        return {
            "adapter_id": self.adapter_id,
            "adapter_sha256": self.adapter_sha256,
            "base_weights_sha256": self.base_weights_sha256,
            "radix_scale": self.radix_scale,
            "frobenius_sq_scaled": self.frobenius_sq_scaled,
            "spectral_norm_sq_scaled": self.spectral_norm_sq_scaled,
            "leakage_energy_scaled": self.leakage_energy_scaled,
            "max_safety_dot_sq_scaled": self.max_safety_dot_sq_scaled,
        }

    def expected_cert_sha256(self) -> str:
        return _canonical_sha256(self.body_dict())

    def to_dict(self) -> dict[str, Any]:
        out = self.body_dict()
        out["cert_sha256"] = self.cert_sha256
        return out

    @classmethod
    def create(
        cls,
        *,
        adapter_id: str,
        adapter_sha256: str,
        base_weights_sha256: str,
        radix_scale: int,
        frobenius_sq_scaled: int,
        spectral_norm_sq_scaled: int,
        leakage_energy_scaled: int,
        max_safety_dot_sq_scaled: int,
    ) -> FixedRadixCertificate:
        body = {
            "adapter_id": adapter_id,
            "adapter_sha256": adapter_sha256,
            "base_weights_sha256": base_weights_sha256,
            "radix_scale": radix_scale,
            "frobenius_sq_scaled": frobenius_sq_scaled,
            "spectral_norm_sq_scaled": spectral_norm_sq_scaled,
            "leakage_energy_scaled": leakage_energy_scaled,
            "max_safety_dot_sq_scaled": max_safety_dot_sq_scaled,
        }
        return cls(cert_sha256=_canonical_sha256(body), **body)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> FixedRadixCertificate:
        if not isinstance(data, dict):
            raise CertificateError("certificate must be a mapping")
        try:
            return cls(
                adapter_id=data["adapter_id"],
                adapter_sha256=data["adapter_sha256"],
                base_weights_sha256=data["base_weights_sha256"],
                radix_scale=data["radix_scale"],
                frobenius_sq_scaled=data["frobenius_sq_scaled"],
                spectral_norm_sq_scaled=data["spectral_norm_sq_scaled"],
                leakage_energy_scaled=data["leakage_energy_scaled"],
                max_safety_dot_sq_scaled=data["max_safety_dot_sq_scaled"],
                cert_sha256=data["cert_sha256"],
            )
        except KeyError as exc:
            raise CertificateError(f"missing certificate field: {exc}") from exc


@dataclass(frozen=True)
class CertificateVerificationResult:
    adapter_id: str
    cert_sha256: str
    elapsed_ns: int
    passed: bool = True


@dataclass(frozen=True)
class StackCertificateResult:
    adapter_results: tuple[CertificateVerificationResult, ...]
    composed_bound_checked: bool
    composed_cert_verified: bool
    elapsed_ns: int


def _check_scaled_cross_mul_le(
    value_scaled: int,
    radix_scale: int,
    bound: RationalBound,
    metric: str,
    label: str,
    *,
    scale_num: int = 1,
    scale_den: int = 1,
) -> None:
    """Check (value_scaled / radix_scale) * (scale_num / scale_den)^2 <= bound.num / bound.den.

    Uses strictly exact integer multiplication with zero floating-point division.
    """
    lhs = value_scaled * (scale_num * scale_num) * bound.den
    rhs = bound.num * radix_scale * (scale_den * scale_den)
    if lhs > rhs:
        raise CertificateError(
            f"{label}: {metric} exceeds bound "
            f"(({value_scaled}/{radix_scale}) * ({scale_num}/{scale_den})^2 > {bound.num}/{bound.den})"
        )


def verify_division_free(
    cert: FixedRadixCertificate,
    bounds: CertificateBounds,
    *,
    scale_num: int = 1,
    scale_den: int = 1,
    expected_adapter_id: str | None = None,
    expected_adapter_sha256: str | None = None,
    expected_base_weights_sha256: str | None = None,
) -> CertificateVerificationResult:
    """Verify a FixedRadixCertificate using strictly exact integer cross-multiplication."""
    start_ns = time.perf_counter_ns()

    if not isinstance(cert, FixedRadixCertificate):
        raise CertificateError("cert must be a FixedRadixCertificate instance")

    _require_exact_int(scale_num, "scale_num", allow_zero=False)
    _require_exact_int(scale_den, "scale_den", allow_zero=False)

    expected_digest = cert.expected_cert_sha256()
    if not hmac.compare_digest(cert.cert_sha256, expected_digest):
        raise CertificateError(
            f"forged certificate digest for {cert.adapter_id}: got {cert.cert_sha256}, expected {expected_digest}"
        )

    if expected_adapter_id is not None and cert.adapter_id != expected_adapter_id:
        raise CertificateError(
            f"certificate adapter_id mismatch: cert has {cert.adapter_id}, expected {expected_adapter_id}"
        )
    if expected_adapter_sha256 is not None and not hmac.compare_digest(cert.adapter_sha256, expected_adapter_sha256):
        raise CertificateError(
            f"certificate adapter_sha256 mismatch for {cert.adapter_id}"
        )
    if expected_base_weights_sha256 is not None and not hmac.compare_digest(
        cert.base_weights_sha256, expected_base_weights_sha256
    ):
        raise CertificateError(
            f"certificate base_weights_sha256 mismatch for {cert.adapter_id}"
        )

    # Spectral norm squared can never exceed Frobenius norm squared for any real matrix.
    if cert.spectral_norm_sq_scaled > cert.frobenius_sq_scaled:
        raise CertificateError(
            f"inconsistent certificate for {cert.adapter_id}: "
            f"spectral_norm_sq_scaled ({cert.spectral_norm_sq_scaled}) > "
            f"frobenius_sq_scaled ({cert.frobenius_sq_scaled})"
        )

    label = f"adapter {cert.adapter_id}"
    _check_scaled_cross_mul_le(
        cert.frobenius_sq_scaled,
        cert.radix_scale,
        bounds.max_frobenius_sq,
        "frobenius_sq",
        label,
        scale_num=scale_num,
        scale_den=scale_den,
    )
    _check_scaled_cross_mul_le(
        cert.spectral_norm_sq_scaled,
        cert.radix_scale,
        bounds.max_spectral_norm_sq,
        "spectral_norm_sq",
        label,
        scale_num=scale_num,
        scale_den=scale_den,
    )
    _check_scaled_cross_mul_le(
        cert.leakage_energy_scaled,
        cert.radix_scale,
        bounds.max_leakage_energy,
        "leakage_energy",
        label,
        scale_num=scale_num,
        scale_den=scale_den,
    )
    _check_scaled_cross_mul_le(
        cert.max_safety_dot_sq_scaled,
        cert.radix_scale,
        bounds.max_safety_dot_sq,
        "max_safety_dot_sq",
        label,
        scale_num=scale_num,
        scale_den=scale_den,
    )

    elapsed_ns = time.perf_counter_ns() - start_ns
    return CertificateVerificationResult(
        adapter_id=cert.adapter_id,
        cert_sha256=cert.cert_sha256,
        elapsed_ns=elapsed_ns,
    )


def stack_composition_digest(entries: Sequence[tuple[str, str, int, int]]) -> str:
    """Deterministic SHA-256 binding a multi-adapter stack (adapter_id, adapter_sha256, scale_num, scale_den)."""
    normalized = sorted(
        (
            {
                "adapter_id": aid,
                "adapter_sha256": asha,
                "scale_num": snum,
                "scale_den": sden,
            }
            for aid, asha, snum, sden in entries
        ),
        key=lambda item: (item["adapter_id"], item["adapter_sha256"]),
    )
    return _canonical_sha256({"stack": normalized})


def verify_stack_division_free(
    items: Sequence[tuple[FixedRadixCertificate, str, str, int, int]],
    single_bounds: CertificateBounds,
    joint_bounds: CertificateBounds,
    *,
    expected_base_weights_sha256: str,
    composed_certificate: FixedRadixCertificate | None = None,
) -> StackCertificateResult:
    """Verify every adapter certificate plus exact integer Cauchy-Schwarz joint stack bounds.

    Each element in items is (cert, adapter_id, adapter_sha256, scale_num, scale_den).
    For N adapters with rational scales s_i = scale_num_i / scale_den_i:
        ||sum_i s_i Delta_i||^2 <= N * sum_i (s_i^2 * ||Delta_i||^2)
    Checked over a common integer denominator L = lcm(R_i * scale_den_i^2) with zero floats.
    """
    start_ns = time.perf_counter_ns()
    if not items:
        raise CertificateError("adapter stack must contain at least one adapter")

    per_adapter_results: list[CertificateVerificationResult] = []
    seen_ids: set[str] = set()
    denominators: list[int] = []
    stack_keys: list[tuple[str, str, int, int]] = []

    for cert, adapter_id, adapter_sha256, scale_num, scale_den in items:
        if adapter_id in seen_ids:
            raise CertificateError(f"duplicate adapter_id in stack: {adapter_id}")
        seen_ids.add(adapter_id)
        _require_exact_int(scale_num, f"{adapter_id}.scale_num", allow_zero=False)
        _require_exact_int(scale_den, f"{adapter_id}.scale_den", allow_zero=False)

        res = verify_division_free(
            cert,
            single_bounds,
            scale_num=scale_num,
            scale_den=scale_den,
            expected_adapter_id=adapter_id,
            expected_adapter_sha256=adapter_sha256,
            expected_base_weights_sha256=expected_base_weights_sha256,
        )
        per_adapter_results.append(res)
        denominators.append(cert.radix_scale * (scale_den * scale_den))
        stack_keys.append((adapter_id, adapter_sha256, scale_num, scale_den))

    composed_bound_checked = False
    composed_cert_verified = False

    if len(items) > 1:
        n_adapters = len(items)
        common_den = math.lcm(*denominators)
        metric_specs = (
            ("frobenius_sq_scaled", joint_bounds.max_frobenius_sq, "composed_frobenius_sq"),
            ("spectral_norm_sq_scaled", joint_bounds.max_spectral_norm_sq, "composed_spectral_norm_sq"),
            ("leakage_energy_scaled", joint_bounds.max_leakage_energy, "composed_leakage_energy"),
            ("max_safety_dot_sq_scaled", joint_bounds.max_safety_dot_sq, "composed_max_safety_dot_sq"),
        )
        for attr, bound, metric_name in metric_specs:
            total_scaled = 0
            for (cert, _aid, _asha, scale_num, scale_den), term_den in zip(items, denominators):
                factor = common_den // term_den
                value_i = getattr(cert, attr)
                total_scaled += value_i * (scale_num * scale_num) * factor
            cauchy_upper_num = n_adapters * total_scaled
            _check_scaled_cross_mul_le(cauchy_upper_num, common_den, bound, metric_name, "composed stack")
        composed_bound_checked = True

    if composed_certificate is not None:
        expected_stack_sha = stack_composition_digest(stack_keys)
        verify_division_free(
            composed_certificate,
            joint_bounds,
            expected_adapter_id="composed_stack",
            expected_adapter_sha256=expected_stack_sha,
            expected_base_weights_sha256=expected_base_weights_sha256,
        )
        composed_cert_verified = True

    elapsed_ns = time.perf_counter_ns() - start_ns
    return StackCertificateResult(
        adapter_results=tuple(per_adapter_results),
        composed_bound_checked=composed_bound_checked,
        composed_cert_verified=composed_cert_verified,
        elapsed_ns=elapsed_ns,
    )
