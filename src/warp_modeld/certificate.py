"""Stage 2 fail-closed gate: exact integer division-free FixedRadixCertificate verifier."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import math
import re
import time
from typing import Any, Mapping, Sequence

from .errors import CertificateError

SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
WEFT_RADIX_EXP2_MIN = 8
WEFT_RADIX_EXP2_MAX = 48


def _require_exact_int(value: Any, name: str, *, allow_zero: bool = True) -> int:
    if type(value) is not int:
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
    def from_dict(cls, data: Mapping[str, Any]) -> FixedRadixCertificate:
        if not isinstance(data, Mapping):
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

    @classmethod
    def from_weft_dict(
        cls,
        data: Mapping[str, Any],
        *,
        adapter_id: str,
        adapter_sha256: str,
        base_weights_sha256: str,
        expected_weft_sha256: str | None = None,
    ) -> FixedRadixCertificate:
        """Ingest an L2 weft FixedRadixCertificate dict natively without float coercion.

        Validates strict `type(v) is int` across all integer fields, expands
        `radix_scale_exp2` -> `1 << exp2` (enforcing `[8, 48]`), checks
        `spectral_norm_sq_scaled <= frobenius_sq_scaled`, and verifies canonical
        weft digest parity when `expected_weft_sha256` is provided.
        """
        if not isinstance(data, Mapping):
            raise CertificateError("weft certificate must be a mapping")

        required = (
            "radix_scale_exp2",
            "frobenius_sq_scaled",
            "spectral_norm_sq_scaled",
            "leakage_energy_scaled",
            "max_safety_dot_sq_scaled",
            "projector_epoch",
            "factor_digest",
            "quant_dtype",
        )
        for key in required:
            if key not in data:
                raise CertificateError(f"missing weft certificate field: '{key}'")

        exp2 = _require_exact_int(data["radix_scale_exp2"], "radix_scale_exp2", allow_zero=False)
        if not (WEFT_RADIX_EXP2_MIN <= exp2 <= WEFT_RADIX_EXP2_MAX):
            raise CertificateError(
                f"radix_scale_exp2 must be in [{WEFT_RADIX_EXP2_MIN}, {WEFT_RADIX_EXP2_MAX}] (got {exp2})"
            )

        frob = _require_exact_int(data["frobenius_sq_scaled"], "frobenius_sq_scaled", allow_zero=True)
        spec = _require_exact_int(data["spectral_norm_sq_scaled"], "spectral_norm_sq_scaled", allow_zero=True)
        leak = _require_exact_int(data["leakage_energy_scaled"], "leakage_energy_scaled", allow_zero=True)
        safety = _require_exact_int(data["max_safety_dot_sq_scaled"], "max_safety_dot_sq_scaled", allow_zero=True)
        epoch = _require_exact_int(data["projector_epoch"], "projector_epoch", allow_zero=True)

        factor_digest = data["factor_digest"]
        quant_dtype = data["quant_dtype"]
        if not isinstance(factor_digest, str) or not SHA256_RE.match(factor_digest):
            raise CertificateError("weft certificate factor_digest must be a 64-char lowercase hex digest")
        if not isinstance(quant_dtype, str) or not quant_dtype.strip():
            raise CertificateError("weft certificate quant_dtype must be a non-empty string")

        if spec > frob:
            raise CertificateError(
                f"inconsistent weft certificate for {adapter_id}: "
                f"spectral_norm_sq_scaled ({spec}) > frobenius_sq_scaled ({frob})"
            )

        weft_canonical = {
            "radix_scale_exp2": exp2,
            "frobenius_sq_scaled": frob,
            "spectral_norm_sq_scaled": spec,
            "leakage_energy_scaled": leak,
            "max_safety_dot_sq_scaled": safety,
            "projector_epoch": epoch,
            "factor_digest": factor_digest,
            "quant_dtype": quant_dtype,
        }
        weft_sha = _canonical_sha256(weft_canonical)
        if expected_weft_sha256 is not None:
            if not isinstance(expected_weft_sha256, str) or not SHA256_RE.match(expected_weft_sha256):
                raise CertificateError("expected_weft_sha256 must be a 64-char lowercase hex digest")
            if not hmac.compare_digest(weft_sha, expected_weft_sha256):
                raise CertificateError(
                    f"weft certificate digest mismatch for {adapter_id}: "
                    f"computed {weft_sha}, expected {expected_weft_sha256}"
                )

        return cls.create(
            adapter_id=adapter_id,
            adapter_sha256=adapter_sha256,
            base_weights_sha256=base_weights_sha256,
            radix_scale=1 << exp2,
            frobenius_sq_scaled=frob,
            spectral_norm_sq_scaled=spec,
            leakage_energy_scaled=leak,
            max_safety_dot_sq_scaled=safety,
        )


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
    if not isinstance(bounds, CertificateBounds):
        raise CertificateError("bounds must be a CertificateBounds instance")

    _require_exact_int(scale_num, "scale_num", allow_zero=False)
    _require_exact_int(scale_den, "scale_den", allow_zero=False)

    expected_digest = cert.expected_cert_sha256()
    if not hmac.compare_digest(cert.cert_sha256, expected_digest):
        raise CertificateError(
            f"forged certificate digest for {cert.adapter_id}: got {cert.cert_sha256}, expected {expected_digest}"
        )

    if expected_adapter_id is not None:
        if not isinstance(expected_adapter_id, str) or cert.adapter_id != expected_adapter_id:
            raise CertificateError(
                f"certificate adapter_id mismatch: cert has {cert.adapter_id}, expected {expected_adapter_id}"
            )
    if expected_adapter_sha256 is not None:
        if not isinstance(expected_adapter_sha256, str) or not SHA256_RE.match(expected_adapter_sha256):
            raise CertificateError("expected_adapter_sha256 must be a 64-char lowercase hex digest")
        if not hmac.compare_digest(cert.adapter_sha256, expected_adapter_sha256):
            raise CertificateError(
                f"certificate adapter_sha256 mismatch for {cert.adapter_id}"
            )
    if expected_base_weights_sha256 is not None:
        if not isinstance(expected_base_weights_sha256, str) or not SHA256_RE.match(expected_base_weights_sha256):
            raise CertificateError("expected_base_weights_sha256 must be a 64-char lowercase hex digest")
        if not hmac.compare_digest(cert.base_weights_sha256, expected_base_weights_sha256):
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
    """Deterministic SHA-256 binding a multi-adapter stack with reduced canonical rational scales."""
    if not entries:
        raise CertificateError("stack composition entries must be non-empty")
    seen_ids: set[str] = set()
    rows: list[dict[str, Any]] = []
    for aid, asha, snum, sden in entries:
        if not isinstance(aid, str) or not aid.strip():
            raise CertificateError("stack entry adapter_id must be a non-empty string")
        if aid in seen_ids:
            raise CertificateError(f"duplicate adapter_id in stack_composition_digest: {aid}")
        seen_ids.add(aid)
        if not isinstance(asha, str) or not SHA256_RE.match(asha):
            raise CertificateError(f"stack entry adapter_sha256 invalid for {aid}")
        _require_exact_int(snum, f"{aid}.scale_num", allow_zero=False)
        _require_exact_int(sden, f"{aid}.scale_den", allow_zero=False)
        g = math.gcd(snum, sden)
        rows.append(
            {
                "adapter_id": aid,
                "adapter_sha256": asha,
                "scale_num": snum // g,
                "scale_den": sden // g,
            }
        )
    normalized = sorted(rows, key=lambda item: (item["adapter_id"], item["adapter_sha256"]))
    return _canonical_sha256({"stack": normalized})


def _check_composed_norm_triangle_exact(
    per_adapter_nums: Sequence[int],
    composed_num: int,
    metric_name: str,
) -> None:
    """Root-free exact integer triangle-inequality consistency check on a common denominator."""
    n_items = len(per_adapter_nums)
    total = sum(per_adapter_nums)
    if composed_num > n_items * total:
        raise CertificateError(
            f"inconsistent composed certificate {metric_name}: exceeds Cauchy-Schwarz upper bound"
        )
    if n_items == 1:
        if composed_num != per_adapter_nums[0]:
            raise CertificateError(
                f"inconsistent single-adapter composed certificate {metric_name}"
            )
        return
    if n_items == 2:
        a1, a2 = per_adapter_nums[0], per_adapter_nums[1]
        diff = a1 + a2 - composed_num
        if diff * diff > 4 * a1 * a2:
            raise CertificateError(
                f"inconsistent composed certificate {metric_name}: violates exact 2-adapter triangle inequality"
            )
        return
    dominant = max(per_adapter_nums)
    rest_bound = (n_items - 1) * (total - dominant)
    if dominant > rest_bound:
        diff = dominant + rest_bound - composed_num
        if diff > 0 and diff * diff > 4 * dominant * rest_bound:
            raise CertificateError(
                f"inconsistent composed certificate {metric_name}: violates dominant-adapter lower triangle bound"
            )


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

    if len(items) == 1:
        cert0, aid0, asha0, snum0, sden0 = items[0]
        verify_division_free(
            cert0,
            joint_bounds,
            scale_num=snum0,
            scale_den=sden0,
            expected_adapter_id=aid0,
            expected_adapter_sha256=asha0,
            expected_base_weights_sha256=expected_base_weights_sha256,
        )
    else:
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
        tri_den = math.lcm(composed_certificate.radix_scale, *denominators)
        comp_factor = tri_den // composed_certificate.radix_scale
        for attr, metric_name in (
            ("frobenius_sq_scaled", "composed_frobenius_sq"),
            ("spectral_norm_sq_scaled", "composed_spectral_norm_sq"),
            ("leakage_energy_scaled", "composed_leakage_energy"),
            ("max_safety_dot_sq_scaled", "composed_max_safety_dot_sq"),
        ):
            per_nums = [
                getattr(cert, attr) * (snum * snum) * (tri_den // tden)
                for (cert, _aid, _asha, snum, _sden), tden in zip(items, denominators)
            ]
            comp_num = getattr(composed_certificate, attr) * comp_factor
            _check_composed_norm_triangle_exact(per_nums, comp_num, metric_name)
        composed_cert_verified = True

    elapsed_ns = time.perf_counter_ns() - start_ns
    return StackCertificateResult(
        adapter_results=tuple(per_adapter_results),
        composed_bound_checked=composed_bound_checked,
        composed_cert_verified=composed_cert_verified,
        elapsed_ns=elapsed_ns,
    )
