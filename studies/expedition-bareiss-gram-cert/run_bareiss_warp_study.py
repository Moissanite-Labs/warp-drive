#!/usr/bin/env python3
"""
Exact Fraction-Free Bareiss Stacked-Adapter Gram Gate Study (Addressing `siliconcordat/warp#15`).

Pure Python 3 stdlib, no floating-point arithmetic or bare `assert`s. Bit-identical across all 4 isolated R4 modes:
  python3 -I -B studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py
  python3 -I -O -B studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py
  python3 -I -B -W error studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py
  python3 -I -O -B -W error studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py
"""
from __future__ import annotations

import json
from fractions import Fraction
from pathlib import Path
import random
import sys
from typing import Any

STUDY_DIR = Path(__file__).resolve().parent
WARP_ROOT = STUDY_DIR.parent.parent
WARP_SRC = WARP_ROOT / "src"

for p in (str(STUDY_DIR), str(WARP_SRC)):
    if p not in sys.path:
        sys.path.insert(0, p)

from bareiss_gram_gate import (  # noqa: E402
    GramGateError,
    bareiss_symmetric_inertia,
    certify_covert_rank_backdoor_gate,
    certify_heedle_blind_drift_haynsworth,
    certify_stacked_mde_gram,
    faddeev_leverrier_descartes_inertia,
    r_h4_stieltjes_hankel_exact,
    r_opt_exact,
    verify_integer_psd_certificate,
    verify_integer_rejection_witness,
)
from warp_modeld.certificate import (  # noqa: E402
    CertificateBounds,
    FixedRadixCertificate,
    RationalBound,
    verify_stack_division_free,
)
from warp_modeld.errors import CertificateError  # noqa: E402


def _req(cond: bool, msg: str) -> None:
    if not cond:
        raise RuntimeError(f"STUDY CHECK FAILED: {msg}")


def _orth_householder_int(d: int) -> list[list[int]]:
    v = [1 if i % 2 == 0 else -1 for i in range(d)]
    return [[(d if i == j else 0) - 2 * v[i] * v[j] for j in range(d)] for i in range(d)]


def run_study() -> dict[str, Any]:
    # 1. Dual-oracle validation: 120 random & edge-case symmetric integer matrices (Bareiss vs Descartes)
    rng = random.Random(20261121)
    mats: list[list[list[int]]] = [
        [[0, 0], [0, 0]],
        [[0, 3], [3, 0]],
        [[0, -5], [-5, 0]],
        [[1, 1, 1, 1], [1, 1, 2, 3], [1, 2, 1, 5], [1, 3, 5, 1]],
        [[0, 1, 2, 0], [1, 0, 0, 3], [2, 0, 0, 4], [0, 3, 4, 0]],
        [[4, 2, 2], [2, 1, 1], [2, 1, 1]],
    ]
    for _ in range(114):
        n = rng.randint(2, 6)
        mode = rng.randint(0, 3)
        M = [[0] * n for _ in range(n)]
        if mode == 0:
            for _ in range(rng.randint(1, n)):
                vec = [rng.randint(-3, 3) for _ in range(n)]
                for i in range(n):
                    for j in range(n):
                        M[i][j] += vec[i] * vec[j]
        elif mode == 1:
            for i in range(n):
                for j in range(i + 1, n):
                    val = rng.randint(-4, 4)
                    M[i][j] = val
                    M[j][i] = val
        else:
            for i in range(n):
                M[i][i] = rng.randint(-4, 4)
                for j in range(i + 1, n):
                    val = rng.randint(-4, 4)
                    M[i][j] = val
                    M[j][i] = val
        mats.append(M)

    psd_ok = 0
    rej_ok = 0
    for M in mats:
        b = bareiss_symmetric_inertia(M)
        d_in = faddeev_leverrier_descartes_inertia(M)
        _req(b["inertia"] == d_in, f"inertia mismatch {b['inertia']} != {d_in}")
        if b["is_psd"]:
            verify_integer_psd_certificate(M, b["psd_certificate"])
            M2 = [[sum(M[i][k] * M[k][j] for k in range(len(M))) for j in range(len(M))] for i in range(len(M))]
            M3 = [[sum(M2[i][k] * M[k][j] for k in range(len(M))) for j in range(len(M))] for i in range(len(M))]
            M4 = [[sum(M2[i][k] * M2[k][j] for k in range(len(M))) for j in range(len(M))] for i in range(len(M))]
            moments = tuple(Fraction(sum(P[i][i] for i in range(len(M)))) for P in (M, M2, M3, M4))
            h4_bound = r_h4_stieltjes_hankel_exact(*moments, 0, H_int=M, scale_div=1)
            _req(h4_bound <= b["inertia"][0], "PSD H4 bound exceeds exact positive rank")
            psd_ok += 1
        else:
            _req(verify_integer_rejection_witness(M, b["rejection_witness"]) < 0, "witness >= 0")
            rej_ok += 1

    # 2. Direct side-by-side comparison vs live `warp_modeld.certificate.verify_stack_division_free` (warp#15)
    H8 = _orth_householder_int(8)
    names4 = ("aletheia-mde", "siliquant-mde", "physics-mde", "formal-mde")
    stack4 = []
    for k, aid in enumerate(names4):
        Bk = [[H8[r][2 * k + c] for c in range(2)] for r in range(8)]
        Ak = [[Bk[r][c] for r in range(8)] for c in range(2)]
        stack4.append({"adapter_id": aid, "B_int": Bk, "A_int": Ak, "factor_exp2": 3, "route_num": 1024, "route_den_log2": 10})

    res4_s1 = certify_stacked_mde_gram(stack4, max_frobenius_sq=(8, 1), max_spectral_norm_sq=(1, 1))
    res4_tight = certify_stacked_mde_gram(stack4, max_frobenius_sq=(8, 1), max_spectral_norm_sq=(99, 100))
    _req(res4_s1["passed"] and not res4_tight["spectral_passed"], "4-orth stack check failed")
    verify_integer_rejection_witness(res4_tight["Q_stack_int"], res4_tight["rejection_witness"])

    # Live warp Stage 2 Cauchy-Schwarz gate on identical 4-adapter bounds (single: frob<=2, spec<=1; joint: frob<=8, spec<=2)
    radix = 1 << 20
    base_sha = "a" * 64
    single_b = CertificateBounds(
        max_frobenius_sq=RationalBound(2, 1), max_spectral_norm_sq=RationalBound(1, 1),
        max_leakage_energy=RationalBound(1, 1), max_safety_dot_sq=RationalBound(1, 1),
    )
    joint_b = CertificateBounds(
        max_frobenius_sq=RationalBound(8, 1), max_spectral_norm_sq=RationalBound(2, 1),
        max_leakage_energy=RationalBound(1, 1), max_safety_dot_sq=RationalBound(1, 1),
    )
    warp_items = []
    for k, aid in enumerate(names4):
        asha = f"{k:064x}"
        c = FixedRadixCertificate.create(
            adapter_id=aid, adapter_sha256=asha, base_weights_sha256=base_sha,
            radix_scale=radix, frobenius_sq_scaled=2 * radix, spectral_norm_sq_scaled=1 * radix,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        warp_items.append((c, aid, asha, 1, 1))
    warp_rejected_4_orth = False
    try:
        verify_stack_division_free(warp_items, single_b, joint_b, expected_base_weights_sha256=base_sha)
    except CertificateError:
        warp_rejected_4_orth = True
    _req(warp_rejected_4_orth, "expected live warp Stage 2 to reject 4-orth stack via N^2 tax")

    # 3. N=8 orthogonal adapters (eliminates 64x Cauchy-Schwarz spectral tax)
    H16 = _orth_householder_int(16)
    stack8 = []
    for k in range(8):
        Bk = [[H16[r][2 * k + c] for c in range(2)] for r in range(16)]
        Ak = [[Bk[r][c] for r in range(16)] for c in range(2)]
        stack8.append({"adapter_id": f"mde_{k}", "B_int": Bk, "A_int": Ak, "factor_exp2": 4, "route_num": 1, "route_den_log2": 0})
    res8_s1 = certify_stacked_mde_gram(stack8, max_frobenius_sq=(16, 1), max_spectral_norm_sq=(1, 1))
    _req(res8_s1["passed"] and res8_s1["frobenius_sq_exact"] == "16", "8-orth stack failed")

    # 4. Dense coupled 4-adapter (R=8) bit-length comparison vs naive rational LDL clearing (warp#15)
    rng_d = random.Random(20261122)
    dense_stack = [
        {
            "adapter_id": f"dense_{k}",
            "B_int": [[rng_d.randint(-2, 2) for _ in range(2)] for _ in range(6)],
            "A_int": [[rng_d.randint(-2, 2) for _ in range(6)] for _ in range(2)],
            "factor_exp2": 2,
            "route_num": 1,
            "route_den_log2": 0,
        }
        for k in range(4)
    ]
    res_dense = certify_stacked_mde_gram(dense_stack, max_frobenius_sq=(500, 1), max_spectral_norm_sq=(100, 1))
    _req(res_dense["passed"] and res_dense["bareiss_cert_bits"] < res_dense["naive_ldl_bits"], "dense bit reduction failed")

    # 5. Shared-carrier conflict rejection with integer witness + zone-gating restoration
    B_conf = [[H8[r][0], H8[r][7]] for r in range(8)]
    A_conf = [[B_conf[r][c] for r in range(8)] for c in range(2)]
    res_conf1 = certify_stacked_mde_gram(
        [stack4[0], {"adapter_id": "conflict", "B_int": B_conf, "A_int": A_conf, "factor_exp2": 3, "route_num": 1024, "route_den_log2": 10}],
        max_frobenius_sq=(10, 1), max_spectral_norm_sq=(1, 1),
    )
    res_gated = certify_stacked_mde_gram(
        [stack4[0], {"adapter_id": "conflict", "B_int": B_conf, "A_int": A_conf, "factor_exp2": 3, "route_num": 0, "route_den_log2": 10}],
        max_frobenius_sq=(10, 1), max_spectral_norm_sq=(1, 1),
    )
    _req(not res_conf1["spectral_passed"] and res_gated["passed"], "conflict/gating check failed")
    verify_integer_rejection_witness(res_conf1["Q_stack_int"], res_conf1["rejection_witness"])

    res_muted = certify_stacked_mde_gram(
        [dict(stack4[0], route_num=0)],
        max_frobenius_sq=(10, 1), max_spectral_norm_sq=(1, 1),
    )
    _req(set(res_muted) == set(res4_s1), "all-muted result schema differs from normal result schema")

    # 6. Singular-G_kk Haynsworth-Schur blind-drift certification (zero pseudoinverse / zero floats)
    H4 = _orth_householder_int(4)
    Jk_rot = [[sum(row[t] * H4[t][c] for t in range(4)) for c in range(4)] for row in ([1, 0, 0, 0], [0, 1, 0, 0], [1, 1, 0, 0])]
    Jo_rot = [[sum(row[t] * H4[t][c] for t in range(4)) for c in range(4)] for row in ([2, 0, 0, 0], [0, 0, 3, 0], [0, 0, 0, 2])]
    h9 = certify_heedle_blind_drift_haynsworth(Jk_rot, Jo_rot, tau=(9, 1), scale_div=4)
    h8 = certify_heedle_blind_drift_haynsworth(Jk_rot, Jo_rot, tau=(8, 1), scale_div=4)
    h3 = certify_heedle_blind_drift_haynsworth(Jk_rot, Jo_rot, tau=(3, 1), scale_div=4)
    _req(h9["n_unsafe_blind_directions"] == 0 and h8["n_unsafe_blind_directions"] == 1 and h3["n_unsafe_blind_directions"] == 2,
         "Haynsworth blind drift counts mismatch")

    # 7. Covert rank-3 perturbation evading norm-only gate & 2nd-moment R_opt, caught by 4th-moment R_H4
    def _conj(vals: list[int]) -> list[list[int]]:
        return [[sum(H4[i][k] * vals[k] * H4[j][k] for k in range(4)) for j in range(4)] for i in range(4)]
    H_observed = _conj([12, 4, 1, 0])
    Q_authorized = _conj([10, 0, 0, 0])
    q3 = certify_covert_rank_backdoor_gate(H_observed, Q_authorized, scale_div=192,
                                           norm_cap_frob_sq=(2, 1), norm_cap_spec_sq=(1, 1), max_allowed_extra_rank=1)
    _req(q3["norm_only_gate_evaded"] and not q3["caught_by_R_opt"] and q3["caught_by_R_H4"] and q3["soundness_ok"],
         "Q3 covert backdoor check failed")

    # 8. Negative R3/forged-certificate controls
    negative_controls_rejected: list[str] = []
    for name, fn in (
        ("float_matrix", lambda: bareiss_symmetric_inertia([[1.0]])),  # type: ignore[list-item]
        ("bool_matrix", lambda: bareiss_symmetric_inertia([[True]])),
        ("asymmetric_matrix", lambda: bareiss_symmetric_inertia([[1, 2], [3, 1]])),
        ("invalid_rejection_witness", lambda: verify_integer_rejection_witness([[2, 1], [1, 2]], [1, 0])),
        ("zero_denominator_frob_cap", lambda: certify_covert_rank_backdoor_gate(
            H_observed, Q_authorized, scale_div=192, norm_cap_frob_sq=(1, 0), norm_cap_spec_sq=(1, 1))),
        ("zero_denominator_spec_cap", lambda: certify_covert_rank_backdoor_gate(
            H_observed, Q_authorized, scale_div=192, norm_cap_frob_sq=(2, 1), norm_cap_spec_sq=(1, 0))),
        ("integer_r_opt_moment", lambda: r_opt_exact(1, Fraction(1), Fraction(1), 0)),  # type: ignore[arg-type]
        ("float_r_opt_moment", lambda: r_opt_exact(1.0, Fraction(1), Fraction(1), 0)),  # type: ignore[arg-type]
        ("integer_r_h4_moment", lambda: r_h4_stieltjes_hankel_exact(
            1, Fraction(1), Fraction(1), Fraction(1), 0, H_int=[[1]], scale_div=1)),  # type: ignore[arg-type]
        ("float_r_h4_moment", lambda: r_h4_stieltjes_hankel_exact(
            1.0, Fraction(1), Fraction(1), Fraction(1), 0, H_int=[[1]], scale_div=1)),  # type: ignore[arg-type]
        ("indefinite_r_h4_matrix", lambda: r_h4_stieltjes_hankel_exact(
            Fraction(-1), Fraction(1), Fraction(-1), Fraction(1), 0, H_int=[[-1]], scale_div=1)),
        ("mismatched_r_h4_moment", lambda: r_h4_stieltjes_hankel_exact(
            Fraction(1), Fraction(1), Fraction(1), Fraction(2), 0, H_int=[[1]], scale_div=1)),
    ):
        try:
            fn()
            raise RuntimeError("forged input accepted")
        except GramGateError:
            negative_controls_rejected.append(name)
    _req(len(negative_controls_rejected) == 12, "negative control count mismatch")

    return {
        "schema": "warp-bareiss-gram-study/v0.1",
        "dual_oracle_bareiss_vs_descartes": {"matrices": len(mats), "psd_certs": psd_ok, "h4_psd_rank_bounds": psd_ok, "rejection_witnesses": rej_ok},
        "warp15_stack4_orthogonal": {
            "exact_frob_sq": res4_s1["frobenius_sq_exact"],
            "exact_spectral_bound": 1,
            "warp_cauchy_schwarz_spectral_bound": 16,
            "spectral_tax_eliminated_factor": 16,
            "live_warp_stage2_rejected_same_stack": warp_rejected_4_orth,
            "tightness_99_100_rejected_with_witness": True,
        },
        "warp15_stack8_orthogonal": {
            "exact_frob_sq": res8_s1["frobenius_sq_exact"],
            "exact_spectral_bound": 1,
            "warp_cauchy_schwarz_spectral_bound": 64,
            "spectral_tax_eliminated_factor": 64,
        },
        "warp15_dense_R8_bit_length": {
            "bareiss_max_pivot_bits": res_dense["bareiss_max_pivot_bits"],
            "bareiss_cert_scale_bits": res_dense["bareiss_cert_bits"],
            "naive_rational_ldl_scale_bits": res_dense["naive_ldl_bits"],
            "bit_reduction_ratio_exact": f"{res_dense['naive_ldl_bits']}/{res_dense['bareiss_cert_bits']}",
        },
        "shared_carrier_conflict_and_zone_gating": {
            "conflict_inertia_at_s1": res_conf1["Q_stack_inertia"],
            "conflict_witness_qval": res_conf1["rejection_value"],
            "zone_gated_restores_s1": res_gated["passed"],
            "all_muted_schema_matches_normal": True,
        },
        "singular_gkk_haynsworth_blind_drift": {
            "rank_G_known": h9["rank_G_known"],
            "n_unsafe_tau_9_8_3": [h9["n_unsafe_blind_directions"], h8["n_unsafe_blind_directions"], h3["n_unsafe_blind_directions"]],
        },
        "covert_rank_backdoor_q3": {
            "norm_only_gate_evaded": q3["norm_only_gate_evaded"],
            "R_opt_exact": q3["R_opt_exact"],
            "R_H4_exact": q3["R_H4_exact"],
            "caught_by_R_H4": q3["caught_by_R_H4"],
        },
        "negative_controls_rejected": negative_controls_rejected,
        "all_verified": True,
    }


if __name__ == "__main__":
    print(json.dumps(run_study(), indent=2, sort_keys=False))
