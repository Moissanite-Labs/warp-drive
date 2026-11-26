#!/usr/bin/env python3
"""Clean-room zero-float audit and cross-pollination oracle for REINFORCE Zero (NVIDIA / Inferact).

Audits and bridges five systems in exact rational arithmetic (pure Python 3 stdlib, zero floats):
  1. hijkzzz/REINFORCE-Zero @ a22153de4b8c4b47faf5bf88a598d6d54801bfc7 (read-only)
  2. Inferact/zero-mismatch-rl @ 136aca87d8158adae94b5a272fa4a8a6d5cd6939 (read-only)
  3. magnitudedev/magnitude (AUDIT-068R MAG-01/MAG-02: BF16 RMS vs F32 state invariance)
  4. Moissanite-Labs/warp-drive#15 (Stage-1 RuntimeFlags & derived-scale cache invalidation)
  5. loom-fun/unsloth-Inkling-2-Mini-loom (AUDIT-074R) & aletheia v1.4.0 / AUDIT-076R (skill governance)
"""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import json
import math
from pathlib import Path
import sys
from typing import Any

PINNED_RZ_REPO = "hijkzzz/REINFORCE-Zero"
PINNED_RZ_COMMIT = "a22153de4b8c4b47faf5bf88a598d6d54801bfc7"
PINNED_ZM_REPO = "Inferact/zero-mismatch-rl"
PINNED_ZM_COMMIT = "136aca87d8158adae94b5a272fa4a8a6d5cd6939"
PINNED_PDF_SHA256 = "5abb9fe2a84d522abed5c51fc39d95de57c0d7830c69dae540023ad46adf2a64"
PINNED_TXT_SHA256 = "5d2abc64df9674b690abffd62c72c2c88da9fe8942457f1ca85471db253702b8"
NOVELTY_CLASS = "N1"

SHA256_HEX_LEN = 64
GIT_SHA_HEX_LEN = 40
HEX_CHARS = frozenset("0123456789abcdef")
VALID_CUDAGRAPH_MODES = frozenset({"FULL", "EAGER_DIAGNOSTIC_ONLY"})
DISALLOWED_ATTENTION_BACKENDS = frozenset({"auto", "default", "unknown", "none"})
VALID_SSM_STATE_DTYPES = frozenset({"float32", "bfloat16", "float16", "none"})

ANCHOR_SPECS: tuple[tuple[str, str, int, str], ...] = (
    (
        "RZ-01a",
        "REINFORCE-Zero.txt",
        1622,
        "𝐴𝜅 = 𝑒𝜅 (𝜅4 + 6𝜅2 + 3),",
    ),
    (
        "RZ-01b",
        "REINFORCE-Zero.txt",
        1625,
        "𝐶𝜅 = 14 𝑒𝜅 (𝜅6 + 13𝜅4 + 34𝜅2 + 10).",
    ),
    (
        "RZ-01c",
        "REINFORCE-Zero.txt",
        1666,
        "Theorem 1 (Accumulated error and stability).",
    ),
    (
        "RZ-01d",
        "REINFORCE-Zero.txt",
        1710,
        "≈ 68.27.",
    ),
    (
        "RZ-01e",
        "REINFORCE-Zero/ALGORITHM.md",
        120,
        r"Then $\mathbb E_q[w^2]=e^{\kappa^2}$.",
    ),
    (
        "RZ-01f",
        "REINFORCE-Zero/ALGORITHM.md",
        144,
        r"At $\kappa=0$, the stable step-size threshold is $2/3$",
    ),
    (
        "RZ-01g",
        "REINFORCE-Zero/README.md",
        33,
        "Its peak-to-median ratio is **442.54 with standard kernels**, versus **1.50 with aligned kernels**.",
    ),
    (
        "RZ-02a",
        "REINFORCE-Zero/skills/train-inference-consistency/contracts.md",
        20,
        "identical processing, hence `--rollout.top_p 1.0` and no",
    ),
    (
        "RZ-02b",
        "REINFORCE-Zero/skills/train-inference-consistency/debugging.md",
        32,
        "The per-token IS ratio overflowed",
    ),
    (
        "RZ-02c",
        "REINFORCE-Zero/ALGORITHM.md",
        152,
        "Only policy-generated action tokens enter the loss.",
    ),
    (
        "RZ-03a",
        "REINFORCE-Zero/skills/train-inference-consistency/SKILL.md",
        59,
        "Compare logprobs as bytes; the live signal is `mismatch/bitwise_frac`.",
    ),
    (
        "RZ-03b",
        "REINFORCE-Zero/skills/train-inference-consistency/molt-integration.md",
        296,
        "| Mamba cache dtype `--vllm.mamba_ssm_cache_dtype` | `float32` |",
    ),
    (
        "RZ-03c",
        "REINFORCE-Zero/skills/train-inference-consistency/molt-integration.md",
        356,
        "Natural-routing disagreement masked by R3 | ≈ 50 %",
    ),
    (
        "RZ-03d",
        "REINFORCE-Zero/skills/train-inference-consistency/molt-integration.md",
        362,
        "12-layer proxy ≈ 1e-12, full model ≈ 1e-2",
    ),
    (
        "RZ-04a",
        "REINFORCE-Zero/skills/train-inference-consistency/molt-integration.md",
        51,
        "Under `--actor.lora_dim > 0` the refit merges",
    ),
    (
        "RZ-04b",
        "zero-mismatch-rl/cases/nemotron/reports/vllm-flashinfer-kvscale-reload-bug.md",
        30,
        "`impl.bmm1_scale` and `impl.bmm2_scale` are never invalidated",
    ),
    (
        "RZ-05a",
        "zero-mismatch-rl/cases/nemotron/reports/skill-admission.md",
        26,
        "agent-only review for 8 hours",
    ),
    (
        "RZ-05b",
        "zero-mismatch-rl/cases/nemotron/reports/skill-admission.md",
        68,
        "FAILs 110 items under the pre-declared tolerance",
    ),
    (
        "RZ-05c",
        "zero-mismatch-rl/skill/templates/audit-verdict.yaml",
        14,
        "never the author",
    ),
    (
        "RZ-05d",
        "REINFORCE-Zero/skills/train-inference-consistency/debugging.md",
        123,
        "assert a.keys() == b.keys()",
    ),
    (
        "RZ-05e",
        "REINFORCE-Zero/skills/train-inference-consistency/debugging.md",
        127,
        "assert x.dtype == y.dtype and torch.equal(mx, my) and mx.any()",
    ),
    (
        "RZ-05f",
        "REINFORCE-Zero/skills/train-inference-consistency/molt-integration.md",
        130,
        "VLLM_ALLOW_INSECURE_SERIALIZATION=1",
    ),
    (
        "RZ-05g",
        "REINFORCE-Zero/skills/train-inference-consistency/acceptance.md",
        285,
        "allow_partial_load=True",
    ),
    (
        "RZ-05h",
        "REINFORCE-Zero/skills/train-inference-consistency/acceptance.md",
        319,
        "evicts the oldest directories by mtime",
    ),
    (
        "RZ-05i",
        "REINFORCE-Zero/skills/train-inference-consistency/workflow.md",
        259,
        "scaled ×1.25 and ×1.05",
    ),
    (
        "RZ-07",
        "REINFORCE-Zero/skills/train-inference-consistency/molt-integration.md",
        156,
        "weight-sync does not refresh the draft block",
    ),
)

TABLE1_ROWS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("Base R1-Distill-1.5B", ("68.7", "58.1", "38.6", "21.0", "15.0"), "40.29"),
    ("Sync TII (6k)", ("76.75", "69.81", "49.09", "28.75", "20.15"), "48.91"),
    ("Async IS (6k)", ("71.84", "66.88", "45.55", "27.08", "15.23"), "45.32"),
    ("Async IS + Seq gate (6k)", ("73.88", "69.30", "47.17", "27.43", "16.19"), "46.79"),
    ("Async IS + Token gate (6k)", ("72.10", "64.82", "45.17", "25.97", "14.87"), "44.59"),
    ("SC (TII) (6k)", ("75.56", "70.63", "47.18", "26.88", "17.26"), "47.50"),
    ("REINFORCE Zero lag 2 (6k)", ("76.84", "71.72", "48.72", "29.17", "17.58"), "48.80"),
    ("REINFORCE Zero lag 8 (6k)", ("77.71", "69.53", "49.07", "28.13", "18.20"), "48.53"),
    ("REINFORCE Zero lag 2 (20k)", ("78.69", "74.69", "50.25", "31.25", "20.63"), "51.10"),
    ("REINFORCE Zero lag 8 (20k)", ("79.43", "75.16", "50.98", "30.00", "19.07"), "50.93"),
)

TABLE3_ROWS: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("Before RL (16K)", ("21.25", "25.00", "60.31", "18.61"), "31.29"),
    ("Update 500 (16K)", ("63.75", "67.92", "94.69", "36.76"), "65.78"),
    ("Update 3000 (16K)", ("74.79", "75.62", "99.14", "36.63"), "71.55"),
    ("Final (32K)", ("76.25", "79.06", "98.75", "36.51"), "72.64"),
)

REQUIRED_GOVERNANCE_KEYS: frozenset[str] = frozenset(
    {
        "batch_invariant_mode",
        "attention_backend",
        "cudagraph_mode",
        "delivery_claim",
        "derived_scale_cache_reset_verified",
        "has_ssm_layers",
        "ssm_state_dtype",
        "lora_enabled",
        "lora_unmerged_bitwise_matched",
        "mtp_speculative_tokens",
        "rollout_top_p",
        "rollout_top_k",
        "synchronous_bitwise_frac",
        "valid_tokens",
        "nonfinite_count",
        "action_mask_excludes_non_policy_tokens",
        "allow_insecure_serialization",
        "verifier_uses_bare_assert",
        "checkpoint_allow_partial_load",
        "checkpoint_eviction_verifies_complete",
        "author_id",
        "reviewer_id",
        "human_approver_id",
        "criteria_sha256",
        "manifest_sha256",
        "planted_error_caught",
        "open_p0",
        "open_p1",
        "rollout_deficit",
        "human_budget_waiver",
    }
)


def _rat(value: Fraction) -> dict[str, int]:
    return {"num": value.numerator, "den": value.denominator}


def _rat_dec(value: Fraction, places: int = 6) -> str:
    """Exact decimal rounding helper using integer arithmetic only (zero floats)."""
    neg = value < 0
    mag = -value if neg else value
    scale = 10**places
    scaled = (mag.numerator * scale * 2 + mag.denominator) // (2 * mag.denominator)
    whole, frac = divmod(scaled, scale)
    sign = "-" if neg and scaled != 0 else ""
    return f"{sign}{whole}.{frac:0{places}d}"


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_clean_str(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) > 0
        and value == value.strip()
        and all(32 <= ord(ch) <= 126 for ch in value)
    )


def _is_sha256_hex(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == SHA256_HEX_LEN
        and all(ch in HEX_CHARS for ch in value)
    )


def _is_git_sha40(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == GIT_SHA_HEX_LEN
        and all(ch in HEX_CHARS for ch in value)
    )


def _canonical_id(value: str) -> str:
    return " ".join(value.strip().lower().split())


def exp_rational_interval(u: Fraction, terms: int = 8) -> tuple[Fraction, Fraction]:
    """Proven pure-Q Taylor enclosure [lo, hi] for exp(u) with rational u >= 0.

    For u >= 0 and N >= 1 with N + 2 > u:
      S_N(u) = sum_{n=0}^{N} u^n / n! <= exp(u) <= S_N(u) + (u^{N+1}/(N+1)!) * (N+2)/(N+2-u).
    """
    if not isinstance(u, Fraction) or not _is_int(terms) or u < 0 or terms < 1 or u >= terms + 2:
        raise ValueError("exp_rational_interval requires Fraction u >= 0, int terms >= 1, u < terms + 2")
    if u == 0:
        return Fraction(1, 1), Fraction(1, 1)
    lower = Fraction(1, 1)
    term = Fraction(1, 1)
    for n in range(1, terms + 1):
        term = term * u / n
        lower += term
    next_term = term * u / (terms + 1)
    tail = next_term * Fraction(terms + 2, 1) / (Fraction(terms + 2, 1) - u)
    return lower, lower + tail


def sqrt_rational_interval(x: Fraction, precision_bits: int = 40) -> tuple[Fraction, Fraction]:
    """Proven pure-Q square-root enclosure [lo, hi] for rational x > 0 via integer isqrt."""
    if not isinstance(x, Fraction) or not _is_int(precision_bits) or x <= 0 or precision_bits < 1:
        raise ValueError("sqrt_rational_interval requires Fraction x > 0 and int precision_bits >= 1")
    scale = 1 << precision_bits
    # Find k such that (k / scale)^2 <= x < ((k + 1) / scale)^2
    scaled_num = (x.numerator * scale * scale) // x.denominator
    k = math.isqrt(scaled_num)
    lo = Fraction(k, scale)
    hi = Fraction(k, scale) if lo * lo == x else Fraction(k + 1, scale)
    return lo, hi


def gaussian_tim_stability_analysis(
    kappa: Fraction,
    eta: Fraction,
    sigma: Fraction,
    batch_size: int,
    steps: int,
    x0: Fraction = Fraction(1, 1),
    terms: int = 8,
) -> dict[str, Any]:
    """Exact pure-Q verifier for REINFORCE Zero Appendix B Theorem 1 + persistent-bias extension.

    Verifies BOTH:
      1. Symmetric batch sign t_k = +/- kappa (NVIDIA Appendix B Eq. 13-15):
           A_k = exp(k^2) * (k^4 + 6 k^2 + 3)
           C_k = (1/4) * exp(k^2) * (k^6 + 13 k^4 + 34 k^2 + 10)
           v_k = (A_k - 1) / M,  b_k = sigma^2 * C_k / M
           rho = (1 - eta)^2 + eta^2 * v_k,  c = eta^2 * b_k
      2. Persistent one-sided kernel mismatch t_k = +kappa vs t_k = -kappa (RZ-01b):
           Uncancelled odd cross-term sigma * D_k * x_k with D_k = exp(k^2) * (k^5 + 9 k^3 + 12 k),
           coupling V_{k+1} to signed mean error (1 - eta)^k * x0!
    """
    if (
        not isinstance(kappa, Fraction)
        or not isinstance(eta, Fraction)
        or not isinstance(sigma, Fraction)
        or not isinstance(x0, Fraction)
        or not _is_int(batch_size)
        or not _is_int(steps)
        or kappa < 0
        or eta <= 0
        or eta >= 2
        or sigma <= 0
        or x0 < 0
        or batch_size < 1
        or steps < 1
    ):
        raise ValueError("invalid gaussian_tim_stability_analysis inputs")
    e_lo, e_hi = exp_rational_interval(kappa * kappa, terms=terms)
    k2 = kappa * kappa
    poly_a = k2 * k2 + 6 * k2 + 3
    poly_c = (k2 * k2 * k2 + 13 * k2 * k2 + 34 * k2 + 10) * Fraction(1, 4)
    poly_d = kappa * (k2 * k2 + 9 * k2 + 12)
    a_lo, a_hi = e_lo * poly_a, e_hi * poly_a
    c_lo, c_hi = e_lo * poly_c, e_hi * poly_c
    d_lo, d_hi = e_lo * poly_d, e_hi * poly_d
    v_lo, v_hi = (a_lo - 1) / batch_size, (a_hi - 1) / batch_size
    b_lo, b_hi = (sigma * sigma * c_lo) / batch_size, (sigma * sigma * c_hi) / batch_size
    q_mean = Fraction(1, 1) - eta
    rho_lo = q_mean * q_mean + eta * eta * v_lo
    rho_hi = q_mean * q_mean + eta * eta * v_hi
    noise_lo = eta * eta * b_lo
    noise_hi = eta * eta * b_hi
    eta_max_lo = Fraction(2, 1) / (Fraction(1, 1) + v_hi)
    eta_max_hi = Fraction(2, 1) / (Fraction(1, 1) + v_lo)

    def _geom_nonneg(r_val: Fraction, q_val: Fraction, count: int) -> Fraction:
        if count == 0:
            return Fraction(0, 1)
        if r_val == q_val:
            return count * (r_val ** (count - 1))
        return (r_val**count - q_val**count) / (r_val - q_val)

    def _closed_sym(rho_val: Fraction, c_val: Fraction) -> Fraction:
        if rho_val == 1:
            return x0 * x0 + steps * c_val
        r_pow = rho_val**steps
        return r_pow * x0 * x0 + c_val * (r_pow - Fraction(1, 1)) / (rho_val - Fraction(1, 1))

    def _geom_interval(r_lo: Fraction, r_hi: Fraction) -> tuple[Fraction, Fraction]:
        if q_mean >= 0:
            return _geom_nonneg(r_lo, q_mean, steps), _geom_nonneg(r_hi, q_mean, steps)
        # Split alternating sum into non-negative monotone even and odd sub-series in (rho^2, q^2)
        q2 = q_mean * q_mean
        neg_q = -q_mean
        half = steps // 2
        if steps % 2 == 0:
            even_lo = r_lo * _geom_nonneg(r_lo * r_lo, q2, half)
            even_hi = r_hi * _geom_nonneg(r_hi * r_hi, q2, half)
            odd_lo = neg_q * _geom_nonneg(r_lo * r_lo, q2, half)
            odd_hi = neg_q * _geom_nonneg(r_hi * r_hi, q2, half)
        else:
            even_lo = _geom_nonneg(r_lo * r_lo, q2, half + 1)
            even_hi = _geom_nonneg(r_hi * r_hi, q2, half + 1)
            odd_lo = neg_q * r_lo * _geom_nonneg(r_lo * r_lo, q2, half)
            odd_hi = neg_q * r_hi * _geom_nonneg(r_hi * r_hi, q2, half)
        return even_lo - odd_hi, even_hi - odd_lo

    v_sym_lo = _closed_sym(rho_lo, noise_lo)
    v_sym_hi = _closed_sym(rho_hi, noise_hi)
    geom_lo, geom_hi = _geom_interval(rho_lo, rho_hi)
    coeff_lo = eta * eta * sigma * d_lo * x0 / batch_size
    coeff_hi = eta * eta * sigma * d_hi * x0 / batch_size
    cross_corners = (coeff_lo * geom_lo, coeff_lo * geom_hi, coeff_hi * geom_lo, coeff_hi * geom_hi)
    cross_lo = min(cross_corners)
    cross_hi = max(cross_corners)
    zero = Fraction(0, 1)
    v_pos_lo = max(zero, v_sym_lo + cross_lo)
    v_pos_hi = max(zero, v_sym_hi + cross_hi)
    v_neg_lo = max(zero, v_sym_lo - cross_hi)
    v_neg_hi = max(zero, v_sym_hi - cross_lo)
    step1_jump_lo = eta * eta * sigma * d_lo * x0 / batch_size
    step1_jump_hi = eta * eta * sigma * d_hi * x0 / batch_size

    stable_proven = rho_hi < 1
    unstable_proven = rho_lo > 1
    v_inf_lo = noise_lo / (Fraction(1, 1) - rho_lo) if stable_proven else None
    v_inf_hi = noise_hi / (Fraction(1, 1) - rho_hi) if stable_proven else None

    return {
        "kappa": _rat(kappa),
        "eta": _rat(eta),
        "sigma": _rat(sigma),
        "batch_size": batch_size,
        "steps": steps,
        "A_kappa_dec": [_rat_dec(a_lo), _rat_dec(a_hi)],
        "C_kappa_dec": [_rat_dec(c_lo), _rat_dec(c_hi)],
        "D_kappa_dec": [_rat_dec(d_lo), _rat_dec(d_hi)],
        "rho_dec": [_rat_dec(rho_lo), _rat_dec(rho_hi)],
        "c_noise_dec": [_rat_dec(noise_lo), _rat_dec(noise_hi)],
        "eta_max_dec": [_rat_dec(eta_max_lo), _rat_dec(eta_max_hi)],
        "stable_proven": stable_proven,
        "unstable_proven": unstable_proven,
        "V_inf_dec": None if v_inf_lo is None else [_rat_dec(v_inf_lo), _rat_dec(v_inf_hi)],
        "V_steps_sym_dec": [_rat_dec(v_sym_lo), _rat_dec(v_sym_hi)],
        "V_steps_persistent_pos_dec": [_rat_dec(v_pos_lo), _rat_dec(v_pos_hi)],
        "V_steps_persistent_neg_dec": [_rat_dec(v_neg_lo), _rat_dec(v_neg_hi)],
        "step1_persistent_pos_jump_dec": [_rat_dec(step1_jump_lo), _rat_dec(step1_jump_hi)],
        "persistent_pos_strictly_worse": v_pos_lo > v_sym_hi if kappa > 0 and x0 > 0 else False,
        "exact_zero_kappa": {
            "rho": _rat(rho_lo),
            "c_noise": _rat(noise_lo),
            "eta_max": _rat(eta_max_lo),
            "V_inf": None if v_inf_lo is None else _rat(v_inf_lo),
        }
        if kappa == 0
        else None,
    }


def gaussian_variance_mismatch_analysis(
    gamma_sq: Fraction,
    eta: Fraction,
    batch_size: int = 1,
) -> dict[str, Any]:
    """Exact pure-Q proof of variance/scale mismatch blowup (RZ-01c).

    For target N(theta, sigma^2) and sampler N(theta, gamma_sq * sigma^2) with variance ratio gamma_sq > 0:
      - If 2 * gamma_sq <= 1 (gamma_sq <= 1/2): E_mu[w^2] = +inf, Var(g_bar) = +inf, eta_max = 0.
      - If 2 * gamma_sq > 1: exact rational A(gamma)^2 = 9 * gamma_sq^6 / (2 * gamma_sq - 1)^5,
        v(gamma) = (A(gamma) - 1) / M, eta_max = 2 / (1 + v(gamma)).
    """
    if (
        not isinstance(gamma_sq, Fraction)
        or not isinstance(eta, Fraction)
        or not _is_int(batch_size)
        or gamma_sq <= 0
        or eta <= 0
        or eta >= 2
        or batch_size < 1
    ):
        raise ValueError("invalid gaussian_variance_mismatch_analysis inputs")
    denom = 2 * gamma_sq - Fraction(1, 1)
    if denom <= 0:
        return {
            "gamma_sq": _rat(gamma_sq),
            "eta": _rat(eta),
            "batch_size": batch_size,
            "infinite_variance": True,
            "stable_proven": False,
            "unstable_proven": True,
            "A_gamma_sq": None,
            "eta_max_dec": ["0.000000", "0.000000"],
        }
    a_sq = Fraction(9, 1) * (gamma_sq**6) / (denom**5)
    a_lo, a_hi = sqrt_rational_interval(a_sq)
    v_lo = (a_lo - Fraction(1, 1)) / batch_size
    v_hi = (a_hi - Fraction(1, 1)) / batch_size
    eta_max_lo = Fraction(2, 1) / (Fraction(1, 1) + v_hi)
    eta_max_hi = Fraction(2, 1) / (Fraction(1, 1) + v_lo)
    return {
        "gamma_sq": _rat(gamma_sq),
        "eta": _rat(eta),
        "batch_size": batch_size,
        "infinite_variance": False,
        "A_gamma_sq": _rat(a_sq),
        "A_gamma_dec": [_rat_dec(a_lo), _rat_dec(a_hi)],
        "eta_max_dec": [_rat_dec(eta_max_lo), _rat_dec(eta_max_hi)],
        "stable_proven": eta < eta_max_lo,
        "unstable_proven": eta > eta_max_hi,
    }


def discrete_policy_gradient_audit(
    p: list[Fraction],
    q: list[Fraction],
    advantages: list[Fraction],
    scores: list[Fraction],
) -> dict[str, Any]:
    """Exact pure-Q verification of Eq. (3)-(5), SC sign reversal, and support-truncation bias (RZ-02)."""
    if (
        not isinstance(p, list)
        or not isinstance(q, list)
        or not isinstance(advantages, list)
        or not isinstance(scores, list)
        or len(p) < 2
        or not (len(p) == len(q) == len(advantages) == len(scores))
        or not all(isinstance(v, Fraction) and v > 0 for v in p)
        or not all(isinstance(v, Fraction) and v >= 0 for v in q)
        or not all(isinstance(v, Fraction) for v in advantages)
        or not all(isinstance(v, Fraction) for v in scores)
        or sum(p) != Fraction(1, 1)
        or sum(q) != Fraction(1, 1)
        or sum(pi * si for pi, si in zip(p, scores)) != Fraction(0, 1)
    ):
        raise ValueError("invalid discrete policy distribution or non-zero-mean target score")
    g_star = sum(pi * ai * si for pi, ai, si in zip(p, advantages, scores))
    e_q_a = sum(qi * ai for qi, ai in zip(q, advantages))
    e_q_s = sum(qi * si for qi, si in zip(q, scores))
    drift = e_q_a * e_q_s
    e_q_as = sum(qi * ai * si for qi, ai, si in zip(q, advantages, scores))
    g_sc = e_q_as - drift
    support_complete = all(qi > 0 for qi in q)
    e_q_ws = sum(qi * (pi / qi) * si for pi, qi, si in zip(p, q, scores) if qi > 0)
    g_is = sum(qi * (pi / qi) * ai * si for pi, qi, ai, si in zip(p, q, advantages, scores) if qi > 0)
    var_p = sum(pi * (ai * si) ** 2 for pi, ai, si in zip(p, advantages, scores)) - g_star * g_star
    var_is = (
        sum(qi * ((pi / qi) * ai * si) ** 2 for pi, qi, ai, si in zip(p, q, advantages, scores) if qi > 0)
        - g_is * g_is
    )
    return {
        "support_complete": support_complete,
        "g_star": _rat(g_star),
        "e_q_As": _rat(e_q_as),
        "score_mean_drift": _rat(drift),
        "g_sc": _rat(g_sc),
        "sc_covariance_bias": _rat(g_sc - g_star),
        "sc_sign_reversed": (g_star > 0 and g_sc < 0) or (g_star < 0 and g_sc > 0),
        "e_q_ws": _rat(e_q_ws),
        "g_is": _rat(g_is),
        "is_bias": _rat(g_is - g_star),
        "is_unbiased": g_is == g_star and e_q_ws == 0,
        "var_on_policy": _rat(var_p),
        "var_unclipped_is": _rat(var_is),
    }


def verify_paper_tables() -> dict[str, Any]:
    """Exact pure-Q audit of Tables 1, 3, 4, 5, 6 from REINFORCE-Zero.pdf & zero-mismatch-rl."""
    t1_results = []
    for name, cols, reported in TABLE1_ROWS:
        exact = sum(Fraction(c) for c in cols) / Fraction(len(cols), 1)
        rep = Fraction(reported)
        diff = exact - rep
        t1_results.append(
            {
                "recipe": name,
                "exact_macro": _rat(exact),
                "reported_macro": _rat(rep),
                "diff": _rat(diff),
                "within_display_rounding": abs(diff) <= Fraction(1, 100),
            }
        )
    t3_results = []
    for name, cols, reported in TABLE3_ROWS:
        exact = sum(Fraction(c) for c in cols) / Fraction(len(cols), 1)
        rep = Fraction(reported)
        diff = exact - rep
        t3_results.append(
            {
                "stage": name,
                "exact_macro": _rat(exact),
                "reported_macro": _rat(rep),
                "diff": _rat(diff),
                "within_display_rounding": abs(diff) <= Fraction(1, 200),
            }
        )
    sync_hrs = Fraction("164.77")
    rz_hrs = Fraction("68.55")
    speedup = sync_hrs / rz_hrs
    osworld_gain = Fraction("56.16") - Fraction("50.97")
    osworld_overhead = (Fraction("944.25") - Fraction("884.17")) / Fraction("884.17")
    ds_v4_rollout_loss = (Fraction("26.53") - Fraction("24.22")) / Fraction("26.53")
    return {
        "table1_rows_verified": len(t1_results),
        "table1_all_within_0_01": all(r["within_display_rounding"] for r in t1_results),
        "table1": t1_results,
        "table3_rows_verified": len(t3_results),
        "table3_all_within_0_005": all(r["within_display_rounding"] for r in t3_results),
        "table3": t3_results,
        "table4_osworld_gain": _rat(osworld_gain),
        "table5_speedup_exact": _rat(speedup),
        "table5_speedup_dec": _rat_dec(speedup, 4),
        "table5_sync_sec_per_update": _rat(sync_hrs * 3600 / 12000),
        "table5_rz_sec_per_update": _rat(rz_hrs * 3600 / 12000),
        "table6_osworld_step_overhead": _rat(osworld_overhead),
        "table6_osworld_step_overhead_dec": _rat_dec(osworld_overhead, 4),
        "zero_mismatch_ds_v4_flash_loss": _rat(ds_v4_rollout_loss),
        "zero_mismatch_ds_v4_flash_loss_dec": _rat_dec(ds_v4_rollout_loss, 4),
    }


def evaluate_tii_governance_boundary(config: dict[str, Any]) -> dict[str, Any]:
    """Fail-closed pure-Q TII execution-closure & coding-agent skill governance gate.

    Bridges REINFORCE Zero / zero-mismatch-rl with Magnitude (AUDIT-068R),
    Moissanite-Labs/warp-drive#15, Inkling (AUDIT-074R), and aletheia v1.4.0 / AUDIT-076R.
    """
    if not isinstance(config, dict) or set(config.keys()) != REQUIRED_GOVERNANCE_KEYS:
        raise ValueError("config must be a dict with the exact required governance key set")
    reasons: list[str] = []

    if (
        config["batch_invariant_mode"] is not True
        or not _is_clean_str(config["attention_backend"])
        or _canonical_id(config["attention_backend"]) in DISALLOWED_ATTENTION_BACKENDS
    ):
        reasons.append("KERNEL_EXECUTION_NOT_PINNED")

    if (
        not _is_clean_str(config["cudagraph_mode"])
        or config["cudagraph_mode"] not in VALID_CUDAGRAPH_MODES
        or not isinstance(config["delivery_claim"], bool)
        or (config["delivery_claim"] and config["cudagraph_mode"] != "FULL")
    ):
        reasons.append("CUDAGRAPH_DELIVERY_CLOSURE_INVALID")

    if config["derived_scale_cache_reset_verified"] is not True:
        reasons.append("DERIVED_SCALE_CACHE_STALE")

    if (
        not isinstance(config["has_ssm_layers"], bool)
        or not _is_clean_str(config["ssm_state_dtype"])
        or _canonical_id(config["ssm_state_dtype"]) not in VALID_SSM_STATE_DTYPES
        or (config["has_ssm_layers"] and _canonical_id(config["ssm_state_dtype"]) != "float32")
    ):
        reasons.append("SSM_STATE_PRECISION_DEGRADED")

    if (
        not isinstance(config["lora_enabled"], bool)
        or not isinstance(config["lora_unmerged_bitwise_matched"], bool)
        or (config["lora_enabled"] and config["lora_unmerged_bitwise_matched"] is not True)
    ):
        reasons.append("LORA_MERGE_ROUNDING_MISMATCH")

    if not _is_int(config["mtp_speculative_tokens"]) or config["mtp_speculative_tokens"] != 0:
        reasons.append("SPECULATIVE_MTP_UNVERIFIED")

    if (
        not isinstance(config["rollout_top_p"], Fraction)
        or config["rollout_top_p"] != Fraction(1, 1)
        or not _is_int(config["rollout_top_k"])
        or config["rollout_top_k"] != 0
    ):
        reasons.append("SUPPORT_TRUNCATION_BREAKS_IS")

    if (
        not isinstance(config["synchronous_bitwise_frac"], Fraction)
        or config["synchronous_bitwise_frac"] != Fraction(0, 1)
        or not _is_int(config["valid_tokens"])
        or config["valid_tokens"] <= 0
        or not _is_int(config["nonfinite_count"])
        or config["nonfinite_count"] != 0
        or config["action_mask_excludes_non_policy_tokens"] is not True
    ):
        reasons.append("BITWISE_FALSE_GREEN_OR_NONZERO_MISMATCH")

    if config["allow_insecure_serialization"] is not False:
        reasons.append("INSECURE_PICKLE_SERIALIZATION_ENABLED")

    if config["verifier_uses_bare_assert"] is not False:
        reasons.append("VERIFIER_BARE_ASSERT_O_STRIPPING_HAZARD")

    if (
        config["checkpoint_allow_partial_load"] is not False
        or config["checkpoint_eviction_verifies_complete"] is not True
    ):
        reasons.append("CHECKPOINT_RESUME_UNVERIFIED")

    roles_valid = (
        _is_clean_str(config["author_id"])
        and _is_clean_str(config["reviewer_id"])
        and _is_clean_str(config["human_approver_id"])
    )
    if not roles_valid or len(
        {
            _canonical_id(config["author_id"]),
            _canonical_id(config["reviewer_id"]),
            _canonical_id(config["human_approver_id"]),
        }
    ) != 3:
        reasons.append("AGENT_SELF_APPROVAL_OR_ROLE_COLLAPSE")

    if (
        not _is_sha256_hex(config["criteria_sha256"])
        or not _is_sha256_hex(config["manifest_sha256"])
        or config["criteria_sha256"] == config["manifest_sha256"]
        or config["planted_error_caught"] is not True
        or not _is_int(config["open_p0"])
        or config["open_p0"] != 0
        or not _is_int(config["open_p1"])
        or config["open_p1"] != 0
    ):
        reasons.append("AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID")

    if (
        not isinstance(config["rollout_deficit"], Fraction)
        or not isinstance(config["human_budget_waiver"], bool)
        or config["rollout_deficit"] < Fraction(-1, 1)
        or config["rollout_deficit"] >= Fraction(1, 1)
        or (config["rollout_deficit"] > Fraction(1, 5) and config["human_budget_waiver"] is not True)
    ):
        reasons.append("ROLLOUT_THROUGHPUT_BUDGET_EXCEEDED")

    return {"admitted": len(reasons) == 0, "reasons": reasons}


def _read_git_head_sha(repo_root: Path) -> str:
    git_dir = (repo_root / ".git").resolve()
    head_text = (git_dir / "HEAD").read_text(encoding="utf-8").strip()
    if head_text.startswith("ref: "):
        ref_rel = head_text[5:].strip()
        if not ref_rel.startswith("refs/") or ".." in Path(ref_rel).parts or "\\" in ref_rel:
            raise ValueError(f"invalid git ref path: {ref_rel}")
        ref_path = (git_dir / ref_rel).resolve()
        if not ref_path.is_relative_to(git_dir):
            raise ValueError(f"git ref escapes .git directory: {ref_rel}")
        if ref_path.is_file():
            sha = ref_path.read_text(encoding="utf-8").strip()
            if not _is_git_sha40(sha):
                raise ValueError(f"invalid loose git sha for {ref_rel}")
            return sha
        packed = git_dir / "packed-refs"
        if packed.is_file():
            for raw_line in packed.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if not line or line.startswith("#") or line.startswith("^"):
                    continue
                parts = line.split()
                if len(parts) == 2 and parts[1] == ref_rel and _is_git_sha40(parts[0]):
                    return parts[0]
        raise ValueError(f"unresolvable git ref: {ref_rel}")
    if not _is_git_sha40(head_text):
        raise ValueError("invalid detached git HEAD sha")
    return head_text


def inspect_reinforce_zero_repos(staging_root: Path) -> dict[str, Any]:
    """Read-only commit, digest, and verbatim line-anchor verification."""
    rz_head = _read_git_head_sha(staging_root / "REINFORCE-Zero")
    zm_head = _read_git_head_sha(staging_root / "zero-mismatch-rl")
    pdf_sha = hashlib.sha256((staging_root / "REINFORCE-Zero" / "REINFORCE-Zero.pdf").read_bytes()).hexdigest()
    txt_sha = hashlib.sha256((staging_root / "REINFORCE-Zero.txt").read_bytes()).hexdigest()

    anchors: list[dict[str, Any]] = []
    all_matched = (
        rz_head == PINNED_RZ_COMMIT
        and zm_head == PINNED_ZM_COMMIT
        and pdf_sha == PINNED_PDF_SHA256
        and txt_sha == PINNED_TXT_SHA256
    )
    for finding_id, rel_path, expected_line, needle in ANCHOR_SPECS:
        file_path = staging_root / rel_path
        lines = file_path.read_text(encoding="utf-8").split("\n")
        line_ok = 1 <= expected_line <= len(lines) and needle in lines[expected_line - 1]
        if not line_ok:
            all_matched = False
        anchors.append(
            {
                "finding_id": finding_id,
                "path": rel_path,
                "line": expected_line,
                "matched": line_ok,
            }
        )
    return {
        "anchor_mode": "live_readonly",
        "rz_commit_pinned": PINNED_RZ_COMMIT,
        "rz_commit_observed": rz_head,
        "zm_commit_pinned": PINNED_ZM_COMMIT,
        "zm_commit_observed": zm_head,
        "pdf_sha256_matches": pdf_sha == PINNED_PDF_SHA256,
        "txt_sha256_matches": txt_sha == PINNED_TXT_SHA256,
        "anchors_total": len(anchors),
        "anchors_verified": sum(1 for item in anchors if item["matched"]),
        "all_anchors_matched": all_matched,
        "anchors": anchors,
    }


def _baseline_hardened_config() -> dict[str, Any]:
    return {
        "batch_invariant_mode": True,
        "attention_backend": "TRITON_ATTN",
        "cudagraph_mode": "FULL",
        "delivery_claim": True,
        "derived_scale_cache_reset_verified": True,
        "has_ssm_layers": True,
        "ssm_state_dtype": "float32",
        "lora_enabled": True,
        "lora_unmerged_bitwise_matched": True,
        "mtp_speculative_tokens": 0,
        "rollout_top_p": Fraction(1, 1),
        "rollout_top_k": 0,
        "synchronous_bitwise_frac": Fraction(0, 1),
        "valid_tokens": 4096,
        "nonfinite_count": 0,
        "action_mask_excludes_non_policy_tokens": True,
        "allow_insecure_serialization": False,
        "verifier_uses_bare_assert": False,
        "checkpoint_allow_partial_load": False,
        "checkpoint_eviction_verifies_complete": True,
        "author_id": "agent-kernel-porter",
        "reviewer_id": "independent-verifier",
        "human_approver_id": "human-release-owner",
        "criteria_sha256": "a" * 64,
        "manifest_sha256": "b" * 64,
        "planted_error_caught": True,
        "open_p0": 0,
        "open_p1": 0,
        "rollout_deficit": Fraction(17, 250),  # 6.8% OSWorld overhead
        "human_budget_waiver": False,
    }


def run_audit_suite(staging_root: Path | None) -> dict[str, Any]:
    """Execute full deterministic pure-Q proof and cross-pollination suite."""
    if staging_root is not None:
        anchor_report = inspect_reinforce_zero_repos(staging_root)
    else:
        anchor_report = {
            "anchor_mode": "standalone_no_repo",
            "rz_commit_pinned": PINNED_RZ_COMMIT,
            "zm_commit_pinned": PINNED_ZM_COMMIT,
            "pdf_sha256_pinned": PINNED_PDF_SHA256,
            "txt_sha256_pinned": PINNED_TXT_SHA256,
            "anchors_total": len(ANCHOR_SPECS),
            "anchors_verified": 0,
            "all_anchors_matched": False,
        }

    # RZ-01a/b: Gaussian TIM theorem (kappa=0, critical bracket, kappa=1/5 + persistent +kappa)
    g_zero = gaussian_tim_stability_analysis(
        kappa=Fraction(0, 1), eta=Fraction(3, 5), sigma=Fraction(1, 5), batch_size=1, steps=200
    )
    g_crit_lo = gaussian_tim_stability_analysis(
        kappa=Fraction(1892, 10000), eta=Fraction(3, 5), sigma=Fraction(1, 5), batch_size=1, steps=200
    )
    g_crit_hi = gaussian_tim_stability_analysis(
        kappa=Fraction(1893, 10000), eta=Fraction(3, 5), sigma=Fraction(1, 5), batch_size=1, steps=200
    )
    g_mismatch = gaussian_tim_stability_analysis(
        kappa=Fraction(1, 5), eta=Fraction(3, 5), sigma=Fraction(1, 5), batch_size=1, steps=200
    )

    # RZ-01c: Variance / scale mismatch blowup (exact variance ratio gamma_sq)
    var_matched = gaussian_variance_mismatch_analysis(gamma_sq=Fraction(1, 1), eta=Fraction(3, 5))
    var_nine_tenths = gaussian_variance_mismatch_analysis(gamma_sq=Fraction(81, 100), eta=Fraction(3, 5))
    var_three_quarters = gaussian_variance_mismatch_analysis(gamma_sq=Fraction(9, 16), eta=Fraction(3, 5))
    var_critical_half = gaussian_variance_mismatch_analysis(gamma_sq=Fraction(1, 2), eta=Fraction(1, 100))
    var_subcritical_7_10 = gaussian_variance_mismatch_analysis(gamma_sq=Fraction(49, 100), eta=Fraction(1, 100))

    # RZ-02: Discrete-token SC sign-reversal vs unclipped IS & support-truncation counter-theorem
    p_tok = [Fraction(1, 2), Fraction(1, 4), Fraction(1, 4)]
    q_full = [Fraction(1, 20), Fraction(9, 20), Fraction(1, 2)]
    q_trunc = [Fraction(0, 1), Fraction(9, 19), Fraction(10, 19)]
    scores_tok = [Fraction(1, 1), Fraction(1, 1), Fraction(-3, 1)]
    adv_tok = [Fraction(10, 1), Fraction(-4, 1), Fraction(0, 1)]
    disc_full = discrete_policy_gradient_audit(p_tok, q_full, adv_tok, scores_tok)
    disc_trunc = discrete_policy_gradient_audit(p_tok, q_trunc, adv_tok, scores_tok)

    # RZ-03..RZ-07: Governance boundary (hardened pass vs upstream vulnerable rejection)
    hardened_cfg = _baseline_hardened_config()
    hardened_verdict = evaluate_tii_governance_boundary(hardened_cfg)

    vuln_cfg = dict(hardened_cfg)
    vuln_cfg.update(
        {
            "batch_invariant_mode": False,
            "attention_backend": "auto",
            "cudagraph_mode": "EAGER_DIAGNOSTIC_ONLY",
            "derived_scale_cache_reset_verified": False,
            "ssm_state_dtype": "bfloat16",
            "lora_unmerged_bitwise_matched": False,
            "mtp_speculative_tokens": 2,
            "rollout_top_p": Fraction(19, 20),
            "synchronous_bitwise_frac": Fraction(1, 100),
            "allow_insecure_serialization": True,
            "verifier_uses_bare_assert": True,
            "checkpoint_allow_partial_load": True,
            "reviewer_id": "AGENT-KERNEL-PORTER ",
            "planted_error_caught": False,
            "rollout_deficit": Fraction(304, 1000),
        }
    )
    vuln_verdict = evaluate_tii_governance_boundary(vuln_cfg)

    payload: dict[str, Any] = {
        "schema": "reinforce-zero-tii-audit.v1",
        "novelty_class": NOVELTY_CLASS,
        "zero_float_arithmetic": True,
        "targets": [
            f"{PINNED_RZ_REPO}@{PINNED_RZ_COMMIT}",
            f"{PINNED_ZM_REPO}@{PINNED_ZM_COMMIT}",
        ],
        "cross_pollination_targets": [
            "magnitudedev/magnitude (AUDIT-068R MAG-01/MAG-02)",
            "Moissanite-Labs/warp-drive#15 (Stage-1 RuntimeFlags & derived-scale flush)",
            "loom-fun/unsloth-Inkling-2-Mini-loom (AUDIT-074R speculative/top-k truncation)",
            "Foundation-0/aletheia v1.4.0 & LangChain Knowledge Factory (AUDIT-076R skill governance)",
        ],
        "anchors": anchor_report,
        "proofs": {
            "rz_01_gaussian_tim": {
                "kappa_0": g_zero,
                "kappa_crit_lower_stable": g_crit_lo,
                "kappa_crit_upper_unstable": g_crit_hi,
                "kappa_one_fifth": g_mismatch,
                "variance_mismatch": {
                    "gamma_sq_1": var_matched,
                    "gamma_sq_81_100": var_nine_tenths,
                    "gamma_sq_9_16": var_three_quarters,
                    "gamma_sq_half_critical_infinite": var_critical_half,
                    "gamma_sq_49_100_subcritical_infinite": var_subcritical_7_10,
                },
            },
            "rz_02_discrete_is_vs_sc": {
                "full_support_sc_sign_reversal": disc_full,
                "truncated_support_is_breaks": disc_trunc,
            },
            "rz_06_paper_tables_exact": verify_paper_tables(),
            "rz_03_to_07_governance_boundary": {
                "hardened_admitted": hardened_verdict,
                "unhardened_rejected": vuln_verdict,
            },
        },
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    payload["canonical_sha256"] = hashlib.sha256(canonical).hexdigest()
    return payload


def _default_staging_root() -> Path | None:
    candidate = Path(__file__).resolve().parent.parent / "repos" / "reinforce-zero"
    if (candidate / "REINFORCE-Zero" / ".git" / "HEAD").is_file() and (
        candidate / "zero-mismatch-rl" / ".git" / "HEAD"
    ).is_file():
        return candidate
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Clean-room zero-float audit for REINFORCE Zero & TII.")
    parser.add_argument("--staging-dir", type=Path, default=None, help="Read-only reinforce-zero staging dir")
    parser.add_argument("--standalone", action="store_true", help="Run standalone without staged repos")
    parser.add_argument("--write-cert", type=Path, default=None, help="Write deterministic JSON certificate")
    parser.add_argument("--json", action="store_true", help="Emit full JSON certificate to stdout")
    args = parser.parse_args(argv)

    staging_root = None if args.standalone else (args.staging_dir or _default_staging_root())
    cert = run_audit_suite(staging_root)
    rendered = json.dumps(cert, indent=2, sort_keys=True) + "\n"
    if args.write_cert is not None:
        args.write_cert.write_text(rendered, encoding="utf-8")
    if args.json:
        sys.stdout.write(rendered)
    else:
        sys.stdout.write(
            f"reinforce-zero-tii-audit ({cert['anchors']['anchor_mode']}) "
            f"sha256={cert['canonical_sha256']}\n"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
