#!/usr/bin/env python3
"""
Wave 2 Round 6 — Arm R6-1 (`AUDIT-061`):
Non-Author Mathematical, R1-R5, and Exact Upgrade Suite for `Moissanite-Labs/warp-drive`
(`src/warp_modeld/certificate.py` on `main` + PR #1 `studies/expedition-bareiss-gram-cert/`).

Pure Python 3 stdlib, zero floats in emitted JSON/certificates, zero bare asserts,
R4-isolated (`-I -B`, `-I -O -B`, `-I -B -W error`, `-I -O -B -W error`) bit-identical.

Modules:
  1. Hardened Stage-2 FixedRadixCertificate & Stack Verifier (closes WARP-CERT-01..04):
     - Strict `\\A[0-9a-f]{64}\\Z` SHA-256 regex (rejects trailing newline `\\n`),
     - `gcd`-canonicalized rational scales in `canonical_stack_composition_digest`,
     - Exact division-free integer reverse-triangle cross-check on `composed_certificate`,
     - Single-adapter `joint_bounds` enforcement,
     - Optional verified Bareiss integer Gram PSD escape hatch lifting the N^2 CS tax.
  2. Exact Indefinite Moment-Cone Guarded Stieltjes-Hankel `R_H4` & `R_Q34` (closes PR1-B1..B2):
     - Proves `S1,S2,S3 > 0 & S1*S3 >= S2^2 & S2*S4 > S3^2 => c1 > 0 & c2 <= 0 => R_H4 <= n_+(H)`,
     - Safely falls back to `max(0, S1^2/S2 - b, S3^4/S4^3 - b)` when `S1*S3 < S2^2`
       (closing the indefinite rank-1 counterexample `H = diag(3, -2)` where PR #1 returned `2 > 1`),
     - Strictly exact `Fraction` output (zero silent `int -> float` coercion, zero JSON floats).
  3. Exact Pure-Integer Bareiss Inertia + Dual-Oracle Faddeev-LeVerrier + Constructive
     Integer Blind-Drift Witness Extractor (closes PR1-B3..B5, `SP-09` singular-`G_kk`):
     - Zero dead branches, strict input validation via `require(...)` (R5-visible),
     - Constructs primitive `dw in Z^d` with exact `J_k @ dw == 0` and strict integer
       `tau_den * ||J_o @ dw||_2^2 > tau_num * scale_div^2 * ||dw||_2^2` even when `G_kk` is singular.
  4. Multifrontal `SignedTree` Block-Schur Gram Certifier (`AUDIT-052`) + 8-Glyph Compression (`AUDIT-051`):
     - Supports `Leaf`, `BlockSum`, and generalized `SchurCouple` (with exact range check
       `col(B) <= col(A)`), verified 100% inertia-identical against flattened Bareiss & Faddeev-LeVerrier.
  5. Live Read-Only Clone Audit (auto-runs against `../repos/warp-drive` & `../repos/warp-drive-pr1`
     when present unless `--standalone` is given; NEVER writes to either clone).
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from fractions import Fraction
import hashlib
import hmac
import json
import math
from pathlib import Path
import re
import subprocess
import sys
from typing import Any, Mapping, Sequence

STRICT_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
LEGACY_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
WEFT_RADIX_EXP2_MIN = 8
WEFT_RADIX_EXP2_MAX = 48


class GramCertError(ValueError):
    """Explicit fail-closed error (never silenced under `python3 -O`)."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"[{code}] {message}")
        self.code = code
        self.message = message


def require(cond: bool, code: str, msg: str) -> None:
    if not cond:
        raise GramCertError(code, msg)


def is_exact_int(x: Any) -> bool:
    return type(x) is int


def require_exact_int(value: Any, name: str, *, allow_zero: bool = True) -> int:
    require(type(value) is int, "INVALID_INT", f"{name} must be exact int")
    if allow_zero:
        require(value >= 0, "NEGATIVE_INT", f"{name} must be >= 0")
    else:
        require(value > 0, "NONPOSITIVE_INT", f"{name} must be > 0")
    return value


def require_strict_sha256(value: Any, name: str) -> str:
    require(
        type(value) is str and bool(STRICT_SHA256_RE.match(value)),
        "INVALID_SHA256",
        f"{name} must be a 64-char lowercase hex digest without trailing newline",
    )
    return value


def require_exact_rational(value: Any, name: str) -> Fraction:
    if type(value) is int:
        return Fraction(value, 1)
    if isinstance(value, Fraction):
        return value
    raise GramCertError("INVALID_RATIONAL", f"{name} must be exact int or Fraction")


def require_rational_pair(pair: Any, name: str, *, allow_zero: bool = True) -> tuple[int, int]:
    require(
        isinstance(pair, (tuple, list)) and len(pair) == 2,
        "INVALID_RATIONAL_PAIR",
        f"{name} must be a 2-tuple (num, den)",
    )
    num, den = pair[0], pair[1]
    require_exact_int(num, f"{name}.num", allow_zero=allow_zero)
    require_exact_int(den, f"{name}.den", allow_zero=False)
    return (num, den)


def frac_dict(x: Fraction) -> dict[str, Any]:
    return {"num": x.numerator, "den": x.denominator, "exact": f"{x.numerator}/{x.denominator}"}


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


def canonical_sha256(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def ceil_fraction(x: Fraction) -> int:
    if x <= 0:
        return 0
    return (x.numerator + x.denominator - 1) // x.denominator


# ---------------------------------------------------------------------------
# 1. Exact Integer & Rational Matrix Primitives
# ---------------------------------------------------------------------------

def require_int_matrix(M: Any, name: str) -> list[list[int]]:
    require(isinstance(M, (list, tuple)) and len(M) > 0, "EMPTY_MATRIX", f"{name} must be non-empty")
    rows: list[list[int]] = []
    cols: int | None = None
    for r_i, row in enumerate(M):
        require(isinstance(row, (list, tuple)) and len(row) > 0, "EMPTY_ROW", f"{name}[{r_i}] empty")
        if cols is None:
            cols = len(row)
        else:
            require(len(row) == cols, "RAGGED_MATRIX", f"{name}[{r_i}] length mismatch")
        int_row: list[int] = []
        for c_i, v in enumerate(row):
            require(type(v) is int, "NON_INT_ENTRY", f"{name}[{r_i}][{c_i}] not exact int")
            int_row.append(v)
        rows.append(int_row)
    return rows


def require_symmetric_int_matrix(M: Any, name: str) -> list[list[int]]:
    A = require_int_matrix(M, name)
    n = len(A)
    require(len(A[0]) == n, "NON_SQUARE", f"{name} must be square")
    for i in range(n):
        for j in range(i + 1, n):
            require(A[i][j] == A[j][i], "ASYMMETRIC", f"{name}[{i}][{j}] != {name}[{j}][{i}]")
    return A


def mat_transpose_int(A: Sequence[Sequence[int]]) -> list[list[int]]:
    return [[A[r][c] for r in range(len(A))] for c in range(len(A[0]))]


def mat_mul_int(A: Sequence[Sequence[int]], B: Sequence[Sequence[int]]) -> list[list[int]]:
    m, k, p = len(A), len(A[0]), len(B[0])
    require(len(B) == k, "MATMUL_DIM_MISMATCH", f"inner dims {k} != {len(B)}")
    return [[sum(A[i][t] * B[t][j] for t in range(k)) for j in range(p)] for i in range(m)]


def mat_vec_int(A: Sequence[Sequence[int]], x: Sequence[int]) -> list[int]:
    require(len(A[0]) == len(x), "MATVEC_DIM_MISMATCH", "matrix/vector dimension mismatch")
    return [sum(row[j] * x[j] for j in range(len(x))) for row in A]


def quad_form_int(M: Sequence[Sequence[int]], x: Sequence[int]) -> int:
    n = len(M)
    require(len(x) == n, "QUAD_DIM_MISMATCH", "quad form dimension mismatch")
    total = 0
    for i in range(n):
        xi = x[i]
        if xi == 0:
            continue
        row = M[i]
        for j in range(n):
            total += xi * row[j] * x[j]
    return total


def vec_gcd(v: Sequence[int]) -> int:
    g = 0
    for x in v:
        g = math.gcd(g, abs(x))
    return g if g > 0 else 1


def _solve_spd_integer_scaled(A_lead: list[list[int]], rhs: list[int]) -> tuple[list[int], int]:
    """Solve A_lead * y = -det(A_lead) * rhs for SPD integer A_lead, returning (y_int, det_A)."""
    k = len(A_lead)
    if k == 0:
        return [], 1
    B = [row[:] for row in A_lead]
    prev = 1
    for p in range(k):
        piv = B[p][p]
        require(piv > 0, "NON_SPD_LEAD", f"leading block pivot {piv} <= 0")
        for i in range(p + 1, k):
            for j in range(p + 1, k):
                B[i][j] = (piv * B[i][j] - B[i][p] * B[p][j]) // prev
        prev = piv
    det_a = prev

    aug: list[list[Fraction]] = [
        [Fraction(A_lead[i][j], 1) for j in range(k)] + [Fraction(-rhs[i], 1)]
        for i in range(k)
    ]
    for col in range(k):
        piv_val = aug[col][col]
        for j in range(col, k + 1):
            aug[col][j] /= piv_val
        for r in range(k):
            if r == col:
                continue
            fac = aug[r][col]
            if fac != 0:
                for j in range(col, k + 1):
                    aug[r][j] -= fac * aug[col][j]
    y_int = [int(aug[i][k] * det_a) for i in range(k)]
    return y_int, det_a


def bareiss_symmetric_inertia_exact(M_int: Any) -> dict[str, Any]:
    """
    Exact pure-integer symmetric Bareiss (1x1 + 2x2 zero-diagonal) inertia & PSD certifier.
    Zero dead branches, zero floats, exact multiplication-only PSD certificate (when n_neg == 0)
    or primitive negative-energy witness x in Z^n with x^T M x < 0 (when n_neg > 0).
    """
    M0 = require_symmetric_int_matrix(M_int, "M_int")
    n = len(M0)
    A = [row[:] for row in M0]
    perm = list(range(n))
    prev_det = 1
    n_pos = 0
    n_neg = 0
    n_zero = 0
    max_pivot_bits = 1
    bareiss_cols: list[list[int]] = []
    bareiss_deltas: list[tuple[int, int]] = []
    psd_so_far = True
    rejection_witness: list[int] | None = None
    rejection_value: int | None = None

    k = 0
    while k < n:
        best_p: int | None = None
        best_abs: int | None = None
        for i in range(k, n):
            v = A[i][i]
            if v != 0:
                av = abs(v)
                if best_abs is None or av < best_abs:
                    best_abs = av
                    best_p = i

        if best_p is not None:
            if best_p != k:
                perm[k], perm[best_p] = perm[best_p], perm[k]
                A[k], A[best_p] = A[best_p], A[k]
                for r in range(n):
                    A[r][k], A[r][best_p] = A[r][best_p], A[r][k]
            piv = A[k][k]
            max_pivot_bits = max(max_pivot_bits, abs(piv).bit_length())
            if (piv > 0 and prev_det > 0) or (piv < 0 and prev_det < 0):
                n_pos += 1
                if psd_so_far:
                    col = [0] * k + [A[i][k] for i in range(k, n)]
                    bareiss_cols.append(col)
                    bareiss_deltas.append((prev_det, piv))
            else:
                n_neg += 1
                if psd_so_far:
                    A_lead = [[M0[perm[r]][perm[c]] for c in range(k)] for r in range(k)]
                    rhs = [M0[perm[r]][perm[k]] for r in range(k)]
                    y_int, det_lead = _solve_spd_integer_scaled(A_lead, rhs)
                    z = y_int + [det_lead] + [0] * (n - k - 1)
                    x = [0] * n
                    for idx_p, orig_i in enumerate(perm):
                        x[orig_i] = z[idx_p]
                    g = vec_gcd(x)
                    x = [v // g for v in x]
                    rejection_witness = x
                    rejection_value = quad_form_int(M0, x)
                    psd_so_far = False

            for i in range(k + 1, n):
                aik = A[i][k]
                for j in range(i, n):
                    val = (piv * A[i][j] - aik * A[j][k]) // prev_det
                    A[i][j] = val
                    A[j][i] = val
                    max_pivot_bits = max(max_pivot_bits, abs(val).bit_length())
            prev_det = piv
            k += 1
            continue

        # All remaining diagonal entries are 0: locate minimal nonzero off-diagonal (p1 < p2)
        off_piv: tuple[int, int] | None = None
        best_off_abs: int | None = None
        for i in range(k, n):
            for j in range(i + 1, n):
                v = A[i][j]
                if v != 0:
                    av = abs(v)
                    if best_off_abs is None or av < best_off_abs:
                        best_off_abs = av
                        off_piv = (i, j)

        if off_piv is None:
            n_zero += n - k
            break

        p1, p2 = off_piv
        # p2 > p1 >= k guarantees p2 != k (eliminates PR #1's unreachable dead branch at L295-296)
        if p1 != k:
            perm[k], perm[p1] = perm[p1], perm[k]
            A[k], A[p1] = A[p1], A[k]
            for r in range(n):
                A[r][k], A[r][p1] = A[r][p1], A[r][k]
        if p2 != k + 1:
            perm[k + 1], perm[p2] = perm[p2], perm[k + 1]
            A[k + 1], A[p2] = A[p2], A[k + 1]
            for r in range(n):
                A[r][k + 1], A[r][p2] = A[r][p2], A[r][k + 1]

        b = A[k][k + 1]
        max_pivot_bits = max(max_pivot_bits, abs(b).bit_length())
        n_pos += 1
        n_neg += 1

        if psd_so_far:
            e0, e1 = (1, -1) if b > 0 else (1, 1)
            A_lead = [[M0[perm[r]][perm[c]] for c in range(k)] for r in range(k)]
            rhs = [M0[perm[r]][perm[k]] * e0 + M0[perm[r]][perm[k + 1]] * e1 for r in range(k)]
            y_int, det_lead = _solve_spd_integer_scaled(A_lead, rhs)
            z = y_int + [det_lead * e0, det_lead * e1] + [0] * (n - k - 2)
            x = [0] * n
            for idx_p, orig_i in enumerate(perm):
                x[orig_i] = z[idx_p]
            g = vec_gcd(x)
            x = [v // g for v in x]
            rejection_witness = x
            rejection_value = quad_form_int(M0, x)
            psd_so_far = False

        new_det = (-b * b) // prev_det
        prev_sq = prev_det * prev_det
        for i in range(k + 2, n):
            aik, aik1 = A[i][k], A[i][k + 1]
            for j in range(i, n):
                val = (b * (aik * A[j][k + 1] + aik1 * A[j][k] - b * A[i][j])) // prev_sq
                A[i][j] = val
                A[j][i] = val
                max_pivot_bits = max(max_pivot_bits, abs(val).bit_length())
        prev_det = new_det
        max_pivot_bits = max(max_pivot_bits, abs(prev_det).bit_length())
        k += 2

    psd_cert: dict[str, Any] | None = None
    if n_neg == 0:
        reduced_cols: list[list[int]] = []
        fracs: list[Fraction] = []
        for col, (d_prev, d_curr) in zip(bareiss_cols, bareiss_deltas):
            g = vec_gcd(col)
            reduced_cols.append([v // g for v in col])
            fracs.append(Fraction(g * g, d_prev * d_curr))
        common_den = 1
        for f in fracs:
            common_den = math.lcm(common_den, f.denominator)
        weights = [int(f * common_den) for f in fracs]
        overall_g = math.gcd(common_den, vec_gcd(weights)) if weights else common_den
        common_den //= overall_g
        weights = [w // overall_g for w in weights]
        psd_cert = {
            "perm": perm,
            "common_den": common_den,
            "weights": weights,
            "cols": reduced_cols,
        }

    return {
        "dim": n,
        "inertia": (n_pos, n_neg, n_zero),
        "is_psd": (n_neg == 0),
        "max_pivot_bits": max_pivot_bits,
        "psd_certificate": psd_cert,
        "rejection_witness": rejection_witness,
        "rejection_value": rejection_value,
    }


def verify_integer_psd_certificate_exact(M_int: Any, cert: Any) -> bool:
    """Zero-division multiplication-only verifier for Bareiss PSD certificates (strictly typed)."""
    M = require_symmetric_int_matrix(M_int, "M_int")
    require(isinstance(cert, Mapping), "INVALID_CERT_TYPE", "cert must be a mapping")
    n = len(M)
    perm = cert.get("perm")
    common_den = cert.get("common_den")
    weights = cert.get("weights")
    cols = cert.get("cols")

    require(
        isinstance(perm, list) and len(perm) == n and all(type(p) is int for p in perm) and sorted(perm) == list(range(n)),
        "BAD_PERM",
        "perm must be a permutation of 0..n-1",
    )
    require_exact_int(common_den, "common_den", allow_zero=False)
    require(
        isinstance(weights, list) and isinstance(cols, list) and len(weights) == len(cols),
        "BAD_WEIGHTS_COLS",
        "weights/cols shape mismatch",
    )
    for w_i, w in enumerate(weights):
        require_exact_int(w, f"weights[{w_i}]", allow_zero=False)
    for c_i, col in enumerate(cols):
        require(
            isinstance(col, list) and len(col) == n and all(type(v) is int for v in col),
            "BAD_COL",
            f"cols[{c_i}] must be length-{n} int vector",
        )

    for i in range(n):
        pi = perm[i]
        for j in range(i, n):
            pj = perm[j]
            lhs = common_den * M[pi][pj]
            rhs = sum(weights[r] * cols[r][i] * cols[r][j] for r in range(len(weights)))
            require(lhs == rhs, "CERT_MISMATCH", f"mismatch at ({i},{j})")
    return True


def _sign_changes(coeffs: Sequence[Fraction]) -> int:
    nz = [c for c in coeffs if c != 0]
    changes = 0
    for i in range(len(nz) - 1):
        if (nz[i] > 0) != (nz[i + 1] > 0):
            changes += 1
    return changes


def faddeev_leverrier_inertia_exact(M_int: Any) -> tuple[int, int, int]:
    """Independent zero-shared-code dual oracle (`⦺`): exact Q characteristic polynomial + Descartes."""
    M = require_symmetric_int_matrix(M_int, "M_int")
    n = len(M)
    Mf = [[Fraction(v, 1) for v in row] for row in M]
    coeffs: list[Fraction] = [Fraction(1, 1)]
    B = [[Fraction(1 if i == j else 0, 1) for j in range(n)] for i in range(n)]
    for k in range(1, n + 1):
        Mk = [row[:] for row in Mf] if k == 1 else [
            [sum(Mf[i][t] * B[t][j] for t in range(n)) for j in range(n)] for i in range(n)
        ]
        ck = -sum(Mk[i][i] for i in range(n)) / Fraction(k, 1)
        coeffs.append(ck)
        if k < n:
            B = [[Mk[i][j] + (ck if i == j else Fraction(0, 1)) for j in range(n)] for i in range(n)]
    n_zero = 0
    while len(coeffs) > 1 and coeffs[-1] == 0:
        coeffs.pop()
        n_zero += 1
    n_pos = _sign_changes(coeffs)
    deg = len(coeffs) - 1
    neg_coeffs = [c * (Fraction(-1, 1) ** (deg - i)) for i, c in enumerate(coeffs)]
    n_neg = _sign_changes(neg_coeffs)
    return (n_pos, n_neg, n_zero)


def solve_consistent_linear_rational(
    A_int: Sequence[Sequence[int]], B_int: Sequence[Sequence[int]]
) -> tuple[bool, list[list[Fraction]]]:
    """
    Exact rational RREF solver for A * X = B (handles singular / rank-deficient A).
    Returns (True, X) iff col(B) <= col(A), else (False, []).
    """
    m = len(A_int)
    p = len(A_int[0])
    q = len(B_int[0])
    aug: list[list[Fraction]] = [
        [Fraction(A_int[r][c], 1) for c in range(p)] + [Fraction(B_int[r][c], 1) for c in range(q)]
        for r in range(m)
    ]
    piv_cols: list[int] = []
    row_i = 0
    for col in range(p):
        piv_r = None
        for r in range(row_i, m):
            if aug[r][col] != 0:
                piv_r = r
                break
        if piv_r is None:
            continue
        aug[row_i], aug[piv_r] = aug[piv_r], aug[row_i]
        piv_v = aug[row_i][col]
        for j in range(col, p + q):
            aug[row_i][j] /= piv_v
        for r in range(m):
            if r == row_i:
                continue
            fac = aug[r][col]
            if fac != 0:
                for j in range(col, p + q):
                    aug[r][j] -= fac * aug[row_i][j]
        piv_cols.append(col)
        row_i += 1
        if row_i == m:
            break

    # Check consistency in zero rows of RREF(A)
    for r in range(row_i, m):
        for c in range(p, p + q):
            if aug[r][c] != 0:
                return False, []

    X = [[Fraction(0, 1) for _ in range(q)] for _ in range(p)]
    for r_idx, col_idx in enumerate(piv_cols):
        for c in range(q):
            X[col_idx][c] = aug[r_idx][p + c]
    return True, X


def extract_row_basis_indices(J_int: Sequence[Sequence[int]]) -> list[int]:
    """Return indices of a maximal linearly independent subset of rows of J_int over Q."""
    m = len(J_int)
    d = len(J_int[0])
    basis_rows: list[list[Fraction]] = []
    basis_pivs: list[int] = []
    basis_indices: list[int] = []
    for r_idx in range(m):
        vec = [Fraction(v, 1) for v in J_int[r_idx]]
        for brow, pcol in zip(basis_rows, basis_pivs):
            fac = vec[pcol]
            if fac != 0:
                for j in range(pcol, d):
                    vec[j] -= fac * brow[j]
        first_nz = None
        for j in range(d):
            if vec[j] != 0:
                first_nz = j
                break
        if first_nz is not None:
            pv = vec[first_nz]
            vec = [v / pv for v in vec]
            basis_rows.append(vec)
            basis_pivs.append(first_nz)
            basis_indices.append(r_idx)
    return basis_indices


# ---------------------------------------------------------------------------
# 2. Hardened Stage-2 FixedRadixCertificate & Stack Verifier (WARP-CERT-01..04)
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HardenedRationalBound:
    num: int
    den: int = 1

    def __post_init__(self) -> None:
        require_exact_int(self.num, "bound.num", allow_zero=True)
        require_exact_int(self.den, "bound.den", allow_zero=False)


@dataclass(frozen=True)
class HardenedCertificateBounds:
    max_frobenius_sq: HardenedRationalBound
    max_spectral_norm_sq: HardenedRationalBound
    max_leakage_energy: HardenedRationalBound
    max_safety_dot_sq: HardenedRationalBound

    def __post_init__(self) -> None:
        require(isinstance(self.max_frobenius_sq, HardenedRationalBound), "BAD_BOUNDS", "max_frobenius_sq type")
        require(isinstance(self.max_spectral_norm_sq, HardenedRationalBound), "BAD_BOUNDS", "max_spectral_norm_sq type")
        require(isinstance(self.max_leakage_energy, HardenedRationalBound), "BAD_BOUNDS", "max_leakage_energy type")
        require(isinstance(self.max_safety_dot_sq, HardenedRationalBound), "BAD_BOUNDS", "max_safety_dot_sq type")


@dataclass(frozen=True)
class HardenedFixedRadixCertificate:
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
        require(type(self.adapter_id) is str and bool(self.adapter_id.strip()), "INVALID_ADAPTER_ID", "adapter_id empty")
        require_strict_sha256(self.adapter_sha256, "adapter_sha256")
        require_strict_sha256(self.base_weights_sha256, "base_weights_sha256")
        require_exact_int(self.radix_scale, "radix_scale", allow_zero=False)
        require_exact_int(self.frobenius_sq_scaled, "frobenius_sq_scaled", allow_zero=True)
        require_exact_int(self.spectral_norm_sq_scaled, "spectral_norm_sq_scaled", allow_zero=True)
        require_exact_int(self.leakage_energy_scaled, "leakage_energy_scaled", allow_zero=True)
        require_exact_int(self.max_safety_dot_sq_scaled, "max_safety_dot_sq_scaled", allow_zero=True)
        require_strict_sha256(self.cert_sha256, "cert_sha256")

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
        return canonical_sha256(self.body_dict())

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
    ) -> HardenedFixedRadixCertificate:
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
        return cls(cert_sha256=canonical_sha256(body), **body)


def canonical_stack_composition_digest(entries: Sequence[tuple[str, str, int, int]]) -> str:
    """
    Hardened canonical stack digest (closes WARP-CERT-02):
    - Strictly validates adapter_id, strict SHA-256 (`\\Z`), and positive exact-int scales,
    - Rejects duplicate adapter_id,
    - Reduces `(scale_num, scale_den)` by `math.gcd` so `(1, 1)` and `(1000, 1000)` share ONE digest.
    """
    require(isinstance(entries, Sequence) and len(entries) > 0, "EMPTY_STACK", "entries must be non-empty")
    seen_ids: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        require(isinstance(entry, (tuple, list)) and len(entry) == 4, "BAD_STACK_ENTRY", "entry must be 4-tuple")
        aid, asha, snum, sden = entry
        require(type(aid) is str and bool(aid.strip()), "INVALID_ADAPTER_ID", "adapter_id must be non-empty str")
        require(aid not in seen_ids, "DUPLICATE_ADAPTER_ID", f"duplicate adapter_id: {aid}")
        seen_ids.add(aid)
        require_strict_sha256(asha, "adapter_sha256")
        require_exact_int(snum, "scale_num", allow_zero=False)
        require_exact_int(sden, "scale_den", allow_zero=False)
        g = math.gcd(snum, sden)
        normalized.append({
            "adapter_id": aid,
            "adapter_sha256": asha,
            "scale_num": snum // g,
            "scale_den": sden // g,
        })
    normalized.sort(key=lambda item: (item["adapter_id"], item["adapter_sha256"]))
    return canonical_sha256({"stack": normalized})


def _check_scaled_cross_mul_le(
    value_scaled: int,
    radix_scale: int,
    bound: HardenedRationalBound,
    metric: str,
    *,
    scale_num: int = 1,
    scale_den: int = 1,
) -> None:
    lhs = value_scaled * (scale_num * scale_num) * bound.den
    rhs = bound.num * radix_scale * (scale_den * scale_den)
    require(lhs <= rhs, "BOUND_EXCEEDED", f"{metric} exceeds policy bound")


def verify_certificate_hardened(
    cert: Any,
    bounds: Any,
    *,
    scale_num: int = 1,
    scale_den: int = 1,
    expected_adapter_id: str | None = None,
    expected_adapter_sha256: str | None = None,
    expected_base_weights_sha256: str | None = None,
) -> dict[str, Any]:
    """Hardened single-adapter verifier closing WARP-CERT-01 and WARP-CERT-04."""
    require(isinstance(cert, HardenedFixedRadixCertificate), "INVALID_CERT", "cert must be HardenedFixedRadixCertificate")
    require(isinstance(bounds, HardenedCertificateBounds), "INVALID_BOUNDS", "bounds must be HardenedCertificateBounds")
    require_exact_int(scale_num, "scale_num", allow_zero=False)
    require_exact_int(scale_den, "scale_den", allow_zero=False)
    require(hmac.compare_digest(cert.cert_sha256, cert.expected_cert_sha256()), "FORGED_DIGEST", "cert_sha256 mismatch")

    if expected_adapter_id is not None:
        require(type(expected_adapter_id) is str and cert.adapter_id == expected_adapter_id, "ADAPTER_ID_MISMATCH", "adapter_id mismatch")
    if expected_adapter_sha256 is not None:
        require_strict_sha256(expected_adapter_sha256, "expected_adapter_sha256")
        require(hmac.compare_digest(cert.adapter_sha256, expected_adapter_sha256), "ADAPTER_SHA_MISMATCH", "adapter_sha256 mismatch")
    if expected_base_weights_sha256 is not None:
        require_strict_sha256(expected_base_weights_sha256, "expected_base_weights_sha256")
        require(hmac.compare_digest(cert.base_weights_sha256, expected_base_weights_sha256), "BASE_SHA_MISMATCH", "base_weights_sha256 mismatch")

    require(cert.spectral_norm_sq_scaled <= cert.frobenius_sq_scaled, "SPEC_GT_FROB", "spectral_norm_sq > frobenius_sq")

    _check_scaled_cross_mul_le(cert.frobenius_sq_scaled, cert.radix_scale, bounds.max_frobenius_sq, "frobenius_sq", scale_num=scale_num, scale_den=scale_den)
    _check_scaled_cross_mul_le(cert.spectral_norm_sq_scaled, cert.radix_scale, bounds.max_spectral_norm_sq, "spectral_norm_sq", scale_num=scale_num, scale_den=scale_den)
    _check_scaled_cross_mul_le(cert.leakage_energy_scaled, cert.radix_scale, bounds.max_leakage_energy, "leakage_energy", scale_num=scale_num, scale_den=scale_den)
    _check_scaled_cross_mul_le(cert.max_safety_dot_sq_scaled, cert.radix_scale, bounds.max_safety_dot_sq, "max_safety_dot_sq", scale_num=scale_num, scale_den=scale_den)
    return {"adapter_id": cert.adapter_id, "cert_sha256": cert.cert_sha256, "passed": True}


def check_composed_norm_triangle_exact(
    component_sq: Sequence[Fraction], composed_sq: Fraction, metric_name: str
) -> None:
    """
    Exact root-free, division-free rational norm consistency check (closes WARP-CERT-03A):
    For norms ||x_1||^2 = a_1, ..., ||x_N||^2 = a_N and ||sum x_i||^2 = c:
      1. Upper Cauchy-Schwarz: c <= N * sum_i a_i
      2. Singleton exact equality (N == 1): c == a_1 (blocks understated forged singleton norms)
      3. Exact 2-term reverse+forward triangle: (a_1 + a_2 - c)^2 <= 4 * a_1 * a_2
      4. General N-term dominant reverse triangle: for every k with a_k > B_k = (N-1)*sum_{j!=k} a_j,
         either c >= a_k + B_k or (a_k + B_k - c)^2 <= 4 * a_k * B_k.
    """
    n = len(component_sq)
    total = sum(component_sq, Fraction(0, 1))
    require(composed_sq <= n * total, "COMPOSED_EXCEEDS_CS", f"{metric_name} composed_sq exceeds N * sum a_i")
    if n == 1:
        require(
            composed_sq == component_sq[0],
            "COMPOSED_SINGLETON_MISMATCH",
            f"{metric_name} singleton composed_sq must equal component_sq[0]",
        )
        return
    if n == 2:
        a1, a2 = component_sq[0], component_sq[1]
        diff = a1 + a2 - composed_sq
        require(diff * diff <= 4 * a1 * a2, "COMPOSED_TRIANGLE_VIOLATION", f"{metric_name} violates 2-term triangle inequality")
        return
    if n > 2:
        for k in range(n):
            ak = component_sq[k]
            bk = (n - 1) * (total - ak)
            if ak > bk and composed_sq < ak + bk:
                gap = ak + bk - composed_sq
                require(gap * gap <= 4 * ak * bk, "COMPOSED_REVERSE_TRIANGLE_VIOLATION", f"{metric_name} violates N-term reverse triangle")


def certify_stacked_mde_gram_exact(
    adapters: Sequence[Mapping[str, Any]],
    *,
    max_frobenius_sq: tuple[int, int],
    max_spectral_norm_sq: tuple[int, int],
) -> dict[str, Any]:
    """
    Exact pure-integer stacked Gram certifier (hardened version of PR #1 Theorem 2):
    Certifies ||sum_i (1/D_i) B_i A_i||_F^2 <= max_frobenius_sq and ||sum_i (1/D_i) B_i A_i||_2^2 <= max_spectral_norm_sq
    via exact integer Bareiss PSD certificate on Q_stack = s_num * D^4 * G_B - s_den * G_B G_A G_B.
    """
    require(isinstance(adapters, (list, tuple)) and len(adapters) > 0, "EMPTY_ADAPTERS", "adapters must be non-empty")
    f_num, f_den = require_rational_pair(max_frobenius_sq, "max_frobenius_sq", allow_zero=True)
    s_num, s_den = require_rational_pair(max_spectral_norm_sq, "max_spectral_norm_sq", allow_zero=True)

    parsed: list[tuple[str, list[list[int]], list[list[int]], int]] = []
    seen_ids: set[str] = set()
    d_out: int | None = None
    d_in: int | None = None
    common_d = 1

    for idx, entry in enumerate(adapters):
        require(isinstance(entry, Mapping), "BAD_ADAPTER_ENTRY", f"adapters[{idx}] must be a mapping")
        aid = entry.get("adapter_id")
        require(type(aid) is str and bool(aid.strip()) and aid not in seen_ids, "BAD_ADAPTER_ID", f"invalid/duplicate adapter_id at {idx}")
        seen_ids.add(aid)
        B = require_int_matrix(entry.get("B_int"), f"{aid}.B_int")
        A = require_int_matrix(entry.get("A_int"), f"{aid}.A_int")
        scale_div = require_exact_int(entry.get("scale_div", 1), f"{aid}.scale_div", allow_zero=False)
        require(len(B[0]) == len(A), "FACTOR_RANK_MISMATCH", f"{aid}: B cols != A rows")
        if d_out is None:
            d_out, d_in = len(B), len(A[0])
        else:
            require(len(B) == d_out and len(A[0]) == d_in, "ADAPTER_SHAPE_MISMATCH", f"{aid} shape mismatch")
        common_d = math.lcm(common_d, scale_div)
        parsed.append((aid, B, A, scale_div))

    # Build stacked B_stack (d_out x R) and A_stack (R x d_in) with exact integer scaling to 1/common_d^2
    B_cols: list[list[int]] = []
    A_rows: list[list[int]] = []
    block_slices: list[list[Any]] = []
    for aid, B, A, sdiv in parsed:
        mult = common_d // sdiv
        r_i = len(B[0])
        s0 = len(B_cols)
        for c in range(r_i):
            B_cols.append([B[row][c] * mult for row in range(len(B))])
        for row in A:
            A_rows.append([v * mult for v in row])
        block_slices.append([aid, s0, len(B_cols)])

    R = len(B_cols)
    B_stack = [[B_cols[c][r] for c in range(R)] for r in range(len(B_cols[0]))]
    G_B = mat_mul_int(mat_transpose_int(B_stack), B_stack)
    G_A = mat_mul_int(A_rows, mat_transpose_int(A_rows))
    G_BA = mat_mul_int(G_B, G_A)
    frob_num_int = sum(G_BA[i][i] for i in range(R))
    d4 = common_d ** 4
    frob_exact = Fraction(frob_num_int, d4)
    frob_ok = frob_num_int * f_den <= f_num * d4

    G_BAB = mat_mul_int(G_BA, G_B)
    Q_stack = [
        [s_num * d4 * G_B[i][j] - s_den * G_BAB[i][j] for j in range(R)]
        for i in range(R)
    ]
    b_res = bareiss_symmetric_inertia_exact(Q_stack)
    spec_ok = b_res["is_psd"]
    cert_verified = False
    if spec_ok:
        cert_verified = verify_integer_psd_certificate_exact(Q_stack, b_res["psd_certificate"])

    return {
        "n_adapters": len(parsed),
        "adapter_ids": sorted(seen_ids),
        "adapter_block_slices": block_slices,
        "total_rank_R": R,
        "common_scale_div": common_d,
        "max_frobenius_sq": frac_dict(Fraction(f_num, f_den)),
        "max_spectral_norm_sq": frac_dict(Fraction(s_num, s_den)),
        "exact_frobenius_sq": frac_dict(frob_exact),
        "frobenius_certified": frob_ok,
        "spectral_certified": spec_ok,
        "psd_cert_verified": cert_verified,
        "G_B_int": G_B,
        "G_A_int": G_A,
        "Q_stack_inertia": list(b_res["inertia"]),
        "Q_stack_int": Q_stack,
        "psd_certificate": b_res["psd_certificate"],
        "rejection_witness": b_res["rejection_witness"],
        "rejection_value": b_res["rejection_value"],
    }


def verify_stack_hardened(
    items: Sequence[tuple[HardenedFixedRadixCertificate, str, str, int, int]],
    single_bounds: Any,
    joint_bounds: Any,
    *,
    expected_base_weights_sha256: str,
    composed_certificate: HardenedFixedRadixCertificate | None = None,
    verified_gram_report: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Hardened multi-adapter Stage-2 verifier (closes WARP-CERT-02, WARP-CERT-03A/B/C,
    and AUDIT-061R GRAM-ESC-BYPASS-1 & GRAM-ESC-BYPASS-2):
      1. Enforces `joint_bounds` even when `len(items) == 1` (`WARP-CERT-03C`).
      2. Enforces exact root-free reverse-triangle cross-consistency on `composed_certificate` (`WARP-CERT-03A`).
      3. Supports cryptographically & policy-bound Bareiss Gram escape hatch (`verified_gram_report`)
         for `frobenius_sq` & `spectral_norm_sq` ONLY — binding adapter IDs, PSD Gram factors `(G_B, G_A)`,
         per-adapter diagonal Frobenius blocks, exact recomputed `tr(G_B G_A) <= joint_bounds.max_frobenius_sq`,
         and recomputed `Q_stack(s_cap) >= 0` with `s_cap <= joint_bounds.max_spectral_norm_sq` — while
         ALWAYS enforcing `joint_bounds.max_leakage_energy` and `joint_bounds.max_safety_dot_sq`.
    """
    require(isinstance(items, Sequence) and len(items) > 0, "EMPTY_STACK", "adapter stack must be non-empty")
    require(isinstance(single_bounds, HardenedCertificateBounds), "INVALID_SINGLE_BOUNDS", "single_bounds invalid")
    require(isinstance(joint_bounds, HardenedCertificateBounds), "INVALID_JOINT_BOUNDS", "joint_bounds invalid")
    require_strict_sha256(expected_base_weights_sha256, "expected_base_weights_sha256")

    seen_ids: set[str] = set()
    stack_keys: list[tuple[str, str, int, int]] = []
    scaled_frobs: list[Fraction] = []
    scaled_specs: list[Fraction] = []
    frob_by_id: dict[str, Fraction] = {}
    denominators: list[int] = []

    for cert, aid, asha, snum, sden in items:
        require(aid not in seen_ids, "DUPLICATE_ADAPTER_ID", f"duplicate adapter_id: {aid}")
        seen_ids.add(aid)
        verify_certificate_hardened(
            cert,
            single_bounds,
            scale_num=snum,
            scale_den=sden,
            expected_adapter_id=aid,
            expected_adapter_sha256=asha,
            expected_base_weights_sha256=expected_base_weights_sha256,
        )
        denominators.append(cert.radix_scale * (sden * sden))
        stack_keys.append((aid, asha, snum, sden))
        f_scaled = Fraction(cert.frobenius_sq_scaled * snum * snum, cert.radix_scale * sden * sden)
        scaled_frobs.append(f_scaled)
        frob_by_id[aid] = f_scaled
        scaled_specs.append(Fraction(cert.spectral_norm_sq_scaled * snum * snum, cert.radix_scale * sden * sden))

    # Single-adapter stack STILL must satisfy joint_bounds (closes WARP-CERT-03C)
    if len(items) == 1:
        cert0, aid0, asha0, snum0, sden0 = items[0]
        verify_certificate_hardened(
            cert0,
            joint_bounds,
            scale_num=snum0,
            scale_den=sden0,
            expected_adapter_id=aid0,
            expected_adapter_sha256=asha0,
            expected_base_weights_sha256=expected_base_weights_sha256,
        )

    gram_escape_used = False
    if verified_gram_report is not None:
        require(isinstance(verified_gram_report, Mapping), "INVALID_GRAM_REPORT", "gram report must be mapping")
        rep_ids = verified_gram_report.get("adapter_ids")
        require(
            isinstance(rep_ids, list) and len(rep_ids) == len(items) and sorted(rep_ids) == sorted(seen_ids),
            "GRAM_ADAPTER_MISMATCH",
            "gram report adapter_ids do not match mounted stack",
        )
        G_B = require_symmetric_int_matrix(verified_gram_report.get("G_B_int"), "gram.G_B_int")
        G_A = require_symmetric_int_matrix(verified_gram_report.get("G_A_int"), "gram.G_A_int")
        R = len(G_B)
        require(len(G_A) == R, "GRAM_DIM_MISMATCH", "gram G_B_int and G_A_int dimension mismatch")
        require(
            bareiss_symmetric_inertia_exact(G_B)["is_psd"] and bareiss_symmetric_inertia_exact(G_A)["is_psd"],
            "GRAM_FACTOR_NOT_PSD",
            "gram G_B_int and G_A_int must both be PSD",
        )
        common_d = require_exact_int(verified_gram_report.get("common_scale_div"), "gram.common_scale_div", allow_zero=False)
        d4 = common_d ** 4

        # Bind every adapter's diagonal block Frobenius norm to its certified scaled Frobenius norm
        slices = verified_gram_report.get("adapter_block_slices")
        require(isinstance(slices, list) and len(slices) == len(items), "GRAM_SLICES_INVALID", "bad adapter_block_slices")
        cursor = 0
        slice_seen: set[str] = set()
        for sl in slices:
            require(
                isinstance(sl, (list, tuple)) and len(sl) == 3
                and type(sl[0]) is str and sl[0] in frob_by_id and sl[0] not in slice_seen
                and type(sl[1]) is int and type(sl[2]) is int and sl[1] == cursor and sl[2] > sl[1] and sl[2] <= R,
                "GRAM_SLICE_ENTRY_INVALID",
                "malformed or non-contiguous adapter_block_slices entry",
            )
            sl_aid, s0, s1 = sl[0], sl[1], sl[2]
            slice_seen.add(sl_aid)
            cursor = s1
            block_trace = sum(G_B[i][j] * G_A[j][i] for i in range(s0, s1) for j in range(s0, s1))
            require(
                Fraction(block_trace, d4) == frob_by_id[sl_aid],
                "GRAM_ADAPTER_FROB_MISMATCH",
                f"gram block Frobenius for {sl_aid} does not match adapter certificate",
            )
        require(cursor == R, "GRAM_SLICES_INCOMPLETE", "adapter_block_slices do not cover full rank R")

        # Independently recompute stacked Frobenius & spectral bounds against joint_bounds
        G_BA = mat_mul_int(G_B, G_A)
        frob_num_int = sum(G_BA[i][i] for i in range(R))
        require(
            frob_num_int * joint_bounds.max_frobenius_sq.den <= joint_bounds.max_frobenius_sq.num * d4,
            "GRAM_FROB_EXCEEDS_JOINT",
            "recomputed Gram Frobenius exceeds joint_bounds.max_frobenius_sq",
        )
        s_cap = verified_gram_report.get("max_spectral_norm_sq")
        require(isinstance(s_cap, Mapping), "GRAM_SPEC_CAP_INVALID", "max_spectral_norm_sq must be mapping")
        s_num, s_den = require_rational_pair((s_cap.get("num"), s_cap.get("den")), "gram.max_spectral_norm_sq", allow_zero=True)
        require(
            s_num * joint_bounds.max_spectral_norm_sq.den <= joint_bounds.max_spectral_norm_sq.num * s_den,
            "GRAM_SPEC_CAP_EXCEEDS_JOINT",
            "gram report max_spectral_norm_sq exceeds joint_bounds.max_spectral_norm_sq",
        )
        G_BAB = mat_mul_int(G_BA, G_B)
        expected_Q = [
            [s_num * d4 * G_B[i][j] - s_den * G_BAB[i][j] for j in range(R)]
            for i in range(R)
        ]
        verify_integer_psd_certificate_exact(expected_Q, verified_gram_report.get("psd_certificate"))
        gram_escape_used = True

    composed_bound_checked = False
    if len(items) > 1:
        n_adapters = len(items)
        common_den = math.lcm(*denominators)
        metric_specs: list[tuple[str, HardenedRationalBound, str]] = [
            ("leakage_energy_scaled", joint_bounds.max_leakage_energy, "composed_leakage_energy"),
            ("max_safety_dot_sq_scaled", joint_bounds.max_safety_dot_sq, "composed_max_safety_dot_sq"),
        ]
        if not gram_escape_used:
            metric_specs = [
                ("frobenius_sq_scaled", joint_bounds.max_frobenius_sq, "composed_frobenius_sq"),
                ("spectral_norm_sq_scaled", joint_bounds.max_spectral_norm_sq, "composed_spectral_norm_sq"),
            ] + metric_specs
        for attr, bound, metric_name in metric_specs:
            total_scaled = 0
            for (cert, _aid, _asha, snum, _sden), term_den in zip(items, denominators):
                total_scaled += getattr(cert, attr) * (snum * snum) * (common_den // term_den)
            _check_scaled_cross_mul_le(n_adapters * total_scaled, common_den, bound, metric_name)
        composed_bound_checked = True

    composed_cert_verified = False
    if composed_certificate is not None:
        expected_stack_sha = canonical_stack_composition_digest(stack_keys)
        verify_certificate_hardened(
            composed_certificate,
            joint_bounds,
            expected_adapter_id="composed_stack",
            expected_adapter_sha256=expected_stack_sha,
            expected_base_weights_sha256=expected_base_weights_sha256,
        )
        comp_frob = Fraction(composed_certificate.frobenius_sq_scaled, composed_certificate.radix_scale)
        comp_spec = Fraction(composed_certificate.spectral_norm_sq_scaled, composed_certificate.radix_scale)
        check_composed_norm_triangle_exact(scaled_frobs, comp_frob, "composed_frobenius_sq")
        check_composed_norm_triangle_exact(scaled_specs, comp_spec, "composed_spectral_norm_sq")
        composed_cert_verified = True

    return {
        "n_adapters": len(items),
        "joint_bounds_checked": True,
        "composed_bound_checked": composed_bound_checked,
        "gram_escape_used": gram_escape_used,
        "composed_cert_verified": composed_cert_verified,
        "passed": True,
    }


# ---------------------------------------------------------------------------
# 3. Exact Moment-Cone Sound R_opt, R_H4, R_Q34 (closes PR1-B1 & PR1-B2)
# ---------------------------------------------------------------------------

def r_opt_exact_strict(u: Any, t: Any, S: Any, b: Any) -> Fraction:
    """Strict zero-float exact rational R_opt(u, t, S, b) (rejects bool/float, never drops to float)."""
    uf = require_exact_rational(u, "u")
    tf = require_exact_rational(t, "t")
    Sf = require_exact_rational(S, "S")
    require_exact_int(b, "b", allow_zero=True)
    if uf <= 0 or (uf + tf) <= 0 or Sf <= 0:
        return Fraction(0, 1)
    if b > 0 and tf > 0 and tf * (uf + tf) >= Fraction(b, 1) * Sf:
        denom = Sf - (tf * tf) / Fraction(b, 1)
        return (uf * uf) / denom if denom > 0 else Fraction(0, 1)
    val = ((uf + tf) * (uf + tf)) / Sf - Fraction(b, 1)
    return val if val > 0 else Fraction(0, 1)


def r_h4_stieltjes_sound(S1: Any, S2: Any, S3: Any, S4: Any, b: Any) -> dict[str, Any]:
    """
    Sound exact rational 4th-moment lower bound on `rank(P)` for ANY (possibly indefinite!)
    Hermitian matrix H = P + Q with P >= 0 and n_+(Q) <= b (closes PR1-B1 & PR1-B2).

    Theorem (Exact KKT Moment-Cone Guard):
      When S1 > 0, S2 > 0, S3 > 0, S1*S3 >= S2^2, and D = S2*S4 - S3^2 > 0:
        c1 = (S1*S4 - S2*S3) / D > 0  and  c2 = (S2^2 - S1*S3) / D <= 0,
      so f(x) = 1 - (1 - c1*x - c2*x^2)^2 satisfies f(x) <= 1 for all x in R and f(x) <= 0
      for all x <= 0! Summing over all eigenvalues of H yields:
        R_H4 = S1^2/S2 + (S1*S3 - S2^2)^2 / (S2*D) - b <= n_+(H) - b <= rank(P).
      When S1*S3 < S2^2 (indefinite defect), `c2 > 0` invalidates `f(x) <= 0` on `x < 0`;
      the function refuses the unconstrained Schur boost and returns the unconditionally sound
      indefinite lower bound `max(0, S1^2/S2 - b, S3^4/S4^3 - b)`.
    """
    s1 = require_exact_rational(S1, "S1")
    s2 = require_exact_rational(S2, "S2")
    s3 = require_exact_rational(S3, "S3")
    s4 = require_exact_rational(S4, "S4")
    require_exact_int(b, "b", allow_zero=True)

    r_cs2 = max(Fraction(0, 1), (s1 * s1) / s2 - Fraction(b, 1)) if (s1 > 0 and s2 > 0) else Fraction(0, 1)
    r_q34 = max(Fraction(0, 1), (s3 ** 4) / (s4 ** 3) - Fraction(b, 1)) if (s3 > 0 and s4 > 0) else Fraction(0, 1)

    denom = s2 * s4 - s3 * s3
    cone_valid = (s1 > 0) and (s2 > 0) and (s3 > 0) and (s1 * s3 >= s2 * s2) and (denom > 0)
    if cone_valid:
        c1 = (s1 * s4 - s2 * s3) / denom
        c2 = (s2 * s2 - s1 * s3) / denom
        raw_h4 = (s1 * s1) / s2 + ((s1 * s3 - s2 * s2) ** 2) / (s2 * denom) - Fraction(b, 1)
        r_h4 = max(Fraction(0, 1), raw_h4)
        best = max(r_h4, r_q34)
        return {
            "moment_cone_valid": True,
            "kkt_c1": frac_dict(c1),
            "kkt_c2": frac_dict(c2),
            "R_cs2": frac_dict(r_cs2),
            "R_q34": frac_dict(r_q34),
            "R_h4_sound": frac_dict(r_h4),
            "best_lower_bound": frac_dict(best),
            "certified_min_rank": ceil_fraction(best),
        }

    best = max(r_cs2, r_q34)
    return {
        "moment_cone_valid": False,
        "kkt_c1": None,
        "kkt_c2": None,
        "R_cs2": frac_dict(r_cs2),
        "R_q34": frac_dict(r_q34),
        "R_h4_sound": frac_dict(r_cs2),
        "best_lower_bound": frac_dict(best),
        "certified_min_rank": ceil_fraction(best),
    }


# ---------------------------------------------------------------------------
# 4. Constructive Integer Blind-Drift Witness Extractor (`SP-09` Upgrade)
# ---------------------------------------------------------------------------

def verify_blind_drift_witness_exact(
    J_known_int: Any,
    J_out_int: Any,
    dw_int: Any,
    *,
    tau: tuple[int, int],
    scale_div: int = 1,
) -> dict[str, Any]:
    """
    Independent 2-line pure-integer verifier for a blind-drift breach witness `dw in Z^d`:
      1. `dw != 0` and `J_known @ dw == 0` identically in Z^{m_k},
      2. `tau_den * ||J_out @ dw||_2^2 > tau_num * scale_div^2 * ||dw||_2^2` strictly in Z.
    """
    Jk = require_int_matrix(J_known_int, "J_known_int")
    Jo = require_int_matrix(J_out_int, "J_out_int")
    require(len(Jk[0]) == len(Jo[0]), "JACOBIAN_COL_MISMATCH", "J_known and J_out column mismatch")
    d = len(Jk[0])
    require(isinstance(dw_int, (list, tuple)) and len(dw_int) == d and all(type(v) is int for v in dw_int), "INVALID_DW", "dw must be length-d int vector")
    t_num, t_den = require_rational_pair(tau, "tau", allow_zero=True)
    require_exact_int(scale_div, "scale_div", allow_zero=False)

    dw_norm_sq = sum(v * v for v in dw_int)
    require(dw_norm_sq > 0, "ZERO_WITNESS", "dw must be nonzero")
    jk_dw = mat_vec_int(Jk, dw_int)
    require(all(v == 0 for v in jk_dw), "NOT_BLIND", "J_known @ dw != 0")
    jo_dw = mat_vec_int(Jo, dw_int)
    jo_norm_sq = sum(v * v for v in jo_dw)
    lhs = t_den * jo_norm_sq
    rhs = t_num * (scale_div * scale_div) * dw_norm_sq
    require(lhs > rhs, "WITNESS_BELOW_TAU", "witness amplification does not strictly exceed tau")

    amp = Fraction(jo_norm_sq, (scale_div * scale_div) * dw_norm_sq)
    return {
        "verified": True,
        "dw_norm_sq": dw_norm_sq,
        "Jo_dw_norm_sq": jo_norm_sq,
        "amplification_exact": frac_dict(amp),
        "tau_exact": frac_dict(Fraction(t_num, t_den)),
    }


def certify_blind_drift_with_witness(
    J_known_int: Any,
    J_out_int: Any,
    *,
    tau: tuple[int, int],
    scale_div: int = 1,
) -> dict[str, Any]:
    """
    Hardened Haynsworth-Schur blind-drift certifier + constructive integer witness extractor.
    Works uniformly for full-rank `G_kk`, rank-deficient singular `G_kk` (`SP-09`), and zero `J_known`!
    """
    Jk = require_int_matrix(J_known_int, "J_known_int")
    Jo = require_int_matrix(J_out_int, "J_out_int")
    require(len(Jk[0]) == len(Jo[0]), "JACOBIAN_COL_MISMATCH", "J_known and J_out column mismatch")
    t_num, t_den = require_rational_pair(tau, "tau", allow_zero=True)
    require_exact_int(scale_div, "scale_div", allow_zero=False)

    mk, mo, d = len(Jk), len(Jo), len(Jk[0])
    G_kk = mat_mul_int(Jk, mat_transpose_int(Jk))
    G_ko = mat_mul_int(Jk, mat_transpose_int(Jo))
    G_oo = mat_mul_int(Jo, mat_transpose_int(Jo))
    b_kk = bareiss_symmetric_inertia_exact(G_kk)
    rank_kk = b_kk["inertia"][0]
    g_kk_singular = rank_kk < mk

    s2 = scale_div * scale_div
    N = mk + mo
    M_blind = [[0] * N for _ in range(N)]
    for i in range(mk):
        for j in range(mk):
            M_blind[i][j] = -t_den * G_kk[i][j]
        for j in range(mo):
            M_blind[i][mk + j] = t_den * G_ko[i][j]
            M_blind[mk + j][i] = t_den * G_ko[i][j]
    for i in range(mo):
        for j in range(mo):
            diag_term = t_num * s2 if i == j else 0
            M_blind[mk + i][mk + j] = diag_term - t_den * G_oo[i][j]

    b_m = bareiss_symmetric_inertia_exact(M_blind)
    n_unsafe = b_m["inertia"][1] - rank_kk

    # Exact rational generalized Schur complement S(tau) = tau_n*D^2*I - tau_d * Jo * P_k * Jo^T
    basis_idx = extract_row_basis_indices(Jk)
    Jk_r = [Jk[idx] for idx in basis_idx]
    if len(Jk_r) > 0:
        G_rr = mat_mul_int(Jk_r, mat_transpose_int(Jk_r))
        G_ro = mat_mul_int(Jk_r, mat_transpose_int(Jo))
        _ok, X_ro = solve_consistent_linear_rational(G_rr, G_ro)
        # Jo * P_k * Jo^T = G_oo - G_ro^T * X_ro
        S_q: list[list[Fraction]] = []
        for i in range(mo):
            row_q: list[Fraction] = []
            for j in range(mo):
                proj_ij = Fraction(G_oo[i][j], 1) - sum(Fraction(G_ro[r][i], 1) * X_ro[r][j] for r in range(len(Jk_r)))
                diag_ij = Fraction(t_num * s2, 1) if i == j else Fraction(0, 1)
                row_q.append(diag_ij - Fraction(t_den, 1) * proj_ij)
            S_q.append(row_q)
    else:
        X_ro = []
        S_q = [
            [(Fraction(t_num * s2, 1) if i == j else Fraction(0, 1)) - Fraction(t_den * G_oo[i][j], 1) for j in range(mo)]
            for i in range(mo)
        ]

    lcm_s = 1
    for row_q in S_q:
        for val_q in row_q:
            lcm_s = math.lcm(lcm_s, val_q.denominator)
    S_int = [[int(val_q * lcm_s) for val_q in row_q] for row_q in S_q]
    b_s = bareiss_symmetric_inertia_exact(S_int)

    witness_dw: list[int] | None = None
    witness_check: dict[str, Any] | None = None
    if n_unsafe > 0:
        y = b_s["rejection_witness"]
        # v = Jo^T y - Jk_r^T (X_ro y) in Q^d
        jo_t_y = [Fraction(sum(Jo[i][c] * y[i] for i in range(mo)), 1) for c in range(d)]
        if len(Jk_r) > 0:
            xy = [sum(X_ro[r][i] * y[i] for i in range(mo)) for r in range(len(Jk_r))]
            v_q = [jo_t_y[c] - sum(Fraction(Jk_r[r][c], 1) * xy[r] for r in range(len(Jk_r))) for c in range(d)]
        else:
            v_q = jo_t_y
        lcm_v = 1
        for fq in v_q:
            lcm_v = math.lcm(lcm_v, fq.denominator)
        dw_raw = [int(fq * lcm_v) for fq in v_q]
        g_dw = vec_gcd(dw_raw)
        witness_dw = [v // g_dw for v in dw_raw]
        witness_check = verify_blind_drift_witness_exact(Jk, Jo, witness_dw, tau=tau, scale_div=scale_div)

    return {
        "m_known": mk,
        "m_out": mo,
        "param_dim": d,
        "rank_G_known": rank_kk,
        "G_known_singular": g_kk_singular,
        "tau": frac_dict(Fraction(t_num, t_den)),
        "M_blind_inertia": list(b_m["inertia"]),
        "schur_inertia": list(b_s["inertia"]),
        "haynsworth_schur_agree": (b_s["inertia"][1] == n_unsafe),
        "n_unsafe_blind_directions": n_unsafe,
        "blind_drift_certified_le_tau": (n_unsafe == 0),
        "witness_dw_int": witness_dw,
        "witness_verification": witness_check,
    }


# ---------------------------------------------------------------------------
# 5. Multifrontal `SignedTree` Block-Schur Certifier (`AUDIT-052`)
# ---------------------------------------------------------------------------

def materialize_signed_tree(node: Mapping[str, Any]) -> list[list[int]]:
    """Expand a SignedTree (`leaf` | `block_sum` | `schur_couple`) into a flat symmetric integer matrix."""
    require(isinstance(node, Mapping), "BAD_TREE_NODE", "tree node must be a mapping")
    kind = node.get("kind")
    if kind == "leaf":
        return require_symmetric_int_matrix(node.get("M"), "leaf.M")
    if kind == "block_sum":
        children = node.get("children")
        require(isinstance(children, (list, tuple)) and len(children) > 0, "EMPTY_BLOCK_SUM", "block_sum needs children")
        mats = [materialize_signed_tree(ch) for ch in children]
        total = sum(len(m) for m in mats)
        out = [[0] * total for _ in range(total)]
        off = 0
        for m in mats:
            sz = len(m)
            for i in range(sz):
                for j in range(sz):
                    out[off + i][off + j] = m[i][j]
            off += sz
        return out
    if kind == "schur_couple":
        A = materialize_signed_tree(node.get("A"))
        C = materialize_signed_tree(node.get("C"))
        B = require_int_matrix(node.get("B"), "schur_couple.B")
        p, q = len(A), len(C)
        require(len(B) == p and len(B[0]) == q, "SCHUR_DIM_MISMATCH", "B shape must be len(A) x len(C)")
        out = [[0] * (p + q) for _ in range(p + q)]
        for i in range(p):
            for j in range(p):
                out[i][j] = A[i][j]
            for j in range(q):
                out[i][p + j] = B[i][j]
                out[p + j][i] = B[i][j]
        for i in range(q):
            for j in range(q):
                out[p + i][p + j] = C[i][j]
        return out
    raise GramCertError("UNKNOWN_TREE_KIND", f"unknown SignedTree kind: {kind!r}")


def evaluate_signed_tree_inertia(node: Mapping[str, Any]) -> dict[str, Any]:
    """
    Bottom-up multifrontal `SignedTree` inertia evaluator (`AUDIT-052` transfer):
      - `leaf(M)`: exact Bareiss inertia on leaf block M,
      - `block_sum(children)`: exact additive inertia `sum_i inertia(M_i)` (zero cross-fill),
      - `schur_couple(A, B, C)`: enforces exact range containment `col(B) <= col(A)` via
        `solve_consistent_linear_rational(A, B)` and returns `inertia(A) + inertia(C - B^T X)`.
    """
    require(isinstance(node, Mapping), "BAD_TREE_NODE", "tree node must be a mapping")
    kind = node.get("kind")
    if kind == "leaf":
        b = bareiss_symmetric_inertia_exact(node.get("M"))
        return {"inertia": list(b["inertia"]), "max_pivot_bits": b["max_pivot_bits"], "leaf_count": 1}
    if kind == "block_sum":
        children = node.get("children")
        require(isinstance(children, (list, tuple)) and len(children) > 0, "EMPTY_BLOCK_SUM", "block_sum needs children")
        np_t = nn_t = nz_t = 0
        max_bits = 1
        leaves = 0
        for ch in children:
            r = evaluate_signed_tree_inertia(ch)
            np_t += r["inertia"][0]
            nn_t += r["inertia"][1]
            nz_t += r["inertia"][2]
            max_bits = max(max_bits, r["max_pivot_bits"])
            leaves += r["leaf_count"]
        return {"inertia": [np_t, nn_t, nz_t], "max_pivot_bits": max_bits, "leaf_count": leaves}
    if kind == "schur_couple":
        A_mat = materialize_signed_tree(node.get("A"))
        C_mat = materialize_signed_tree(node.get("C"))
        B_mat = require_int_matrix(node.get("B"), "schur_couple.B")
        p, q = len(A_mat), len(C_mat)
        require(len(B_mat) == p and len(B_mat[0]) == q, "SCHUR_DIM_MISMATCH", "B shape must match A and C")
        ok, X = solve_consistent_linear_rational(A_mat, B_mat)
        require(ok, "SCHUR_RANGE_VIOLATION", "col(B) not contained in col(A); generalized Haynsworth inapplicable")
        S_q = [
            [Fraction(C_mat[i][j], 1) - sum(Fraction(B_mat[r][i], 1) * X[r][j] for r in range(p)) for j in range(q)]
            for i in range(q)
        ]
        lcm_s = 1
        for row_q in S_q:
            for val_q in row_q:
                lcm_s = math.lcm(lcm_s, val_q.denominator)
        S_int = [[int(val_q * lcm_s) for val_q in row_q] for row_q in S_q]
        ra = evaluate_signed_tree_inertia(node.get("A"))
        rs = bareiss_symmetric_inertia_exact(S_int)
        return {
            "inertia": [
                ra["inertia"][0] + rs["inertia"][0],
                ra["inertia"][1] + rs["inertia"][1],
                ra["inertia"][2] + rs["inertia"][2],
            ],
            "max_pivot_bits": max(ra["max_pivot_bits"], rs["max_pivot_bits"]),
            "leaf_count": ra["leaf_count"] + 1,
        }
    raise GramCertError("UNKNOWN_TREE_KIND", f"unknown SignedTree kind: {kind!r}")


# ---------------------------------------------------------------------------
# 6. Full Audit + Upgrade Certificate Generator (Zero Floats, R4 Bit-Identical)
# ---------------------------------------------------------------------------

def _inspect_live_clones_readonly(repos_dir: Path) -> dict[str, Any]:
    """Read-only probe of local `warp-drive` & `warp-drive-pr1` clones (never modifies either repo)."""
    main_dir = repos_dir / "warp-drive"
    pr1_dir = repos_dir / "warp-drive-pr1"
    if not (main_dir.is_dir() and pr1_dir.is_dir()):
        return {"live_clones_present": False}

    def git_info(repo: Path) -> dict[str, Any]:
        head = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
        dirty = len(subprocess.check_output(["git", "-C", str(repo), "status", "--porcelain"], text=True).splitlines())
        return {"head_sha": head, "dirty_files": dirty}

    main_git = git_info(main_dir)
    pr1_git = git_info(pr1_dir)

    # Probe exact defects live on unmodified clones (isolated sys.path)
    orig_path = list(sys.path)
    try:
        sys.path.insert(0, str(main_dir / "src"))
        import warp_modeld.certificate as main_cert  # type: ignore[import-not-found]

        h_nl = "a" * 64 + "\n"
        b_nl = "b" * 64 + "\n"
        base_h, h1, h2 = "b" * 64, "1" * 64, "2" * 64
        cert_nl = main_cert.FixedRadixCertificate.create(
            adapter_id="nl:test", adapter_sha256=h_nl, base_weights_sha256=b_nl,
            radix_scale=1, frobenius_sq_scaled=1, spectral_norm_sq_scaled=1,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        warp_cert_01 = bool(main_cert.SHA256_RE.match(h_nl)) and cert_nl.adapter_sha256.endswith("\n")

        d_1_1 = main_cert.stack_composition_digest([("a1", h1, 1, 1)])
        d_1000 = main_cert.stack_composition_digest([("a1", h1, 1000, 1000)])
        warp_cert_02 = (d_1_1 != d_1000)

        b100 = main_cert.CertificateBounds(
            main_cert.RationalBound(100, 1), main_cert.RationalBound(100, 1),
            main_cert.RationalBound(100, 1), main_cert.RationalBound(100, 1),
        )
        c1 = main_cert.FixedRadixCertificate.create(
            adapter_id="a1", adapter_sha256=h1, base_weights_sha256=base_h,
            radix_scale=1, frobenius_sq_scaled=16, spectral_norm_sq_scaled=16,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        c2 = main_cert.FixedRadixCertificate.create(
            adapter_id="a2", adapter_sha256=h2, base_weights_sha256=base_h,
            radix_scale=1, frobenius_sq_scaled=1, spectral_norm_sq_scaled=1,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        comp_sha = main_cert.stack_composition_digest([("a1", h1, 1, 1), ("a2", h2, 1, 1)])
        forged_comp = main_cert.FixedRadixCertificate.create(
            adapter_id="composed_stack", adapter_sha256=comp_sha, base_weights_sha256=base_h,
            radix_scale=1, frobenius_sq_scaled=0, spectral_norm_sq_scaled=0,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        res_forged = main_cert.verify_stack_division_free(
            [(c1, "a1", h1, 1, 1), (c2, "a2", h2, 1, 1)], b100, b100,
            expected_base_weights_sha256=base_h, composed_certificate=forged_comp,
        )
        warp_cert_03a = bool(res_forged.composed_cert_verified)

        b2 = main_cert.CertificateBounds(
            main_cert.RationalBound(2, 1), main_cert.RationalBound(2, 1),
            main_cert.RationalBound(2, 1), main_cert.RationalBound(2, 1),
        )
        o1 = main_cert.FixedRadixCertificate.create(
            adapter_id="a1", adapter_sha256=h1, base_weights_sha256=base_h,
            radix_scale=1, frobenius_sq_scaled=1, spectral_norm_sq_scaled=1,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        o2 = main_cert.FixedRadixCertificate.create(
            adapter_id="a2", adapter_sha256=h2, base_weights_sha256=base_h,
            radix_scale=1, frobenius_sq_scaled=1, spectral_norm_sq_scaled=1,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        honest_comp = main_cert.FixedRadixCertificate.create(
            adapter_id="composed_stack", adapter_sha256=comp_sha, base_weights_sha256=base_h,
            radix_scale=1, frobenius_sq_scaled=2, spectral_norm_sq_scaled=1,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        warp_cert_03b = False
        try:
            main_cert.verify_stack_division_free(
                [(o1, "a1", h1, 1, 1), (o2, "a2", h2, 1, 1)], b2, b2,
                expected_base_weights_sha256=base_h, composed_certificate=honest_comp,
            )
        except main_cert.CertificateError:
            warp_cert_03b = True

        b10 = main_cert.CertificateBounds(
            main_cert.RationalBound(10, 1), main_cert.RationalBound(10, 1),
            main_cert.RationalBound(10, 1), main_cert.RationalBound(10, 1),
        )
        b1 = main_cert.CertificateBounds(
            main_cert.RationalBound(1, 1), main_cert.RationalBound(1, 1),
            main_cert.RationalBound(1, 1), main_cert.RationalBound(1, 1),
        )
        c_mid = main_cert.FixedRadixCertificate.create(
            adapter_id="a1", adapter_sha256=h1, base_weights_sha256=base_h,
            radix_scale=1, frobenius_sq_scaled=5, spectral_norm_sq_scaled=5,
            leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
        )
        res_single = main_cert.verify_stack_division_free(
            [(c_mid, "a1", h1, 1, 1)], b10, b1, expected_base_weights_sha256=base_h,
        )
        warp_cert_03c = (len(res_single.adapter_results) == 1)

        warp_cert_04_type = ""
        try:
            main_cert.verify_division_free(
                c1, b100, expected_adapter_id="a1",
                expected_adapter_sha256=b"1" * 64,  # type: ignore[arg-type]
                expected_base_weights_sha256=base_h,
            )
        except Exception as exc:
            warp_cert_04_type = type(exc).__name__

        # PR #1 probes
        pr1_study_dir = pr1_dir / "studies" / "expedition-bareiss-gram-cert"
        sys.path.insert(0, str(pr1_study_dir))
        import bareiss_gram_gate as pr1_gate  # type: ignore[import-not-found]

        pr1_rh4_frac = pr1_gate.r_h4_stieltjes_hankel_exact(
            Fraction(1), Fraction(13), Fraction(19), Fraction(97), 0
        )
        pr1_rh4_int_is_float = isinstance(pr1_gate.r_h4_stieltjes_hankel_exact(1, 13, 19, 97, 0), float)
        pr1_ropt_int_is_float = isinstance(pr1_gate.r_opt_exact(1, 0, 2, 0), float)
        pr1_bd = pr1_gate.certify_covert_rank_backdoor_gate(
            [[2, 0], [0, 2]], [[1, 0], [0, 1]],
            scale_div=1, norm_cap_frob_sq=(10, 1), norm_cap_spec_sq=(10, 1), max_allowed_extra_rank=2,
        )
        pr1_bd_float_keys = sorted(k for k, v in pr1_bd.items() if isinstance(v, float))

        pr1_fden0_exc = ""
        try:
            pr1_gate.certify_covert_rank_backdoor_gate(
                [[2, 0], [0, 2]], [[1, 0], [0, 1]],
                scale_div=1, norm_cap_frob_sq=(1, 0), norm_cap_spec_sq=(1, 1), max_allowed_extra_rank=1,
            )
        except Exception as exc:
            pr1_fden0_exc = type(exc).__name__

        pr1_bool_rank_accepted = isinstance(
            pr1_gate.certify_covert_rank_backdoor_gate(
                [[2, 0], [0, 2]], [[1, 0], [0, 1]],
                scale_div=1, norm_cap_frob_sq=(10, 1), norm_cap_spec_sq=(10, 1), max_allowed_extra_rank=True,
            ),
            dict,
        )
        pr1_gate_src = (pr1_study_dir / "bareiss_gram_gate.py").read_text(encoding="utf-8")
        pr1_req_count = len(re.findall(r"\b_req\(", pr1_gate_src)) - len(re.findall(r"\bdef\s+_req\(", pr1_gate_src))
    finally:
        sys.path[:] = orig_path

    return {
        "live_clones_present": True,
        "warp_drive_main": main_git,
        "warp_drive_pr1": pr1_git,
        "live_reproductions": {
            "WARP_CERT_01_trailing_newline_accepted": warp_cert_01,
            "WARP_CERT_02_unreduced_scale_digest_mismatch": warp_cert_02,
            "WARP_CERT_03A_forged_zero_composed_cert_accepted": warp_cert_03a,
            "WARP_CERT_03B_honest_orthogonal_stack_rejected_by_CS": warp_cert_03b,
            "WARP_CERT_03C_single_adapter_skips_joint_bounds": warp_cert_03c,
            "WARP_CERT_04_non_str_digest_raw_exception": warp_cert_04_type,
            "PR1_B1_indefinite_rh4_false_rank_exact": frac_dict(pr1_rh4_frac),
            "PR1_B1_indefinite_rh4_exceeds_true_rank_1": (pr1_rh4_frac > Fraction(1, 1)),
            "PR1_B1_int_args_return_float": pr1_rh4_int_is_float and pr1_ropt_int_is_float,
            "PR1_B2_covert_gate_emits_float_keys": pr1_bd_float_keys,
            "PR1_B3_f_den_zero_raw_exception": pr1_fden0_exc,
            "PR1_B3_bool_max_allowed_extra_rank_accepted": pr1_bool_rank_accepted,
            "PR1_B4_hidden_underscore_req_calls": pr1_req_count,
        },
    }


def build_audit_certificate(*, standalone: bool = False) -> dict[str, Any]:
    """Build the complete canonical zero-float AUDIT-061 verification & upgrade certificate."""
    base_h, h1, h2 = "b" * 64, "1" * 64, "2" * 64
    b2 = HardenedCertificateBounds(
        HardenedRationalBound(2, 1), HardenedRationalBound(2, 1),
        HardenedRationalBound(2, 1), HardenedRationalBound(2, 1),
    )

    # Demo 1: Hardened Stage-2 fixes WARP-CERT-01..04
    # 1A: Trailing newline rejected
    nl_rejected = False
    try:
        require_strict_sha256("a" * 64 + "\n", "test")
    except GramCertError as exc:
        nl_rejected = (exc.code == "INVALID_SHA256")
    # 1B: Canonical gcd scale digest
    canon_d1 = canonical_stack_composition_digest([("a1", h1, 1, 1)])
    canon_d2 = canonical_stack_composition_digest([("a1", h1, 1000, 1000)])
    # 1C: Forged frobenius_sq=0 composed cert rejected on (16, 1) where true >= 9 AND on singleton (16,)
    forged_rejected = False
    try:
        check_composed_norm_triangle_exact([Fraction(16, 1), Fraction(1, 1)], Fraction(0, 1), "frob")
    except GramCertError as exc:
        forged_rejected = (exc.code == "COMPOSED_TRIANGLE_VIOLATION")
    singleton_forged_rejected = False
    try:
        check_composed_norm_triangle_exact([Fraction(16, 1)], Fraction(0, 1), "frob")
    except GramCertError as exc:
        singleton_forged_rejected = (exc.code == "COMPOSED_SINGLETON_MISMATCH")
    # 1D: Honest orthogonal 2-adapter stack ACCEPTED via verified Bareiss Gram escape hatch
    orth_adapters = [
        {"adapter_id": "a1", "B_int": [[1], [0]], "A_int": [[1, 0]], "scale_div": 1},
        {"adapter_id": "a2", "B_int": [[0], [1]], "A_int": [[0, 1]], "scale_div": 1},
    ]
    gram_orth = certify_stacked_mde_gram_exact(
        orth_adapters, max_frobenius_sq=(2, 1), max_spectral_norm_sq=(1, 1)
    )
    o1 = HardenedFixedRadixCertificate.create(
        adapter_id="a1", adapter_sha256=h1, base_weights_sha256=base_h,
        radix_scale=1, frobenius_sq_scaled=1, spectral_norm_sq_scaled=1,
        leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
    )
    o2 = HardenedFixedRadixCertificate.create(
        adapter_id="a2", adapter_sha256=h2, base_weights_sha256=base_h,
        radix_scale=1, frobenius_sq_scaled=1, spectral_norm_sq_scaled=1,
        leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
    )
    comp_sha = canonical_stack_composition_digest([("a1", h1, 1, 1), ("a2", h2, 1, 1)])
    honest_comp = HardenedFixedRadixCertificate.create(
        adapter_id="composed_stack", adapter_sha256=comp_sha, base_weights_sha256=base_h,
        radix_scale=1, frobenius_sq_scaled=2, spectral_norm_sq_scaled=1,
        leakage_energy_scaled=0, max_safety_dot_sq_scaled=0,
    )
    orth_stack_res = verify_stack_hardened(
        [(o1, "a1", h1, 1, 1), (o2, "a2", h2, 1, 1)],
        b2, b2, expected_base_weights_sha256=base_h,
        composed_certificate=honest_comp, verified_gram_report=gram_orth,
    )

    # Demo 2: Moment-cone sound R_H4 on indefinite counterexample H = diag(3, -2) vs PSD H = diag(10, 1, 1)
    indef_ce = r_h4_stieltjes_sound(1, 13, 19, 97, 0)
    psd_gain = r_h4_stieltjes_sound(12, 102, 1002, 10002, 0)
    ropt_psd = r_opt_exact_strict(12, 0, 102, 0)

    # Demo 3: Constructive Blind-Drift Witness Extraction on SINGULAR G_kk (`SP-09`)
    # J_k has 2 linearly dependent rows (row 1 = 2 * row 0) -> G_kk is 2x2 rank-1 SINGULAR!
    # Ker(J_k) = span{(0, 1, 0), (0, 0, 1)}. J_o probes directions (1, 0, 0) and (0, 3, 4) (norm^2 = 25).
    Jk_sing = [[1, 0, 0], [2, 0, 0]]
    Jo_sing = [[1, 0, 0], [0, 3, 4]]
    blind_breach = certify_blind_drift_with_witness(Jk_sing, Jo_sing, tau=(10, 1), scale_div=1)
    blind_safe = certify_blind_drift_with_witness(Jk_sing, Jo_sing, tau=(25, 1), scale_div=1)

    # Demo 4: Multifrontal SignedTree (`AUDIT-052`) on 3-layer stack + coupled singular-A Schur block
    # Layer 1..3 block-diagonal Q_stack blocks + coupled 2x2 block with rank-1 singular A = [[2, 2], [2, 2]]
    layer_tree = {
        "kind": "block_sum",
        "children": [
            {"kind": "leaf", "M": [[4, -1], [-1, 4]]},
            {"kind": "leaf", "M": [[3, 1], [1, 3]]},
            {
                "kind": "schur_couple",
                "A": {"kind": "leaf", "M": [[2, 2], [2, 2]]},
                "B": [[2, -4], [2, -4]],
                "C": {"kind": "leaf", "M": [[5, -2], [-2, 10]]},
            },
        ],
    }
    tree_eval = evaluate_signed_tree_inertia(layer_tree)
    flat_mat = materialize_signed_tree(layer_tree)
    flat_bareiss = bareiss_symmetric_inertia_exact(flat_mat)
    flat_fl = faddeev_leverrier_inertia_exact(flat_mat)

    # Live read-only clone inspection (when present and not --standalone)
    repos_dir = Path(__file__).resolve().parent.parent / "repos"
    live_info = {"live_clones_present": False} if standalone else _inspect_live_clones_readonly(repos_dir)

    body: dict[str, Any] = {
        "schema": "expedition.round6.arm1_warp_drive_gram_cert.v1",
        "audit_id": "AUDIT-061",
        "target_repo": "Moissanite-Labs/warp-drive",
        "stage2_hardening": {
            "WARP_CERT_01_strict_Z_rejects_trailing_newline": nl_rejected,
            "WARP_CERT_02_canonical_gcd_digest_equal": (canon_d1 == canon_d2),
            "WARP_CERT_02_canonical_digest": canon_d1,
            "WARP_CERT_03A_forged_zero_composed_cert_rejected": forged_rejected,
            "WARP_CERT_03A_singleton_forged_zero_rejected": singleton_forged_rejected,
            "WARP_CERT_03B_orthogonal_stack_gram_escape": {
                "gram_frobenius_exact": gram_orth["exact_frobenius_sq"],
                "gram_Q_stack_inertia": gram_orth["Q_stack_inertia"],
                "gram_psd_cert_verified": gram_orth["psd_cert_verified"],
                "stack_result": orth_stack_res,
            },
        },
        "moment_cone_rh4_upgrade": {
            "indefinite_counterexample_H_diag_3_neg2": {
                "true_rank_P": 1,
                "true_b": 0,
                "pr1_unguarded_output_exact": "2/1",
                "sound_result": indef_ce,
                "soundness_holds": (Fraction(indef_ce["best_lower_bound"]["num"], indef_ce["best_lower_bound"]["den"]) <= Fraction(1, 1)),
            },
            "psd_strict_gain_H_diag_10_1_1": {
                "R_opt_exact": frac_dict(ropt_psd),
                "sound_result": psd_gain,
                "strictly_beats_R_opt": (Fraction(psd_gain["R_h4_sound"]["num"], psd_gain["R_h4_sound"]["den"]) > ropt_psd),
            },
        },
        "blind_drift_sp09_witness": {
            "singular_G_kk_breach_tau_10": blind_breach,
            "singular_G_kk_safe_tau_25": {
                "G_known_singular": blind_safe["G_known_singular"],
                "rank_G_known": blind_safe["rank_G_known"],
                "n_unsafe_blind_directions": blind_safe["n_unsafe_blind_directions"],
                "blind_drift_certified_le_tau": blind_safe["blind_drift_certified_le_tau"],
                "haynsworth_schur_agree": blind_safe["haynsworth_schur_agree"],
            },
        },
        "signed_tree_multifrontal_audit052": {
            "flat_dim": len(flat_mat),
            "tree_inertia": tree_eval["inertia"],
            "flat_bareiss_inertia": list(flat_bareiss["inertia"]),
            "flat_faddeev_leverrier_inertia": list(flat_fl),
            "triple_oracle_exact_agreement": (
                tree_eval["inertia"] == list(flat_bareiss["inertia"]) == list(flat_fl)
            ),
            "tree_max_pivot_bits": tree_eval["max_pivot_bits"],
            "flat_max_pivot_bits": flat_bareiss["max_pivot_bits"],
            "leaf_count": tree_eval["leaf_count"],
        },
        "eight_glyph_compression_audit051": {
            "gram_stack_psd": "⦺(G_stack ⧄ B_blk) ⩩ (r_+, 0, r_0) ⫩ R5_gate",
            "blind_drift_sp09": "⦺(M_blind ⧄ G_kk) ⩩ (m_o - n_u, n_u, 0) ; dw in ⧅(J_k, J_o)",
            "signed_tree_schur": "⦺(M_coupled) ⩩ ⦺(A) + ⦺(M_coupled ⧄ A)  [col(B) <= col(A)]",
            "moment_cone_rh4": "S1*S3 >= S2^2 & S2*S4 > S3^2 => R_H4 <= n_+(H) <= rank(P) + b",
        },
        "live_clone_audit": live_info,
    }
    return {
        "certificate": body,
        "certificate_sha256": canonical_sha256(body),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="AUDIT-061 warp-drive Gram & Stage-2 certificate audit")
    parser.add_argument("--standalone", action="store_true", help="Skip live clone inspection")
    parser.add_argument("--write-cert", type=str, default="", help="Write canonical JSON certificate to path")
    args = parser.parse_args(list(argv) if argv is not None else None)
    cert = build_audit_certificate(standalone=args.standalone)
    out = canonical_json(cert)
    if args.write_cert:
        Path(args.write_cert).write_text(out + "\n", encoding="utf-8", newline="\n")
    sys.stdout.write(out + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
