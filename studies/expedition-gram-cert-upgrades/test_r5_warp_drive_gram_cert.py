#!/usr/bin/env python3
"""
R1-R5 Mutation-Killing & Dual-Oracle Verification Test Suite for AUDIT-061
(`warp_drive_gram_cert_audit.py`).

Safe under `python3 -I -B`, `python3 -I -O -B`, `python3 -I -B -W error`, `python3 -I -O -B -W error`.
Zero external dependencies, zero bare asserts.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from fractions import Fraction
import io
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import warp_drive_gram_cert_audit as mod  # noqa: E402


def _assert_no_floats(obj: object, path: str = "root") -> None:
    if isinstance(obj, float):
        raise AssertionError(f"float leaked at {path}: {obj!r}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _assert_no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _assert_no_floats(v, f"{path}[{i}]")


def _mk_cert(
    aid: str,
    asha: str,
    bsha: str,
    radix: int = 1,
    frob: int = 1,
    spec: int = 1,
    leak: int = 0,
    safety: int = 0,
) -> mod.HardenedFixedRadixCertificate:
    return mod.HardenedFixedRadixCertificate.create(
        adapter_id=aid,
        adapter_sha256=asha,
        base_weights_sha256=bsha,
        radix_scale=radix,
        frobenius_sq_scaled=frob,
        spectral_norm_sq_scaled=spec,
        leakage_energy_scaled=leak,
        max_safety_dot_sq_scaled=safety,
    )


def _mk_bounds(f: tuple[int, int] = (10, 1), s: tuple[int, int] = (10, 1), l: tuple[int, int] = (10, 1), d: tuple[int, int] = (10, 1)) -> mod.HardenedCertificateBounds:
    return mod.HardenedCertificateBounds(
        mod.HardenedRationalBound(*f),
        mod.HardenedRationalBound(*s),
        mod.HardenedRationalBound(*l),
        mod.HardenedRationalBound(*d),
    )


class TestPrimitivesAndParsers(unittest.TestCase):
    def test_exact_int_rational_sha256_boundaries(self) -> None:
        self.assertTrue(mod.is_exact_int(0))
        self.assertFalse(mod.is_exact_int(True))
        self.assertEqual(mod.require_exact_int(0, "x", allow_zero=True), 0)
        self.assertEqual(mod.require_exact_int(1, "x", allow_zero=False), 1)
        for bad in (True, 1.0, "1", None):
            with self.assertRaises(mod.GramCertError):
                mod.require_exact_int(bad, "x")
        with self.assertRaises(mod.GramCertError):
            mod.require_exact_int(-1, "x", allow_zero=True)
        with self.assertRaises(mod.GramCertError):
            mod.require_exact_int(0, "x", allow_zero=False)

        h = "a" * 64
        self.assertEqual(mod.require_strict_sha256(h, "h"), h)
        for bad_h in (h + "\n", h.upper(), "a" * 63, b"a" * 64, 123):
            with self.assertRaises(mod.GramCertError):
                mod.require_strict_sha256(bad_h, "h")

        self.assertEqual(mod.require_exact_rational(3, "q"), Fraction(3, 1))
        self.assertEqual(mod.require_exact_rational(Fraction(2, 5), "q"), Fraction(2, 5))
        for bad_q in (True, 1.5, "1/2", None):
            with self.assertRaises(mod.GramCertError):
                mod.require_exact_rational(bad_q, "q")

        self.assertEqual(mod.require_rational_pair((0, 1), "p", allow_zero=True), (0, 1))
        self.assertEqual(mod.require_rational_pair([2, 3], "p", allow_zero=False), (2, 3))
        for bad_p in ((1,), (1, 2, 3), "12", (0, 0), (-1, 1), (True, 1)):
            with self.assertRaises(mod.GramCertError):
                mod.require_rational_pair(bad_p, "p")
        with self.assertRaises(mod.GramCertError):
            mod.require_rational_pair((0, 1), "p", allow_zero=False)
        self.assertEqual(mod.ceil_fraction(Fraction(0, 1)), 0)
        self.assertEqual(mod.ceil_fraction(Fraction(-1, 2)), 0)
        self.assertEqual(mod.ceil_fraction(Fraction(5, 2)), 3)

    def test_matrix_validation_and_ops(self) -> None:
        for bad in ([], "abc", [[]], [[1], [1, 2]], [[1.0]], [[True]]):
            with self.assertRaises(mod.GramCertError):
                mod.require_int_matrix(bad, "M")
        with self.assertRaises(mod.GramCertError):
            mod.require_symmetric_int_matrix([[1, 2]], "M")
        with self.assertRaises(mod.GramCertError):
            mod.require_symmetric_int_matrix([[1, 2], [3, 1]], "M")
        with self.assertRaises(mod.GramCertError):
            mod.mat_mul_int([[1, 2]], [[1]])
        with self.assertRaises(mod.GramCertError):
            mod.mat_vec_int([[1, 2]], [1])
        with self.assertRaises(mod.GramCertError):
            mod.quad_form_int([[1, 0], [0, 1]], [1])
        with self.assertRaises(mod.GramCertError):
            mod._solve_spd_integer_scaled([[0]], [1])
        with self.assertRaises(mod.GramCertError):
            mod._solve_spd_integer_scaled([[-1]], [1])
        self.assertEqual(mod._solve_spd_integer_scaled([], []), ([], 1))
        self.assertEqual(mod.vec_gcd([0, 0]), 1)


class TestBareissAndDualOracle(unittest.TestCase):
    def test_bareiss_vs_faddeev_leverrier_and_2x2_zero_diag(self) -> None:
        # 2x2 zero-diagonal positive/negative off-diagonal + trailing 3x3 block + zero tail
        cases = [
            [[0, 0], [0, 0]],
            [[0, 3], [3, 0]],
            [[0, -2], [-2, 0]],
            [[0, 2, 1], [2, 0, 1], [1, 1, 0]],
            [[2, 1, 0, 0], [1, 2, 0, 0], [0, 0, 0, 3], [0, 0, 3, 0]],
            [[0, 0, 5], [0, 0, 0], [5, 0, 0]],
            [[4, 2, 2], [2, 1, 1], [2, 1, 1]],
            [[1, 2, 0], [2, 1, 0], [0, 0, 3]],
        ]
        rng = random.Random(20261121)
        for _ in range(30):
            n = rng.randint(1, 5)
            M = [[0] * n for _ in range(n)]
            for i in range(n):
                for j in range(i, n):
                    v = rng.randint(-4, 4)
                    M[i][j] = v
                    M[j][i] = v
            cases.append(M)

        for M in cases:
            b = mod.bareiss_symmetric_inertia_exact(M)
            fl = mod.faddeev_leverrier_inertia_exact(M)
            self.assertEqual(b["inertia"], fl)
            if b["is_psd"]:
                self.assertTrue(mod.verify_integer_psd_certificate_exact(M, b["psd_certificate"]))
            else:
                self.assertIsNotNone(b["rejection_witness"])
                self.assertLess(b["rejection_value"], 0)
                self.assertEqual(mod.quad_form_int(M, b["rejection_witness"]), b["rejection_value"])

    def test_psd_certificate_verifier_refusals(self) -> None:
        M = [[2, 1], [1, 2]]
        cert = mod.bareiss_symmetric_inertia_exact(M)["psd_certificate"]
        self.assertTrue(mod.verify_integer_psd_certificate_exact(M, cert))

        with self.assertRaises(mod.GramCertError) as ctx_wc:
            mod.verify_integer_psd_certificate_exact(M, {**cert, "weights": [1]})
        self.assertEqual(ctx_wc.exception.code, "BAD_WEIGHTS_COLS")

        for bad_cert in (
            None,
            123,
            {**cert, "perm": [0, 0]},
            {**cert, "perm": [0]},
            {**cert, "perm": [False, 1]},
            {**cert, "common_den": 0},
            {**cert, "weights": [0, 1]},
            {**cert, "cols": [[1], [1, 2]]},
            {**cert, "cols": [[True, 1], [0, 1]]},
            {**cert, "common_den": cert["common_den"] + 1},
        ):
            with self.assertRaises(mod.GramCertError):
                mod.verify_integer_psd_certificate_exact(M, bad_cert)


class TestStage2HardenedCertificates(unittest.TestCase):
    def setUp(self) -> None:
        self.base_h = "b" * 64
        self.h1 = "1" * 64
        self.h2 = "2" * 64
        self.h3 = "3" * 64

    def test_certificate_and_bounds_refusals(self) -> None:
        b = _mk_bounds()
        c = _mk_cert("a1", self.h1, self.base_h, 1, 2, 2, 1, 1)
        res = mod.verify_certificate_hardened(
            c, b, expected_adapter_id="a1", expected_adapter_sha256=self.h1, expected_base_weights_sha256=self.base_h
        )
        self.assertTrue(res["passed"])

        # Boundary: exact equality on bounds AND spec == frob passes
        b_exact = _mk_bounds((2, 1), (2, 1), (1, 1), (1, 1))
        self.assertTrue(mod.verify_certificate_hardened(c, b_exact)["passed"])
        # Exceed bound by 1 fails
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(_mk_cert("a1", self.h1, self.base_h, 1, 3, 2, 1, 1), b_exact)

        # Bad bounds field types
        for idx in range(4):
            args = [mod.HardenedRationalBound(1, 1)] * 4
            args[idx] = (1, 1)  # type: ignore[assignment]
            with self.assertRaises(mod.GramCertError):
                mod.HardenedCertificateBounds(*args)  # type: ignore[arg-type]

        # Empty adapter_id, trailing newline, forged digest, spec > frob, mismatches, wrong types
        with self.assertRaises(mod.GramCertError):
            _mk_cert("   ", self.h1, self.base_h)
        with self.assertRaises(mod.GramCertError):
            _mk_cert("a1", self.h1 + "\n", self.base_h)
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened("not-a-cert", b)
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(c, "not-bounds")

        forged = mod.HardenedFixedRadixCertificate(
            "a1", self.h1, self.base_h, 1, 1, 1, 0, 0, "0" * 64
        )
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(forged, b)
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(c, b, expected_adapter_id="wrong")
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(c, b, expected_adapter_id=123)  # type: ignore[arg-type]
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(c, b, expected_adapter_sha256=self.h2)
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(c, b, expected_adapter_sha256=b"1" * 64)  # type: ignore[arg-type]
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(c, b, expected_base_weights_sha256=self.h2)
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(c, b, expected_base_weights_sha256=b"b" * 64)  # type: ignore[arg-type]
        with self.assertRaises(mod.GramCertError):
            mod.verify_certificate_hardened(_mk_cert("a1", self.h1, self.base_h, 1, 1, 2, 0, 0), b)

    def test_canonical_stack_digest_and_triangle_boundaries(self) -> None:
        d1 = mod.canonical_stack_composition_digest([("a1", self.h1, 1, 1)])
        d2 = mod.canonical_stack_composition_digest([("a1", self.h1, 1000, 1000)])
        self.assertEqual(d1, d2)

        for bad_entries in (
            [],
            [("a1", self.h1, 1)],
            [("", self.h1, 1, 1)],
            [("a1", self.h1, 1, 1), ("a1", self.h2, 1, 1)],
            [("a1", self.h1 + "\n", 1, 1)],
            [("a1", self.h1, 0, 1)],
            [("a1", self.h1, 1, 0)],
        ):
            with self.assertRaises(mod.GramCertError):
                mod.canonical_stack_composition_digest(bad_entries)  # type: ignore[arg-type]

        # Exact 1-term singleton equality (closes PR #12 review forgery): a=[16] => c must equal 16
        mod.check_composed_norm_triangle_exact([Fraction(16)], Fraction(16), "f")
        for under in (Fraction(0), Fraction(1), Fraction(15)):
            with self.assertRaises(mod.GramCertError) as ctx_u:
                mod.check_composed_norm_triangle_exact([Fraction(16)], under, "f")
            self.assertEqual(ctx_u.exception.code, "COMPOSED_SINGLETON_MISMATCH")
        for over in (Fraction(17), Fraction(100)):
            with self.assertRaises(mod.GramCertError) as ctx_o:
                mod.check_composed_norm_triangle_exact([Fraction(16)], over, "f")
            self.assertEqual(ctx_o.exception.code, "COMPOSED_EXCEEDS_CS")

        # Exact 2-term triangle boundaries: a1=16, a2=1 => valid c in [9, 25]
        mod.check_composed_norm_triangle_exact([Fraction(16), Fraction(1)], Fraction(9), "f")
        mod.check_composed_norm_triangle_exact([Fraction(16), Fraction(1)], Fraction(25), "f")
        with self.assertRaises(mod.GramCertError):
            mod.check_composed_norm_triangle_exact([Fraction(16), Fraction(1)], Fraction(8), "f")
        with self.assertRaises(mod.GramCertError):
            mod.check_composed_norm_triangle_exact([Fraction(16), Fraction(1)], Fraction(26), "f")
        with self.assertRaises(mod.GramCertError):
            mod.check_composed_norm_triangle_exact([Fraction(16), Fraction(1)], Fraction(35), "f")

        # 3-term reverse triangle: a = [100, 1, 1], B_0 = 2*(1+1) = 4, (sqrt(100)-sqrt(4))^2 = 64
        mod.check_composed_norm_triangle_exact([Fraction(100), Fraction(1), Fraction(1)], Fraction(64), "f")
        mod.check_composed_norm_triangle_exact([Fraction(100), Fraction(1), Fraction(1)], Fraction(104), "f")
        mod.check_composed_norm_triangle_exact([Fraction(100), Fraction(1), Fraction(1)], Fraction(306), "f")
        with self.assertRaises(mod.GramCertError):
            mod.check_composed_norm_triangle_exact([Fraction(100), Fraction(1), Fraction(1)], Fraction(63), "f")
        with self.assertRaises(mod.GramCertError):
            mod.check_composed_norm_triangle_exact([Fraction(100), Fraction(1), Fraction(1)], Fraction(307), "f")

    def test_stack_verifier_single_joint_cs_and_gram_escape(self) -> None:
        b10 = _mk_bounds((10, 1), (10, 1), (10, 1), (10, 1))
        b2 = _mk_bounds((2, 1), (2, 1), (2, 1), (2, 1))
        b1 = _mk_bounds((1, 1), (1, 1), (1, 1), (1, 1))
        c1 = _mk_cert("a1", self.h1, self.base_h, 1, 1, 1, 0, 0)
        c2 = _mk_cert("a2", self.h2, self.base_h, 1, 1, 1, 0, 0)

        # Empty, bad bounds (distinct codes), duplicate adapter_id
        with self.assertRaises(mod.GramCertError):
            mod.verify_stack_hardened([], b10, b10, expected_base_weights_sha256=self.base_h)
        with self.assertRaises(mod.GramCertError) as ctx_sb:
            mod.verify_stack_hardened([(c1, "a1", self.h1, 1, 1)], "bad", b10, expected_base_weights_sha256=self.base_h)
        self.assertEqual(ctx_sb.exception.code, "INVALID_SINGLE_BOUNDS")
        with self.assertRaises(mod.GramCertError) as ctx_jb:
            mod.verify_stack_hardened([(c1, "a1", self.h1, 1, 1)], b10, "bad", expected_base_weights_sha256=self.base_h)
        self.assertEqual(ctx_jb.exception.code, "INVALID_JOINT_BOUNDS")
        with self.assertRaises(mod.GramCertError):
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c1, "a1", self.h1, 1, 1)],
                b10, b10, expected_base_weights_sha256=self.base_h,
            )

        # Single-adapter enforces joint_bounds (WARP-CERT-03C closed!)
        c_mid = _mk_cert("a1", self.h1, self.base_h, 1, 5, 5, 0, 0)
        with self.assertRaises(mod.GramCertError):
            mod.verify_stack_hardened([(c_mid, "a1", self.h1, 1, 1)], b10, b1, expected_base_weights_sha256=self.base_h)
        r_single = mod.verify_stack_hardened([(c1, "a1", self.h1, 1, 1)], b10, b1, expected_base_weights_sha256=self.base_h)
        self.assertTrue(r_single["joint_bounds_checked"])

        # Singleton composed-certificate forgery regression (n == 1 must match component norm exactly!)
        b20 = _mk_bounds((20, 1), (20, 1), (20, 1), (20, 1))
        c16 = _mk_cert("a1", self.h1, self.base_h, 1, 16, 16, 0, 0)
        single_stack_sha = mod.canonical_stack_composition_digest([("a1", self.h1, 1, 1)])
        comp_zero = _mk_cert("composed_stack", single_stack_sha, self.base_h, 1, 0, 0, 0, 0)
        with self.assertRaises(mod.GramCertError) as ctx_s0:
            mod.verify_stack_hardened(
                [(c16, "a1", self.h1, 1, 1)],
                b20,
                b20,
                expected_base_weights_sha256=self.base_h,
                composed_certificate=comp_zero,
            )
        self.assertEqual(ctx_s0.exception.code, "COMPOSED_SINGLETON_MISMATCH")
        comp_over = _mk_cert("composed_stack", single_stack_sha, self.base_h, 1, 17, 17, 0, 0)
        with self.assertRaises(mod.GramCertError) as ctx_s17:
            mod.verify_stack_hardened(
                [(c16, "a1", self.h1, 1, 1)],
                b20,
                b20,
                expected_base_weights_sha256=self.base_h,
                composed_certificate=comp_over,
            )
        self.assertEqual(ctx_s17.exception.code, "COMPOSED_EXCEEDS_CS")
        comp_exact = _mk_cert("composed_stack", single_stack_sha, self.base_h, 1, 16, 16, 0, 0)
        r_single_comp = mod.verify_stack_hardened(
            [(c16, "a1", self.h1, 1, 1)],
            b20,
            b20,
            expected_base_weights_sha256=self.base_h,
            composed_certificate=comp_exact,
        )
        self.assertTrue(r_single_comp["composed_cert_verified"])

        # Multi-adapter CS check without Gram escape rejects orthogonal stack under tight b2 (4 > 2), passes under b10
        r_cs = mod.verify_stack_hardened(
            [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
            b10, b10, expected_base_weights_sha256=self.base_h,
        )
        self.assertTrue(r_cs["composed_bound_checked"])
        with self.assertRaises(mod.GramCertError):
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
            )

        # Gram escape hatch accepts honest orthogonal stack (at exact joint_bounds boundary!)
        adapters = [
            {"adapter_id": "a1", "B_int": [[1], [0]], "A_int": [[1, 0]], "scale_div": 1},
            {"adapter_id": "a2", "B_int": [[0], [1]], "A_int": [[0, 1]], "scale_div": 1},
        ]
        gram_ok = mod.certify_stacked_mde_gram_exact(adapters, max_frobenius_sq=(2, 1), max_spectral_norm_sq=(1, 1))
        self.assertTrue(gram_ok["frobenius_certified"] and gram_ok["spectral_certified"])
        b_exact_gram = _mk_bounds((2, 1), (1, 1), (0, 1), (0, 1))
        r_esc = mod.verify_stack_hardened(
            [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
            b2, b_exact_gram, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_ok,
        )
        self.assertTrue(r_esc["gram_escape_used"])
        self.assertTrue(r_esc["composed_bound_checked"])

        # GRAM-ESC-BYPASS-1: leakage_energy & max_safety_dot_sq MUST NOT be skipped under Gram escape!
        c1_leak = _mk_cert("a1", self.h1, self.base_h, 1, 1, 1, 10, 0)
        c2_leak = _mk_cert("a2", self.h2, self.base_h, 1, 1, 1, 10, 0)
        b_leak_tight = _mk_bounds((2, 1), (2, 1), (1, 1), (1, 1))
        with self.assertRaises(mod.GramCertError) as ctx_lk:
            mod.verify_stack_hardened(
                [(c1_leak, "a1", self.h1, 1, 1), (c2_leak, "a2", self.h2, 1, 1)],
                b10, b_leak_tight, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_ok,
            )
        self.assertEqual(ctx_lk.exception.code, "BOUND_EXCEEDED")

        c1_saf = _mk_cert("a1", self.h1, self.base_h, 1, 1, 1, 0, 10)
        c2_saf = _mk_cert("a2", self.h2, self.base_h, 1, 1, 1, 0, 10)
        with self.assertRaises(mod.GramCertError) as ctx_sf:
            mod.verify_stack_hardened(
                [(c1_saf, "a1", self.h1, 1, 1), (c2_saf, "a2", self.h2, 1, 1)],
                b10, b_leak_tight, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_ok,
            )
        self.assertEqual(ctx_sf.exception.code, "BOUND_EXCEEDED")

        # GRAM-ESC-BYPASS-2: reject unbound/decoy/bound-swapped/tampered Gram reports (kills EVERY guard & boundary!)
        with self.assertRaises(mod.GramCertError) as ctx_gm:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h, verified_gram_report="bad",  # type: ignore[arg-type]
            )
        self.assertEqual(ctx_gm.exception.code, "INVALID_GRAM_REPORT")

        # Decoy adapter_id replay
        gram_decoy = mod.certify_stacked_mde_gram_exact(
            [{"adapter_id": "decoy", "B_int": [[1]], "A_int": [[1]], "scale_div": 1}],
            max_frobenius_sq=(999, 1), max_spectral_norm_sq=(999, 1),
        )
        with self.assertRaises(mod.GramCertError) as ctx_da:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_decoy,
            )
        self.assertEqual(ctx_da.exception.code, "GRAM_ADAPTER_MISMATCH")

        # G_B / G_A dimension mismatch
        with self.assertRaises(mod.GramCertError) as ctx_dm:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
                verified_gram_report={**gram_ok, "G_A_int": [[1]]},
            )
        self.assertEqual(ctx_dm.exception.code, "GRAM_DIM_MISMATCH")

        # Non-PSD Gram factor G_B or G_A
        with self.assertRaises(mod.GramCertError) as ctx_np:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
                verified_gram_report={**gram_ok, "G_B_int": [[-1, 0], [0, 1]]},
            )
        self.assertEqual(ctx_np.exception.code, "GRAM_FACTOR_NOT_PSD")

        # Bad adapter_block_slices count, malformed entry, Frobenius mismatch, incomplete coverage
        with self.assertRaises(mod.GramCertError) as ctx_sl0:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
                verified_gram_report={**gram_ok, "adapter_block_slices": [["a1", 0, 2]]},
            )
        self.assertEqual(ctx_sl0.exception.code, "GRAM_SLICES_INVALID")

        with self.assertRaises(mod.GramCertError) as ctx_sl1:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
                verified_gram_report={**gram_ok, "adapter_block_slices": [["a1", 0, 1], ["a1", 1, 2]]},
            )
        self.assertEqual(ctx_sl1.exception.code, "GRAM_SLICE_ENTRY_INVALID")

        # Forged small Gram matrices for large-Frobenius certificates (frob=10 vs Gram block frob=1)
        c1_big = _mk_cert("a1", self.h1, self.base_h, 1, 10, 10, 0, 0)
        c2_big = _mk_cert("a2", self.h2, self.base_h, 1, 10, 10, 0, 0)
        with self.assertRaises(mod.GramCertError) as ctx_bf:
            mod.verify_stack_hardened(
                [(c1_big, "a1", self.h1, 1, 1), (c2_big, "a2", self.h2, 1, 1)],
                b10, b2, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_ok,
            )
        self.assertEqual(ctx_bf.exception.code, "GRAM_ADAPTER_FROB_MISMATCH")

        # Incomplete slices (R=3 with slices covering only 0..2)
        with self.assertRaises(mod.GramCertError) as ctx_inc:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
                verified_gram_report={
                    **gram_ok,
                    "G_B_int": [[1, 0, 0], [0, 1, 0], [0, 0, 0]],
                    "G_A_int": [[1, 0, 0], [0, 1, 0], [0, 0, 0]],
                },
            )
        self.assertEqual(ctx_inc.exception.code, "GRAM_SLICES_INCOMPLETE")

        # Recomputed Gram Frobenius exceeds tight joint_bounds.max_frobenius_sq = 1 (< 2)
        b_frob_tight = _mk_bounds((1, 1), (2, 1), (2, 1), (2, 1))
        with self.assertRaises(mod.GramCertError) as ctx_gf:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b_frob_tight, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_ok,
            )
        self.assertEqual(ctx_gf.exception.code, "GRAM_FROB_EXCEEDS_JOINT")

        # Missing / non-mapping max_spectral_norm_sq in report
        with self.assertRaises(mod.GramCertError) as ctx_sc:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
                verified_gram_report={**gram_ok, "max_spectral_norm_sq": "bad"},
            )
        self.assertEqual(ctx_sc.exception.code, "GRAM_SPEC_CAP_INVALID")

        # Bound-swap attack: report certified at looser spectral cap (999/1) vs tight joint_bounds (2/1)
        gram_loose_spec = mod.certify_stacked_mde_gram_exact(
            adapters, max_frobenius_sq=(2, 1), max_spectral_norm_sq=(999, 1)
        )
        with self.assertRaises(mod.GramCertError) as ctx_bs:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_loose_spec,
            )
        self.assertEqual(ctx_bs.exception.code, "GRAM_SPEC_CAP_EXCEEDS_JOINT")

        # Spoofed max_spectral_norm_sq label on a looser Q_stack PSD certificate -> recomputed expected_Q fails!
        with self.assertRaises(mod.GramCertError) as ctx_sp:
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h,
                verified_gram_report={**gram_loose_spec, "max_spectral_norm_sq": {"num": 1, "den": 1, "exact": "1/1"}},
            )
        self.assertEqual(ctx_sp.exception.code, "CERT_MISMATCH")

        gram_bad = mod.certify_stacked_mde_gram_exact(adapters, max_frobenius_sq=(1, 1), max_spectral_norm_sq=(1, 2))
        self.assertFalse(gram_bad["frobenius_certified"])
        self.assertFalse(gram_bad["spectral_certified"])
        with self.assertRaises(mod.GramCertError):
            mod.verify_stack_hardened(
                [(c1, "a1", self.h1, 1, 1), (c2, "a2", self.h2, 1, 1)],
                b2, b2, expected_base_weights_sha256=self.base_h, verified_gram_report=gram_bad,
            )

        # Stacked Gram input refusal guards
        with self.assertRaises(mod.GramCertError) as ctx_rk:
            mod.certify_stacked_mde_gram_exact(
                [{"adapter_id": "a1", "B_int": [[1, 2]], "A_int": [[1]]}],
                max_frobenius_sq=(1, 1),
                max_spectral_norm_sq=(1, 1),
            )
        self.assertEqual(ctx_rk.exception.code, "FACTOR_RANK_MISMATCH")
        for bad_ad in (
            [],
            [123],
            [{"adapter_id": "", "B_int": [[1]], "A_int": [[1]]}],
            [
                {"adapter_id": "a1", "B_int": [[1]], "A_int": [[1]]},
                {"adapter_id": "a1", "B_int": [[1]], "A_int": [[1]]},
            ],
            [
                {"adapter_id": "a1", "B_int": [[1]], "A_int": [[1]]},
                {"adapter_id": "a2", "B_int": [[1], [0]], "A_int": [[1]]},
            ],
        ):
            with self.assertRaises(mod.GramCertError):
                mod.certify_stacked_mde_gram_exact(bad_ad, max_frobenius_sq=(1, 1), max_spectral_norm_sq=(1, 1))  # type: ignore[arg-type]


class TestMomentConeAndBlindDriftAndSignedTree(unittest.TestCase):
    def test_moment_cone_rh4_and_ropt(self) -> None:
        # Strict Fraction return on int inputs
        r0 = mod.r_opt_exact_strict(1, 0, 2, 0)
        self.assertIsInstance(r0, Fraction)
        self.assertEqual(r0, Fraction(1, 2))
        self.assertEqual(mod.r_opt_exact_strict(0, 1, 2, 0), Fraction(0, 1))
        self.assertEqual(mod.r_opt_exact_strict(1, 2, 5, 1), Fraction(1, 1))
        self.assertEqual(mod.r_opt_exact_strict(1, 2, 2, 1), Fraction(0, 1))
        self.assertEqual(mod.r_opt_exact_strict(1, 0, 10, 5), Fraction(0, 1))

        # Indefinite counterexample H = diag(3, -2), rank(P) = 1, b = 0: S1*S3 = 19 < 169 = S2^2
        ce = mod.r_h4_stieltjes_sound(1, 13, 19, 97, 0)
        self.assertFalse(ce["moment_cone_valid"])
        self.assertLessEqual(Fraction(ce["best_lower_bound"]["num"], ce["best_lower_bound"]["den"]), Fraction(1, 1))
        self.assertEqual(ce["certified_min_rank"], 1)

        # PSD H = diag(10, 1, 1) -> cone valid, R_H4 strictly beats R_opt
        psd = mod.r_h4_stieltjes_sound(12, 102, 1002, 10002, 0)
        self.assertTrue(psd["moment_cone_valid"])
        self.assertGreater(Fraction(psd["kkt_c1"]["num"], psd["kkt_c1"]["den"]), 0)
        self.assertLessEqual(Fraction(psd["kkt_c2"]["num"], psd["kkt_c2"]["den"]), 0)
        self.assertGreater(
            Fraction(psd["R_h4_sound"]["num"], psd["R_h4_sound"]["den"]),
            mod.r_opt_exact_strict(12, 0, 102, 0),
        )

    def test_blind_drift_singular_zero_and_refusals(self) -> None:
        # Singular G_kk breach & safe
        Jk = [[1, 0, 0], [2, 0, 0]]
        Jo = [[1, 0, 0], [0, 3, 4]]
        br = mod.certify_blind_drift_with_witness(Jk, Jo, tau=(10, 1), scale_div=1)
        self.assertTrue(br["G_known_singular"])
        self.assertEqual(br["n_unsafe_blind_directions"], 1)
        self.assertTrue(br["haynsworth_schur_agree"])
        self.assertTrue(br["witness_verification"]["verified"])

        sf = mod.certify_blind_drift_with_witness(Jk, Jo, tau=(25, 1), scale_div=1)
        self.assertTrue(sf["blind_drift_certified_le_tau"])
        self.assertIsNone(sf["witness_dw_int"])

        # Zero J_known (rank 0) breach
        br0 = mod.certify_blind_drift_with_witness([[0, 0]], [[3, 4]], tau=(10, 1), scale_div=1)
        self.assertEqual(br0["rank_G_known"], 0)
        self.assertTrue(br0["witness_verification"]["verified"])

        # Witness verifier negative controls (assert exact error codes to kill every guard + boundary cmp)
        with self.assertRaises(mod.GramCertError) as ctx_cm:
            mod.verify_blind_drift_witness_exact([[1, 0]], [[1, 0, 0]], [0, 1], tau=(1, 1))
        self.assertEqual(ctx_cm.exception.code, "JACOBIAN_COL_MISMATCH")
        with self.assertRaises(mod.GramCertError) as ctx_dw:
            mod.verify_blind_drift_witness_exact(Jk, Jo, [0, True, 4], tau=(1, 1))
        self.assertEqual(ctx_dw.exception.code, "INVALID_DW")
        with self.assertRaises(mod.GramCertError) as ctx_zw:
            mod.verify_blind_drift_witness_exact(Jk, Jo, [0, 0, 0], tau=(1, 1))
        self.assertEqual(ctx_zw.exception.code, "ZERO_WITNESS")
        with self.assertRaises(mod.GramCertError) as ctx_nb:
            mod.verify_blind_drift_witness_exact(Jk, Jo, [1, 3, 4], tau=(1, 1))  # not blind!
        self.assertEqual(ctx_nb.exception.code, "NOT_BLIND")
        # Exact boundary equality: ||Jo dw||^2 / ||dw||^2 == 25 == tau -> must REJECT (strict >)
        with self.assertRaises(mod.GramCertError) as ctx_bt:
            mod.verify_blind_drift_witness_exact(Jk, Jo, [0, 3, 4], tau=(25, 1))
        self.assertEqual(ctx_bt.exception.code, "WITNESS_BELOW_TAU")
        # Col mismatch in certifier
        with self.assertRaises(mod.GramCertError) as ctx_ccm:
            mod.certify_blind_drift_with_witness([[1, 0]], [[1, 0, 0]], tau=(1, 1))
        self.assertEqual(ctx_ccm.exception.code, "JACOBIAN_COL_MISMATCH")

    def test_signed_tree_and_refusals(self) -> None:
        tree = {
            "kind": "block_sum",
            "children": [
                {"kind": "leaf", "M": [[2, 0], [0, -1]]},
                {
                    "kind": "schur_couple",
                    "A": {"kind": "leaf", "M": [[2, 2], [2, 2]]},
                    "B": [[2], [2]],
                    "C": {"kind": "leaf", "M": [[5]]},
                },
            ],
        }
        ev = mod.evaluate_signed_tree_inertia(tree)
        flat = mod.materialize_signed_tree(tree)
        self.assertEqual(ev["inertia"], list(mod.bareiss_symmetric_inertia_exact(flat)["inertia"]))
        self.assertEqual(ev["inertia"], list(mod.faddeev_leverrier_inertia_exact(flat)))

        # Negative controls: col(B) not in col(A), bad kinds, bad dims, empty block_sum
        bad_range = {
            "kind": "schur_couple",
            "A": {"kind": "leaf", "M": [[1, 1], [1, 1]]},
            "B": [[1], [0]],
            "C": {"kind": "leaf", "M": [[2]]},
        }
        with self.assertRaises(mod.GramCertError):
            mod.evaluate_signed_tree_inertia(bad_range)

        for bad_node in (
            "not-a-dict",
            {"kind": "unknown"},
            {"kind": "block_sum", "children": []},
            {
                "kind": "schur_couple",
                "A": {"kind": "leaf", "M": [[1]]},
                "B": [[1], [2]],
                "C": {"kind": "leaf", "M": [[1]]},
            },
        ):
            with self.assertRaises(mod.GramCertError):
                mod.materialize_signed_tree(bad_node)  # type: ignore[arg-type]
            with self.assertRaises(mod.GramCertError):
                mod.evaluate_signed_tree_inertia(bad_node)  # type: ignore[arg-type]

    def test_certificate_zero_float_and_cli(self) -> None:
        cert = mod.build_audit_certificate(standalone=True)
        _assert_no_floats(cert)
        self.assertTrue(cert["certificate"]["signed_tree_multifrontal_audit052"]["triple_oracle_exact_agreement"])
        self.assertTrue(cert["certificate"]["moment_cone_rh4_upgrade"]["indefinite_counterexample_H_diag_3_neg2"]["soundness_holds"])
        self.assertTrue(cert["certificate"]["moment_cone_rh4_upgrade"]["psd_strict_gain_H_diag_10_1_1"]["strictly_beats_R_opt"])
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(mod._inspect_live_clones_readonly(Path(td)), {"live_clones_present": False})
            out_path = Path(td) / "cert.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = mod.main(["--standalone", "--write-cert", str(out_path)])
            self.assertEqual(rc, 0)
            parsed = json.loads(out_path.read_text(encoding="utf-8"))
            _assert_no_floats(parsed)
            self.assertEqual(parsed["certificate_sha256"], cert["certificate_sha256"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
