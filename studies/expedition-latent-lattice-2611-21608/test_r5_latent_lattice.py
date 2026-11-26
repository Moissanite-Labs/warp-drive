#!/usr/bin/env python3
"""
R1-R5 Mutation-Killing & Dual-Oracle Verification Suite for AUDIT-072
(`latent_lattice_audit.py`).

Safe under `python3 -I -B`, `python3 -I -O -B`, `python3 -I -B -W error`, `python3 -I -O -B -W error`.
Zero external dependencies, zero bare asserts, zero floats in certificates.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import random
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import latent_lattice_audit as mod  # noqa: E402


def _assert_no_floats(obj: object, path: str = "root") -> None:
    if isinstance(obj, float):
        raise AssertionError(f"float leaked at {path}: {obj!r}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            _assert_no_floats(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            _assert_no_floats(v, f"{path}[{i}]")


def _valid_j3_ckpt_and_flags() -> tuple[dict[str, object], dict[str, object], str]:
    r0 = hashlib.sha256(b"test-r0-seed").hexdigest()
    ckpt: dict[str, object] = {
        "has_ssm_recurrent": True,
        "has_horizontal_lattice": True,
        "lattice_early_layers": 1,
        "lattice_layers": 20,
        "lattice_late_layers": 1,
        "lattice_width": 256,
        "has_vstream": True,
        "has_input_injection": True,
        "has_jacobi_refiner": True,
        "jacobi_train_sweeps": 3,
        "n_capability_banks": 4,
        "r0_sha256": r0,
    }
    flags: dict[str, object] = {
        "has_horizontal_lattice": True,
        "lattice_flush_supported": True,
        "jacobi_infer_mode": "parallel_sweeps",
        "jacobi_infer_sweeps": 3,
        "lattice_scan_precision": "fp32",
        "lattice_norm_mode": "per_bank_rmsnorm",
    }
    return ckpt, flags, r0


def _valid_4bank_slot(sid: int, r0_sha: str) -> dict[str, object]:
    return {
        "id": sid,
        "is_processing": False,
        "banks_confirmed": list(mod.ALL_4_STATE_BANKS),
        "state_banks": {
            mod.STATE_BANK_KV: {"tainted": False, "tokens_or_layers": 0, "active_lora_ids": []},
            mod.STATE_BANK_SSM: {"tainted": False, "tokens_or_layers": 0, "active_lora_ids": []},
            mod.STATE_BANK_LATTICE: {
                "tainted": False,
                "tokens_or_layers": 0,
                "active_lora_ids": [],
                "reset_mode": "learned_r0_restore",
                "r0_sha256": r0_sha,
            },
            mod.STATE_BANK_JACOBI: {"tainted": False, "tokens_or_layers": 0, "active_lora_ids": []},
        },
    }


class TestPrimitivesAndDualOracles(unittest.TestCase):
    def test_primitive_validators_and_boundaries(self) -> None:
        self.assertEqual(mod.require_exact_int(0, "x", allow_zero=True), 0)
        self.assertEqual(mod.require_exact_int(1, "x", allow_zero=False), 1)
        for bad in (True, 1.0, "1", None):
            with self.assertRaises(mod.LatticeAuditError) as ctx:
                mod.require_exact_int(bad, "x")
            self.assertEqual(ctx.exception.code, "INVALID_INT")
        with self.assertRaises(mod.LatticeAuditError) as ctx_neg:
            mod.require_exact_int(-1, "x", allow_zero=True)
        self.assertEqual(ctx_neg.exception.code, "NEGATIVE_INT")
        with self.assertRaises(mod.LatticeAuditError) as ctx_z:
            mod.require_exact_int(0, "x", allow_zero=False)
        self.assertEqual(ctx_z.exception.code, "NONPOSITIVE_INT")

        self.assertIs(mod.require_exact_bool(True, "b"), True)
        self.assertIs(mod.require_exact_bool(False, "b"), False)
        for bad_b in (1, 0, "false", None):
            with self.assertRaises(mod.LatticeAuditError) as ctx_b:
                mod.require_exact_bool(bad_b, "b")
            self.assertEqual(ctx_b.exception.code, "INVALID_BOOL")

        self.assertEqual(mod.require_exact_rational(3, "q"), Fraction(3, 1))
        self.assertEqual(mod.require_exact_rational(Fraction(1, 2), "q"), Fraction(1, 2))
        for bad_q in (True, 0.5, "1/2"):
            with self.assertRaises(mod.LatticeAuditError) as ctx_q:
                mod.require_exact_rational(bad_q, "q")
            self.assertEqual(ctx_q.exception.code, "INVALID_RATIONAL")

        good_sha = "a" * 64
        self.assertEqual(mod.require_sha256_hex(good_sha, "h"), good_sha)
        for bad_sha in ("a" * 64 + "\n", "A" * 64, "a" * 63, 123):
            with self.assertRaises(mod.LatticeAuditError) as ctx_h:
                mod.require_sha256_hex(bad_sha, "h")
            self.assertEqual(ctx_h.exception.code, "INVALID_SHA256")

    def test_bareiss_vs_faddeev_dual_oracle(self) -> None:
        for bad, code in (
            ([], "EMPTY_MATRIX"),
            ([[1, 2]], "BAD_MATRIX_SHAPE"),
            ([[1.0]], "NON_INT_ENTRY"),
            ([[True]], "NON_INT_ENTRY"),
            ([[1, 2], [3, 1]], "ASYMMETRIC"),
        ):
            with self.assertRaises(mod.LatticeAuditError) as ctx:
                mod.require_symmetric_int_matrix(bad, "M")
            self.assertEqual(ctx.exception.code, code)

        cases = [
            [[0, 0], [0, 0]],
            [[0, 3], [3, 0]],
            [[0, 0, 5], [0, 0, 0], [5, 0, 0]],
            [[2, 1, 0, 0], [1, 2, 0, 0], [0, 0, 0, 4], [0, 0, 4, 0]],
        ]
        rng = random.Random(20261122)
        for _ in range(20):
            n = rng.randint(1, 5)
            M = [[0] * n for _ in range(n)]
            for i in range(n):
                for j in range(i, n):
                    v = rng.randint(-4, 4)
                    M[i][j] = M[j][i] = v
            cases.append(M)
        for M in cases:
            self.assertEqual(mod.bareiss_symmetric_inertia_exact(M), mod.faddeev_leverrier_inertia_exact(M))


class TestPillarsOneThroughFour(unittest.TestCase):
    def test_pillar_1_block_schur_and_vstream(self) -> None:
        res = mod.verify_pillar_1_block_schur_and_vstream()
        j0 = res["j0_base"]
        self.assertEqual(j0["schur_det"]["exact"], "1/1")
        self.assertTrue(j0["lower_triangular_exact"])
        self.assertTrue(j0["eigenvalues_equal_gates"])
        self.assertTrue(j0["dual_oracles_agree"])
        self.assertTrue(j0["non_contractive_despite_rho_lt_1"])
        self.assertEqual(j0["inertia_I_minus_TtT_bareiss"], [2, 1, 0])
        self.assertEqual(j0["unit_bottom_taint_t1_norm2"]["exact"], "27/8")
        self.assertEqual(j0["unit_bottom_taint_t2_norm2"]["exact"], "1215/128")
        self.assertEqual(j0["unit_bottom_taint_peak_step"], 6)
        self.assertEqual(j0["unit_bottom_taint_peak_norm2"]["exact"], "203541903/8388608")
        self.assertTrue(res["vstream_preserves_eigenvalues"])
        self.assertTrue(res["vstream_amplifies_transient_peak"])

        # Refusal & boundary checks for build_2d_lattice_block_schur
        with self.assertRaises(mod.LatticeAuditError) as ctx_len:
            mod.build_2d_lattice_block_schur([Fraction(1, 2), Fraction(1, 2)])
        self.assertEqual(ctx_len.exception.code, "BAD_GATES_LEN")
        for bad_g in (Fraction(0), Fraction(1), Fraction(-1, 2)):
            with self.assertRaises(mod.LatticeAuditError) as ctx_g:
                mod.build_2d_lattice_block_schur([bad_g, Fraction(1, 2), Fraction(1, 2)])
            self.assertEqual(ctx_g.exception.code, "GATE_OUT_OF_RANGE")
        with self.assertRaises(mod.LatticeAuditError) as ctx_vs:
            mod.build_2d_lattice_block_schur([Fraction(1, 2)] * 3, vstream_gain=Fraction(-1, 4))
        self.assertEqual(ctx_vs.exception.code, "NEGATIVE_VSTREAM_GAIN")

    def test_pillar_2_j3_feedback_and_divergence(self) -> None:
        res = mod.verify_j3_feedback_stability_and_divergence()
        self.assertEqual(res["f_crit_exact"]["exact"], "1/80")
        self.assertEqual(res["det_I_minus_T_at_f_crit"]["exact"], "0/1")
        self.assertEqual(res["det_I_minus_T_at_f_super"]["exact"], "-1/64")
        self.assertTrue(res["supercritical_has_real_eig_gt_1"])
        for key in ("subcritical_rollout", "supercritical_rollout"):
            self.assertTrue(res[key]["exact_agreement_t1_to_t3"])
            self.assertTrue(res[key]["t4_matches_closed_form_384_f6"])
        # Exact step boundaries n_steps=4 and n_steps=16 succeed; 3 and 17 fail
        self.assertTrue(mod.verify_j3_feedback_stability_and_divergence(n_steps=4)["supercritical_rollout"]["t4_matches_closed_form_384_f6"])
        self.assertTrue(mod.verify_j3_feedback_stability_and_divergence(n_steps=16)["supercritical_rollout"]["t4_matches_closed_form_384_f6"])
        for bad_s in (3, 17):
            with self.assertRaises(mod.LatticeAuditError) as ctx_s:
                mod.verify_j3_feedback_stability_and_divergence(n_steps=bad_s)
            self.assertEqual(ctx_s.exception.code, "STEPS_RANGE")
        for bad_fsub in (Fraction(0), Fraction(1, 80)):
            with self.assertRaises(mod.LatticeAuditError) as ctx_fs:
                mod.verify_j3_feedback_stability_and_divergence(f_sub=bad_fsub)
            self.assertEqual(ctx_fs.exception.code, "BAD_FSUB")
        with self.assertRaises(mod.LatticeAuditError) as ctx_fu:
            mod.verify_j3_feedback_stability_and_divergence(f_super=Fraction(1, 80))
        self.assertEqual(ctx_fu.exception.code, "BAD_FSUPER")

    def test_pillar_3_and_4_rollback_and_siliquant(self) -> None:
        r3 = mod.verify_4regime_rollback_and_learned_r0()
        self.assertGreater(Fraction(r3["regime_a_kv_ssm_only_err2"]["num"], r3["regime_a_kv_ssm_only_err2"]["den"]), 0)
        self.assertTrue(r3["regime_b_all_3_layers_recontaminated"])
        self.assertTrue(r3["regime_c_corrupts_clean_base_w0"])
        self.assertTrue(r3["regime_d_exact_zero_drift"])

        r4 = mod.verify_siliquant_horizontal_quantization_laws()
        self.assertTrue(r4["bf16_carry_scan_stagnation"]["bf16_permanently_frozen_at_1"])
        self.assertTrue(r4["bf16_carry_scan_stagnation"]["fp32_step1_zero_error"])
        self.assertTrue(r4["bf16_carry_scan_stagnation"]["exact_512_step_below_37pct"])
        self.assertTrue(r4["bf16_carry_scan_stagnation"]["bf16_512_step_rel_err_gt_170pct"])
        self.assertEqual(r4["global_vs_per_bank_rmsnorm"]["global_rmsnorm_scale_sq"]["exact"], "9/16")
        self.assertTrue(r4["global_vs_per_bank_rmsnorm"]["per_bank_eliminates_bleed"])
        self.assertTrue(r4["asymmetric_film_factor_leakage"]["asymmetry_verified"])
        self.assertTrue(r4["horizontal_dr256_outlier_masking"]["naive_admitted_under_alpha8"])
        self.assertEqual(r4["horizontal_dr256_outlier_masking"]["naive_rms_ratio_sq"]["exact"], "802160640/16779511")
        self.assertTrue(r4["horizontal_dr256_outlier_masking"]["siliquant_bulk_split_rejects"])
        self.assertEqual(r4["horizontal_dr256_outlier_masking"]["siliquant_bulk_split_ratio_sq"]["exact"], "1048576/3")

        # Exact boundaries for quantize_ieee_binary_exact and ieee_rounding_cell_width_exact
        self.assertEqual(mod.quantize_ieee_binary_exact(Fraction(0), 7), Fraction(0))
        self.assertEqual(mod.quantize_ieee_binary_exact(Fraction(-511, 512), 7), Fraction(-1, 1))
        self.assertEqual(mod.quantize_ieee_binary_exact(Fraction(3, 2), 1), Fraction(3, 2))
        self.assertEqual(mod.quantize_ieee_binary_exact(Fraction(3, 2), 52), Fraction(3, 2))
        self.assertEqual(mod.quantize_ieee_binary_exact(Fraction(1024, 1), 7), Fraction(1024, 1))
        self.assertEqual(mod.ieee_rounding_cell_width_exact(Fraction(1, 2), 1), Fraction(3, 16))
        self.assertEqual(mod.ieee_rounding_cell_width_exact(Fraction(-4096, 1), 7), Fraction(24, 1))
        self.assertEqual(mod.ieee_rounding_cell_width_exact(Fraction(3, 2), 52), Fraction(1, 1 << 52))
        with self.assertRaises(mod.LatticeAuditError) as ctx_m53:
            mod.quantize_ieee_binary_exact(Fraction(1, 1), 53)
        self.assertEqual(ctx_m53.exception.code, "MANTISSA_RANGE")
        with self.assertRaises(mod.LatticeAuditError) as ctx_w53:
            mod.ieee_rounding_cell_width_exact(Fraction(1, 1), 53)
        self.assertEqual(ctx_w53.exception.code, "MANTISSA_RANGE")
        with self.assertRaises(mod.LatticeAuditError) as ctx_wz:
            mod.ieee_rounding_cell_width_exact(Fraction(0, 1), 7)
        self.assertEqual(ctx_wz.exception.code, "ZERO_CELL_WIDTH")


class TestHardenedContractAnd4BankFlush(unittest.TestCase):
    def test_hardened_lattice_contract_all_refusal_paths(self) -> None:
        ckpt, flags, r0 = _valid_j3_ckpt_and_flags()
        ok = mod.validate_hardened_lattice_contract(ckpt, flags)
        self.assertTrue(ok["valid"])
        self.assertEqual(ok["required_state_banks"], list(mod.ALL_4_STATE_BANKS))
        self.assertEqual(ok["e_l_d_split"], [1, 20, 1])

        # Disabled lattice valid case
        dis_ckpt = {
            "has_ssm_recurrent": False,
            "has_horizontal_lattice": False,
            "lattice_early_layers": 0,
            "lattice_layers": 0,
            "lattice_late_layers": 0,
            "lattice_width": 0,
            "has_vstream": False,
            "has_input_injection": False,
            "has_jacobi_refiner": False,
            "jacobi_train_sweeps": 0,
            "n_capability_banks": 1,
        }
        dis_flags = {
            "has_horizontal_lattice": False,
            "lattice_flush_supported": False,
            "jacobi_infer_mode": "none",
            "jacobi_infer_sweeps": 0,
            "lattice_scan_precision": "fp32",
            "lattice_norm_mode": "per_bank_rmsnorm",
        }
        self.assertEqual(mod.validate_hardened_lattice_contract(dis_ckpt, dis_flags)["required_state_banks"], [mod.STATE_BANK_KV])

        # Non-Jacobi enabled + single-bank global_rmsnorm allowed (tests exact boundary n_cap_banks=1)
        c_noj = dict(ckpt, has_jacobi_refiner=False, jacobi_train_sweeps=0, n_capability_banks=1)
        f_noj = dict(flags, jacobi_infer_mode="none", jacobi_infer_sweeps=0, lattice_norm_mode="global_rmsnorm")
        self.assertEqual(
            mod.validate_hardened_lattice_contract(c_noj, f_noj)["required_state_banks"],
            [mod.STATE_BANK_KV, mod.STATE_BANK_SSM, mod.STATE_BANK_LATTICE],
        )

        # Sequential rollout on J3 allowed ONLY with explicit waiver, exact boundary jacobi_train_sweeps=2
        c_j2 = dict(ckpt, jacobi_train_sweeps=2)
        f_seq_ok = dict(flags, jacobi_infer_mode="sequential_rollout", jacobi_infer_sweeps=0, allow_jacobi_sequential_mismatch=True)
        self.assertTrue(mod.validate_hardened_lattice_contract(c_j2, f_seq_ok)["valid"])

        # Exhaustive refusal tests covering every single guard
        with self.assertRaises(mod.LatticeAuditError) as ctx_t1:
            mod.validate_hardened_lattice_contract([], flags)  # type: ignore[arg-type]
        self.assertEqual(ctx_t1.exception.code, "BAD_CKPT_TYPE")
        with self.assertRaises(mod.LatticeAuditError) as ctx_t2:
            mod.validate_hardened_lattice_contract(ckpt, [])  # type: ignore[arg-type]
        self.assertEqual(ctx_t2.exception.code, "BAD_FLAGS_TYPE")

        refusal_cases: list[tuple[dict[str, object], dict[str, object], str]] = [
            (ckpt, dict(flags, has_horizontal_lattice=False), "LATTICE_FLAG_MISMATCH"),
            (ckpt, dict(flags, jacobi_infer_mode="bad"), "INVALID_JACOBI_MODE"),
            (ckpt, dict(flags, lattice_scan_precision="fp8"), "INVALID_SCAN_PRECISION"),
            (ckpt, dict(flags, lattice_norm_mode="layernorm"), "INVALID_NORM_MODE"),
            (ckpt, dict(flags, allow_jacobi_sequential_mismatch="not-a-bool"), "INVALID_BOOL"),
            (dict(dis_ckpt, lattice_width=16), dis_flags, "NONZERO_LATTICE_WHEN_DISABLED"),
            (dis_ckpt, dict(dis_flags, jacobi_infer_mode="sequential_rollout"), "JACOBI_WHEN_DISABLED"),
            (dict(ckpt, lattice_width=0), flags, "INVALID_LATTICE_DIMS"),
            (dict(ckpt, lattice_layers=0), flags, "INVALID_LATTICE_DIMS"),
            (ckpt, dict(flags, lattice_flush_supported=False), "LATTICE_FLUSH_UNSUPPORTED"),
            (ckpt, dict(flags, lattice_scan_precision="bf16"), "UNSAFE_SCAN_PRECISION"),
            (ckpt, dict(flags, lattice_norm_mode="global_rmsnorm"), "GLOBAL_RMSNORM_BLEED"),
            (dict(ckpt, jacobi_train_sweeps=1), dict(flags, jacobi_infer_sweeps=1), "BAD_JACOBI_TRAIN_SWEEPS"),
            (ckpt, dict(flags, jacobi_infer_mode="none", jacobi_infer_sweeps=0), "JACOBI_MODE_MISSING"),
            (ckpt, dict(flags, jacobi_infer_sweeps=2), "JACOBI_SWEEP_DRIFT"),
            (ckpt, dict(flags, jacobi_infer_mode="sequential_rollout", jacobi_infer_sweeps=1, allow_jacobi_sequential_mismatch=True), "SEQ_SWEEPS_NONZERO"),
            (ckpt, dict(flags, jacobi_infer_mode="sequential_rollout", jacobi_infer_sweeps=0), "JACOBI_ROLLOUT_DRIFT"),
            (dict(ckpt, has_jacobi_refiner=False, jacobi_train_sweeps=0), flags, "SPURIOUS_JACOBI_CONFIG"),
        ]
        for c_bad, f_bad, exp_code in refusal_cases:
            with self.assertRaises(mod.LatticeAuditError) as ctx:
                mod.validate_hardened_lattice_contract(c_bad, f_bad)
            self.assertEqual(ctx.exception.code, exp_code)

    def test_verify_4bank_lattice_flush_all_refusal_paths(self) -> None:
        _, _, r0 = _valid_j3_ckpt_and_flags()
        ok = mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [_valid_4bank_slot(0, r0)], expected_r0_sha256=r0)
        self.assertTrue(ok["verified_clean"])

        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush([], [0], [_valid_4bank_slot(0, r0)])
        self.assertEqual(ctx.exception.code, "EMPTY_REQ_BANKS")
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(["bogus_bank"], [0], [_valid_4bank_slot(0, r0)])
        self.assertEqual(ctx.exception.code, "UNKNOWN_REQ_BANK")
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [], [_valid_4bank_slot(0, r0)], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "EMPTY_PRE_SLOTS")
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0, 0], [_valid_4bank_slot(0, r0)], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "DUPLICATE_PRE_SLOT_ID")
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "EMPTY_POST_SLOTS")
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(
                mod.ALL_4_STATE_BANKS, [0], [_valid_4bank_slot(0, r0), _valid_4bank_slot(0, r0)], expected_r0_sha256=r0
            )
        self.assertEqual(ctx.exception.code, "DUPLICATE_SLOT_ID")
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], ["not_a_dict"], expected_r0_sha256=r0)  # type: ignore[list-item]
        self.assertEqual(ctx.exception.code, "BAD_SLOT_ENTRY")

        s_proc = _valid_4bank_slot(0, r0)
        s_proc["is_processing"] = True
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_proc], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "SLOT_STILL_PROCESSING")

        s_badc = _valid_4bank_slot(0, r0)
        s_badc["banks_confirmed"] = "kv_cache"
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_badc], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "BAD_BANKS_CONFIRMED")

        s_unkc = _valid_4bank_slot(0, r0)
        s_unkc["banks_confirmed"] = ["unknown_bank"]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_unkc], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "UNKNOWN_CONFIRMED_BANK")

        s_miss_j = _valid_4bank_slot(0, r0)
        s_miss_j["banks_confirmed"] = [mod.STATE_BANK_KV, mod.STATE_BANK_SSM, mod.STATE_BANK_LATTICE]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_miss_j], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "UNCONFIRMED_BANK_FLUSH")

        s_nobanks = _valid_4bank_slot(0, r0)
        s_nobanks["state_banks"] = []
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_nobanks], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "MISSING_STATE_BANKS")

        s_miss_b = _valid_4bank_slot(0, r0)
        del s_miss_b["state_banks"][mod.STATE_BANK_JACOBI]  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_miss_b], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "MISSING_BANK_STATUS")

        # LLLM-BYPASS-01 regressions: extra tainted bank & unknown bank & non-mapping status
        s_extra_taint = _valid_4bank_slot(0, r0)
        s_extra_taint["state_banks"][mod.STATE_BANK_JACOBI] = {"tainted": True, "tokens_or_layers": 99, "active_lora_ids": [7]}  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush([mod.STATE_BANK_KV], [0], [s_extra_taint])
        self.assertEqual(ctx.exception.code, "BANK_NOT_CLEAN")

        s_unk_b = _valid_4bank_slot(0, r0)
        s_unk_b["state_banks"]["rogue_bank"] = {"tainted": False, "tokens_or_layers": 0, "active_lora_ids": []}  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_unk_b], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "UNKNOWN_STATE_BANK")

        s_bad_bmap = _valid_4bank_slot(0, r0)
        s_bad_bmap["state_banks"][mod.STATE_BANK_KV] = "not_a_mapping"  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_bad_bmap], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "BAD_BANK_STATUS")

        s_bad_act = _valid_4bank_slot(0, r0)
        s_bad_act["state_banks"][mod.STATE_BANK_KV]["active_lora_ids"] = "none"  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_bad_act], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "BAD_ACTIVE_LORA_IDS")

        s_taint = _valid_4bank_slot(0, r0)
        s_taint["state_banks"][mod.STATE_BANK_JACOBI]["tainted"] = True  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_taint], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "BANK_NOT_CLEAN")

        s_neg_cnt = _valid_4bank_slot(0, r0)
        s_neg_cnt["state_banks"][mod.STATE_BANK_LATTICE]["tokens_or_layers"] = -1  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_neg_cnt], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "NEGATIVE_INT")

        s_bad_rmode = _valid_4bank_slot(0, r0)
        s_bad_rmode["state_banks"][mod.STATE_BANK_LATTICE]["reset_mode"] = "unknown"  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_bad_rmode], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "INVALID_RESET_MODE")

        s_zmode = _valid_4bank_slot(0, r0)
        s_zmode["state_banks"][mod.STATE_BANK_LATTICE]["reset_mode"] = "zero_fill"  # type: ignore[index]
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_zmode], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "ZERO_FILL_CORRUPTS_R0")

        s_bad_r0 = _valid_4bank_slot(0, "b" * 64)
        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0], [s_bad_r0], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "R0_SHA256_MISMATCH")

        with self.assertRaises(mod.LatticeAuditError) as ctx:
            mod.verify_4bank_lattice_flush(mod.ALL_4_STATE_BANKS, [0, 1], [_valid_4bank_slot(0, r0)], expected_r0_sha256=r0)
        self.assertEqual(ctx.exception.code, "SLOT_SET_MISMATCH")


class TestStagingAndCliZeroFloat(unittest.TestCase):
    def test_staging_helpers_and_cli_zero_float(self) -> None:
        cert = mod.build_audit_certificate(standalone=True)
        _assert_no_floats(cert)
        self.assertTrue(cert["certificate"]["arxiv_table_exact_arithmetic"]["table5_means_exact_match"])

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            self.assertEqual(mod._inspect_live_staging_readonly(root, None), {"staging_present": False})
            self.assertIsNone(mod._resolve_git_head_readonly(root / ".git"))

            # Test detached, loose-ref, packed-ref, and dangling-ref git HEAD resolution
            gdir = root / "g1"
            gdir.mkdir()
            (gdir / "HEAD").write_text("1" * 40 + "\n", encoding="utf-8")
            self.assertEqual(mod._resolve_git_head_readonly(gdir), "1" * 40)

            (gdir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            self.assertIsNone(mod._resolve_git_head_readonly(gdir))

            (gdir / "packed-refs").write_text("# comment\n" + "2" * 40 + " refs/heads/main\n", encoding="utf-8")
            self.assertEqual(mod._resolve_git_head_readonly(gdir), "2" * 40)

            (gdir / "refs" / "heads").mkdir(parents=True)
            (gdir / "refs" / "heads" / "main").write_text("3" * 40 + "\n", encoding="utf-8")
            self.assertEqual(mod._resolve_git_head_readonly(gdir), "3" * 40)

            # LLLM-BYPASS-02 regressions: reject path traversal (../secret.txt) and non-40-hex SHAs
            (root / "secret.txt").write_text("4" * 40 + "\n", encoding="utf-8")
            (gdir / "HEAD").write_text("ref: ../secret.txt\n", encoding="utf-8")
            self.assertIsNone(mod._resolve_git_head_readonly(gdir))
            (gdir / "HEAD").write_text("ref: refs/heads/../../secret.txt\n", encoding="utf-8")
            self.assertIsNone(mod._resolve_git_head_readonly(gdir))
            (gdir / "HEAD").write_text("not-a-40-hex-sha\n", encoding="utf-8")
            self.assertIsNone(mod._resolve_git_head_readonly(gdir))

            # CLI standalone write-cert parity & zero floats
            out_p = root / "cert.json"
            buf = io.StringIO()
            with redirect_stdout(buf):
                rc = mod.main(["--standalone", "--write-cert", str(out_p)])
            self.assertEqual(rc, 0)
            parsed = json.loads(out_p.read_text(encoding="utf-8"))
            _assert_no_floats(parsed)
            self.assertEqual(parsed["certificate_sha256"], cert["certificate_sha256"])


if __name__ == "__main__":
    suite = unittest.defaultTestLoader.loadTestsFromModule(sys.modules[__name__])
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    raise SystemExit(0 if result.wasSuccessful() else 1)
