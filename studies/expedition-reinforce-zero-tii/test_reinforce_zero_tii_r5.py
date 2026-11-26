#!/usr/bin/env python3
"""Adversarial R5 unit & mutation-killing test suite for reinforce_zero_tii_audit.py."""

from __future__ import annotations

from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))

import reinforce_zero_tii_audit as audit


def _has_float(obj: object) -> bool:
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_float(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_float(v) for v in obj)
    return False


class TestPureQMathPrimitives(unittest.TestCase):
    def test_exp_and_sqrt_rational_intervals_and_guards(self) -> None:
        self.assertEqual(audit.exp_rational_interval(Fraction(0, 1)), (Fraction(1, 1), Fraction(1, 1)))
        lo, hi = audit.exp_rational_interval(Fraction(1, 25), terms=12)
        self.assertGreater(lo, Fraction(104081, 100000))
        self.assertLess(hi, Fraction(104082, 100000))
        # Exact boundary terms=1, u=2 (< terms + 2 = 3)
        lo_b, hi_b = audit.exp_rational_interval(Fraction(2, 1), terms=1)
        self.assertLess(lo_b, hi_b)
        for bad_u, bad_t in (
            (1, 12),
            (0.04, 12),
            (Fraction(-1, 10), 12),
            (Fraction(1, 10), 0),
            (Fraction(1, 10), True),
            (Fraction(3, 1), 1),  # u == terms + 2 rejected
        ):
            with self.assertRaises(ValueError):
                audit.exp_rational_interval(bad_u, terms=bad_t)  # type: ignore[arg-type]

        # Exact perfect square vs irrational sqrt
        self.assertEqual(audit.sqrt_rational_interval(Fraction(9, 4)), (Fraction(3, 2), Fraction(3, 2)))
        s_lo, s_hi = audit.sqrt_rational_interval(Fraction(2, 1), precision_bits=20)
        self.assertLess(s_lo * s_lo, Fraction(2, 1))
        self.assertGreater(s_hi * s_hi, Fraction(2, 1))
        for bad_x, bad_p in (
            (2, 20),
            (2.0, 20),
            (Fraction(0, 1), 20),
            (Fraction(-1, 1), 20),
            (Fraction(2, 1), 0),
            (Fraction(2, 1), False),
        ):
            with self.assertRaises(ValueError):
                audit.sqrt_rational_interval(bad_x, precision_bits=bad_p)  # type: ignore[arg-type]

    def test_gaussian_tim_theorem_persistent_bias_and_guards(self) -> None:
        g0 = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(0, 1), eta=Fraction(3, 5), sigma=Fraction(1, 5), batch_size=1, steps=200
        )
        self.assertTrue(g0["stable_proven"])
        self.assertFalse(g0["unstable_proven"])
        self.assertEqual(g0["exact_zero_kappa"]["rho"], {"num": 22, "den": 25})
        self.assertEqual(g0["exact_zero_kappa"]["c_noise"], {"num": 9, "den": 250})
        self.assertEqual(g0["exact_zero_kappa"]["eta_max"], {"num": 2, "den": 3})
        self.assertEqual(g0["exact_zero_kappa"]["V_inf"], {"num": 3, "den": 10})
        self.assertFalse(g0["persistent_pos_strictly_worse"])

        g_hi = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(1, 5), eta=Fraction(3, 5), sigma=Fraction(1, 5), batch_size=1, steps=200
        )
        self.assertFalse(g_hi["stable_proven"])
        self.assertTrue(g_hi["unstable_proven"])
        self.assertIsNone(g_hi["V_inf_dec"])
        self.assertIsNone(g_hi["exact_zero_kappa"])
        self.assertEqual(g_hi["V_steps_sym_dec"][0][:5], "68.26")
        self.assertEqual(g_hi["V_steps_persistent_pos_dec"][0][:5], "73.74")
        self.assertEqual(g_hi["V_steps_persistent_neg_dec"][0][:5], "62.79")
        self.assertTrue(g_hi["persistent_pos_strictly_worse"])

        # Zero x0 boundary: persistent_pos_strictly_worse is False when x0 == 0
        g_zero_x0 = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(1, 5),
            eta=Fraction(3, 5),
            sigma=Fraction(1, 5),
            batch_size=1,
            steps=5,
            x0=Fraction(0, 1),
        )
        self.assertFalse(g_zero_x0["persistent_pos_strictly_worse"])

        # Exact rho == 1 linear-growth boundary (kappa=0, M=1, eta=2/3) & rho == q boundary (eta=1/3)
        g_linear = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(0, 1), eta=Fraction(2, 3), sigma=Fraction(1, 5), batch_size=1, steps=5
        )
        self.assertFalse(g_linear["stable_proven"])
        self.assertFalse(g_linear["unstable_proven"])
        self.assertEqual(g_linear["exact_zero_kappa"]["rho"], {"num": 1, "den": 1})

        g_eq_q = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(0, 1), eta=Fraction(1, 3), sigma=Fraction(1, 5), batch_size=1, steps=5
        )
        self.assertTrue(g_eq_q["stable_proven"])
        self.assertEqual(g_eq_q["exact_zero_kappa"]["rho"], {"num": 2, "den": 3})

        # RZ-BUG-01 regression (a): alternating q_mean < 0 (eta=3/2 > 1, even steps=2 & odd steps=3)
        # Must rigorously enclose SymPy exact V_2(+k)=0.080745074 & V_2(-k)=0.090630476
        g_alt_even = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(1, 2), eta=Fraction(3, 2), sigma=Fraction(1, 1), batch_size=1000, steps=2, terms=1
        )
        self.assertLessEqual(Fraction(g_alt_even["V_steps_persistent_pos_dec"][0]), Fraction("0.080745"))
        self.assertGreaterEqual(Fraction(g_alt_even["V_steps_persistent_pos_dec"][1]), Fraction("0.080746"))
        self.assertLessEqual(Fraction(g_alt_even["V_steps_persistent_neg_dec"][0]), Fraction("0.090630"))
        self.assertGreaterEqual(Fraction(g_alt_even["V_steps_persistent_neg_dec"][1]), Fraction("0.090631"))
        g_alt_odd = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(1, 2), eta=Fraction(3, 2), sigma=Fraction(1, 1), batch_size=1000, steps=3, terms=1
        )
        self.assertLessEqual(
            Fraction(g_alt_odd["V_steps_persistent_pos_dec"][0]),
            Fraction(g_alt_odd["V_steps_persistent_pos_dec"][1]),
        )
        self.assertGreaterEqual(Fraction(g_alt_odd["V_steps_persistent_neg_dec"][0]), Fraction(0, 1))

        # RZ-BUG-01 regression (b): nonnegative lower clamp on V_steps_persistent_neg_dec
        g_nonneg = audit.gaussian_tim_stability_analysis(
            kappa=Fraction(1, 1), eta=Fraction(1, 2), sigma=Fraction(1, 2), batch_size=1, steps=2, terms=1
        )
        self.assertGreaterEqual(Fraction(g_nonneg["V_steps_persistent_neg_dec"][0]), Fraction(0, 1))

        for kwargs in (
            {"kappa": 0, "eta": Fraction(3, 5), "sigma": Fraction(1, 5), "batch_size": 1, "steps": 5},
            {"kappa": Fraction(-1, 5), "eta": Fraction(3, 5), "sigma": Fraction(1, 5), "batch_size": 1, "steps": 5},
            {"kappa": Fraction(0, 1), "eta": Fraction(0, 1), "sigma": Fraction(1, 5), "batch_size": 1, "steps": 5},
            {"kappa": Fraction(0, 1), "eta": Fraction(2, 1), "sigma": Fraction(1, 5), "batch_size": 1, "steps": 5},
            {"kappa": Fraction(0, 1), "eta": Fraction(3, 5), "sigma": Fraction(0, 1), "batch_size": 1, "steps": 5},
            {"kappa": Fraction(0, 1), "eta": Fraction(3, 5), "sigma": Fraction(1, 5), "batch_size": 0, "steps": 5},
            {"kappa": Fraction(0, 1), "eta": Fraction(3, 5), "sigma": Fraction(1, 5), "batch_size": True, "steps": 5},
            {"kappa": Fraction(0, 1), "eta": Fraction(3, 5), "sigma": Fraction(1, 5), "batch_size": 1, "steps": 0},
            {"kappa": Fraction(0, 1), "eta": Fraction(3, 5), "sigma": Fraction(1, 5), "batch_size": 1, "steps": 5, "x0": Fraction(-1, 1)},
            {"kappa": Fraction(0, 1), "eta": Fraction(3, 5), "sigma": Fraction(1, 5), "batch_size": 1, "steps": 5, "x0": 1},
        ):
            with self.assertRaises(ValueError):
                audit.gaussian_tim_stability_analysis(**kwargs)  # type: ignore[arg-type]

    def test_variance_mismatch_and_guards(self) -> None:
        # Exact critical boundary gamma_sq == 1/2 (denom == 0) AND strictly below (49/100)
        for g_sq in (Fraction(1, 2), Fraction(49, 100)):
            v_inf = audit.gaussian_variance_mismatch_analysis(gamma_sq=g_sq, eta=Fraction(1, 100))
            self.assertTrue(v_inf["infinite_variance"])
            self.assertTrue(v_inf["unstable_proven"])
            self.assertFalse(v_inf["stable_proven"])

        v_ok = audit.gaussian_variance_mismatch_analysis(gamma_sq=Fraction(1, 1), eta=Fraction(3, 5))
        self.assertFalse(v_ok["infinite_variance"])
        self.assertTrue(v_ok["stable_proven"])
        self.assertEqual(v_ok["A_gamma_sq"], {"num": 9, "den": 1})

        v_34 = audit.gaussian_variance_mismatch_analysis(gamma_sq=Fraction(9, 16), eta=Fraction(3, 5))
        self.assertEqual(v_34["A_gamma_sq"], {"num": 4782969, "den": 512})
        self.assertTrue(v_34["unstable_proven"])

        for kwargs in (
            {"gamma_sq": Fraction(0, 1), "eta": Fraction(3, 5)},
            {"gamma_sq": 1, "eta": Fraction(3, 5)},
            {"gamma_sq": Fraction(1, 1), "eta": Fraction(0, 1)},
            {"gamma_sq": Fraction(1, 1), "eta": Fraction(2, 1)},
            {"gamma_sq": Fraction(1, 1), "eta": Fraction(3, 5), "batch_size": 0},
            {"gamma_sq": Fraction(1, 1), "eta": Fraction(3, 5), "batch_size": True},
        ):
            with self.assertRaises(ValueError):
                audit.gaussian_variance_mismatch_analysis(**kwargs)  # type: ignore[arg-type]


class TestDiscretePolicyAndTables(unittest.TestCase):
    def test_discrete_is_vs_sc_and_support_truncation(self) -> None:
        p = [Fraction(1, 2), Fraction(1, 4), Fraction(1, 4)]
        q_full = [Fraction(1, 20), Fraction(9, 20), Fraction(1, 2)]
        q_trunc = [Fraction(0, 1), Fraction(9, 19), Fraction(10, 19)]
        s = [Fraction(1, 1), Fraction(1, 1), Fraction(-3, 1)]
        a = [Fraction(10, 1), Fraction(-4, 1), Fraction(0, 1)]

        full = audit.discrete_policy_gradient_audit(p, q_full, a, s)
        self.assertTrue(full["support_complete"])
        self.assertTrue(full["is_unbiased"])
        self.assertTrue(full["sc_sign_reversed"])
        self.assertEqual(full["g_star"], {"num": 4, "den": 1})
        self.assertEqual(full["g_sc"], {"num": -13, "den": 5})
        self.assertEqual(full["g_is"], {"num": 4, "den": 1})
        self.assertEqual(full["var_unclipped_is"], {"num": 4376, "den": 9})

        trunc = audit.discrete_policy_gradient_audit(p, q_trunc, a, s)
        self.assertFalse(trunc["support_complete"])
        self.assertFalse(trunc["is_unbiased"])
        self.assertEqual(trunc["e_q_ws"], {"num": -1, "den": 2})
        self.assertEqual(trunc["g_is"], {"num": -1, "den": 1})

        # Opposite sign reversal branch (g_star < 0 and g_sc > 0)
        neg_a = [-x for x in a]
        full_neg = audit.discrete_policy_gradient_audit(p, q_full, neg_a, s)
        self.assertTrue(full_neg["sc_sign_reversed"])

        for bad_args in (
            ([Fraction(1, 1)], [Fraction(1, 1)], [Fraction(1, 1)], [Fraction(0, 1)]),
            (p, q_full[:2], a, s),
            ([Fraction(0, 1), Fraction(1, 1)], [Fraction(1, 2), Fraction(1, 2)], [Fraction(1, 1), Fraction(0, 1)], [Fraction(0, 1), Fraction(0, 1)]),
            (p, [Fraction(-1, 20), Fraction(11, 20), Fraction(1, 2)], a, s),
            (p, q_full, a, [Fraction(1, 1), Fraction(1, 1), Fraction(1, 1)]),  # E_p[s] != 0
            (p, q_full, [10, -4, 0], s),
        ):
            with self.assertRaises(ValueError):
                audit.discrete_policy_gradient_audit(*bad_args)  # type: ignore[arg-type]

    def test_verify_paper_tables(self) -> None:
        tables = audit.verify_paper_tables()
        self.assertEqual(tables["table1_rows_verified"], 10)
        self.assertTrue(tables["table1_all_within_0_01"])
        self.assertEqual(tables["table3_rows_verified"], 4)
        self.assertTrue(tables["table3_all_within_0_005"])
        self.assertEqual(tables["table4_osworld_gain"], {"num": 519, "den": 100})
        self.assertEqual(tables["table5_speedup_exact"], {"num": 16477, "den": 6855})
        self.assertEqual(tables["table6_osworld_step_overhead"], {"num": 6008, "den": 88417})
        self.assertEqual(tables["zero_mismatch_ds_v4_flash_loss"], {"num": 33, "den": 379})


class TestGovernanceBoundaryAndAdversarialBypasses(unittest.TestCase):
    def test_every_governance_invariant_and_redteam_bypass(self) -> None:
        base = audit._baseline_hardened_config()
        res = audit.evaluate_tii_governance_boundary(base)
        self.assertTrue(res["admitted"])
        self.assertEqual(res["reasons"], [])

        # Missing key / smuggled extra key / non-dict guard (RZ-BUG-03c)
        with self.assertRaises(ValueError):
            audit.evaluate_tii_governance_boundary([])  # type: ignore[arg-type]
        missing = dict(base)
        missing.pop("batch_invariant_mode")
        with self.assertRaises(ValueError):
            audit.evaluate_tii_governance_boundary(missing)
        smuggled = dict(base)
        smuggled["allow_insecure_serialisation"] = True
        with self.assertRaises(ValueError):
            audit.evaluate_tii_governance_boundary(smuggled)

        # Valid non-delivery eager diagnostic, non-SSM, non-LoRA, exact 20% budget, waived over-budget
        alt_ok = dict(base)
        alt_ok.update(
            {
                "delivery_claim": False,
                "cudagraph_mode": "EAGER_DIAGNOSTIC_ONLY",
                "has_ssm_layers": False,
                "ssm_state_dtype": "bfloat16",
                "lora_enabled": False,
                "lora_unmerged_bitwise_matched": False,
                "rollout_deficit": Fraction(1, 5),  # exact 20% boundary admitted
            }
        )
        self.assertTrue(audit.evaluate_tii_governance_boundary(alt_ok)["admitted"])

        waived_ok = dict(base)
        waived_ok.update({"rollout_deficit": Fraction(1, 4), "human_budget_waiver": True})
        self.assertTrue(audit.evaluate_tii_governance_boundary(waived_ok)["admitted"])

        neg_ok = dict(base)
        neg_ok.update({"rollout_deficit": Fraction(-1, 1)})
        self.assertTrue(audit.evaluate_tii_governance_boundary(neg_ok)["admitted"])

        # Every single invariant violation + sibling non-bool & canonicalization red-team cases
        cases: list[tuple[dict[str, object], str]] = [
            ({"batch_invariant_mode": False}, "KERNEL_EXECUTION_NOT_PINNED"),
            ({"attention_backend": "auto"}, "KERNEL_EXECUTION_NOT_PINNED"),
            ({"attention_backend": " TRITON_ATTN "}, "KERNEL_EXECUTION_NOT_PINNED"),
            ({"attention_backend": "TRITON_ATTN\n"}, "KERNEL_EXECUTION_NOT_PINNED"),
            ({"cudagraph_mode": "EAGER_DIAGNOSTIC_ONLY", "delivery_claim": True}, "CUDAGRAPH_DELIVERY_CLOSURE_INVALID"),
            ({"cudagraph_mode": "PIECEWISE", "delivery_claim": False}, "CUDAGRAPH_DELIVERY_CLOSURE_INVALID"),
            ({"delivery_claim": "yes"}, "CUDAGRAPH_DELIVERY_CLOSURE_INVALID"),
            ({"derived_scale_cache_reset_verified": False}, "DERIVED_SCALE_CACHE_STALE"),
            ({"has_ssm_layers": True, "ssm_state_dtype": "bfloat16"}, "SSM_STATE_PRECISION_DEGRADED"),
            ({"has_ssm_layers": False, "ssm_state_dtype": "garbage_xyz"}, "SSM_STATE_PRECISION_DEGRADED"),
            ({"has_ssm_layers": False, "ssm_state_dtype": ""}, "SSM_STATE_PRECISION_DEGRADED"),
            ({"has_ssm_layers": 1}, "SSM_STATE_PRECISION_DEGRADED"),
            ({"lora_enabled": True, "lora_unmerged_bitwise_matched": False}, "LORA_MERGE_ROUNDING_MISMATCH"),
            ({"lora_enabled": False, "lora_unmerged_bitwise_matched": "yes"}, "LORA_MERGE_ROUNDING_MISMATCH"),
            ({"mtp_speculative_tokens": 1}, "SPECULATIVE_MTP_UNVERIFIED"),
            ({"mtp_speculative_tokens": False}, "SPECULATIVE_MTP_UNVERIFIED"),
            ({"rollout_top_p": Fraction(19, 20)}, "SUPPORT_TRUNCATION_BREAKS_IS"),
            ({"rollout_top_k": 64}, "SUPPORT_TRUNCATION_BREAKS_IS"),
            ({"rollout_top_k": False}, "SUPPORT_TRUNCATION_BREAKS_IS"),
            ({"synchronous_bitwise_frac": Fraction(1, 1000)}, "BITWISE_FALSE_GREEN_OR_NONZERO_MISMATCH"),
            ({"valid_tokens": 0}, "BITWISE_FALSE_GREEN_OR_NONZERO_MISMATCH"),
            ({"nonfinite_count": 1}, "BITWISE_FALSE_GREEN_OR_NONZERO_MISMATCH"),
            ({"action_mask_excludes_non_policy_tokens": False}, "BITWISE_FALSE_GREEN_OR_NONZERO_MISMATCH"),
            ({"allow_insecure_serialization": True}, "INSECURE_PICKLE_SERIALIZATION_ENABLED"),
            ({"verifier_uses_bare_assert": True}, "VERIFIER_BARE_ASSERT_O_STRIPPING_HAZARD"),
            ({"checkpoint_allow_partial_load": True}, "CHECKPOINT_RESUME_UNVERIFIED"),
            ({"checkpoint_eviction_verifies_complete": False}, "CHECKPOINT_RESUME_UNVERIFIED"),
            ({"reviewer_id": "AGENT-KERNEL-PORTER"}, "AGENT_SELF_APPROVAL_OR_ROLE_COLLAPSE"),
            ({"reviewer_id": "agent-kernel-porter\u200b"}, "AGENT_SELF_APPROVAL_OR_ROLE_COLLAPSE"),
            ({"human_approver_id": "independent-verifier"}, "AGENT_SELF_APPROVAL_OR_ROLE_COLLAPSE"),
            ({"author_id": "   "}, "AGENT_SELF_APPROVAL_OR_ROLE_COLLAPSE"),
            ({"criteria_sha256": "a" * 64 + "\n"}, "AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID"),
            ({"manifest_sha256": "a" * 64}, "AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID"),
            ({"manifest_sha256": "A" * 64}, "AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID"),
            ({"planted_error_caught": False}, "AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID"),
            ({"open_p0": 1}, "AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID"),
            ({"open_p1": 1}, "AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID"),
            ({"open_p0": False}, "AUDIT_VERDICT_OR_PLANTED_ERROR_INVALID"),
            ({"rollout_deficit": Fraction(201, 1000), "human_budget_waiver": False}, "ROLLOUT_THROUGHPUT_BUDGET_EXCEEDED"),
            ({"rollout_deficit": Fraction(1, 1), "human_budget_waiver": True}, "ROLLOUT_THROUGHPUT_BUDGET_EXCEEDED"),
            ({"rollout_deficit": Fraction(-101, 100)}, "ROLLOUT_THROUGHPUT_BUDGET_EXCEEDED"),
            ({"rollout_deficit": Fraction(0, 1), "human_budget_waiver": "no"}, "ROLLOUT_THROUGHPUT_BUDGET_EXCEEDED"),
        ]
        for override, expected_reason in cases:
            cfg = dict(base)
            cfg.update(override)
            verdict = audit.evaluate_tii_governance_boundary(cfg)
            self.assertFalse(verdict["admitted"], f"expected reject for {override}")
            self.assertIn(expected_reason, verdict["reasons"], f"missing {expected_reason} for {override}")


class TestRepoInspectionSuiteAndCli(unittest.TestCase):
    def test_git_head_packed_refs_and_repo_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            rz = root / "REINFORCE-Zero"
            zm = root / "zero-mismatch-rl"
            (rz / ".git").mkdir(parents=True)
            (zm / ".git").mkdir(parents=True)
            (rz / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
            (rz / ".git" / "packed-refs").write_text(
                "# pack-refs with: peeled\n"
                "# refs/heads/main\n"
                f"^{'0' * 40}\n"
                f"{audit.PINNED_RZ_COMMIT} refs/heads/main\n",
                encoding="utf-8",
            )
            (zm / ".git" / "HEAD").write_text(f"{audit.PINNED_ZM_COMMIT}\n", encoding="utf-8")
            (rz / "REINFORCE-Zero.pdf").write_bytes(b"wrong-pdf")
            (root / "REINFORCE-Zero.txt").write_text("line1\n", encoding="utf-8")
            # Create stub files for all anchor paths so inspect runs cleanly
            for _, rel, _, _ in audit.ANCHOR_SPECS:
                p = root / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                if not p.exists():
                    p.write_text("placeholder\n", encoding="utf-8")
            rep = audit.inspect_reinforce_zero_repos(root)
            self.assertEqual(rep["rz_commit_observed"], audit.PINNED_RZ_COMMIT)
            self.assertEqual(rep["zm_commit_observed"], audit.PINNED_ZM_COMMIT)
            self.assertFalse(rep["pdf_sha256_matches"])
            self.assertFalse(rep["all_anchors_matched"])

            # RZ-BUG-02 regressions: non-hex detached HEAD, non-hex loose ref, comment-only packed-refs
            (zm / ".git" / "HEAD").write_text("NOT-A-GIT-SHA-AT-ALL\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                audit._read_git_head_sha(zm)

            (rz / ".git" / "refs" / "heads").mkdir(parents=True, exist_ok=True)
            (rz / ".git" / "refs" / "heads" / "badsha").write_text("garbage-loose-ref\n", encoding="utf-8")
            (rz / ".git" / "HEAD").write_text("ref: refs/heads/badsha\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                audit._read_git_head_sha(rz)

            (rz / ".git" / "packed-refs").write_text("# refs/heads/comment_only\n^" + "a" * 40 + "\n", encoding="utf-8")
            (rz / ".git" / "HEAD").write_text("ref: refs/heads/comment_only\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                audit._read_git_head_sha(rz)

            # Unresolvable ref, non-refs/ inside .git, path traversal, and symlink escape all raise ValueError
            (rz / ".git" / "ORIG_HEAD").write_text("e" * 40 + "\n", encoding="utf-8")
            for bad_head in (
                "ref: refs/heads/missing\n",
                "ref: ORIG_HEAD\n",
                "ref: ../../outside.txt\n",
                "ref: refs/heads\\bad\n",
            ):
                (rz / ".git" / "HEAD").write_text(bad_head, encoding="utf-8")
                with self.assertRaises(ValueError):
                    audit._read_git_head_sha(rz)

            outside = root / "outside_sha.txt"
            outside.write_text("f" * 40 + "\n", encoding="utf-8")
            (rz / ".git" / "refs").mkdir(parents=True, exist_ok=True)
            (rz / ".git" / "refs" / "escape").symlink_to(outside)
            (rz / ".git" / "HEAD").write_text("ref: refs/escape\n", encoding="utf-8")
            with self.assertRaises(ValueError):
                audit._read_git_head_sha(rz)

    def test_suite_standalone_zero_float_and_cli(self) -> None:
        cert = audit.run_audit_suite(None)
        self.assertFalse(_has_float(cert))
        self.assertEqual(cert["novelty_class"], "N1")
        self.assertEqual(cert["anchors"]["anchor_mode"], "standalone_no_repo")
        self.assertTrue(cert["proofs"]["rz_03_to_07_governance_boundary"]["hardened_admitted"]["admitted"])
        self.assertFalse(cert["proofs"]["rz_03_to_07_governance_boundary"]["unhardened_rejected"]["admitted"])

        buf_json = io.StringIO()
        with tempfile.TemporaryDirectory() as tmp:
            out_path = Path(tmp) / "cert.json"
            with patch("sys.stdout", buf_json):
                rc = audit.main(["--standalone", "--json", "--write-cert", str(out_path)])
            self.assertEqual(rc, 0)
            written = out_path.read_text(encoding="utf-8")
            self.assertEqual(written, buf_json.getvalue())
            parsed = json.loads(written)
            self.assertFalse(_has_float(parsed))

        buf_short = io.StringIO()
        with patch("sys.stdout", buf_short):
            rc2 = audit.main(["--standalone"])
        self.assertEqual(rc2, 0)
        self.assertIn(cert["canonical_sha256"], buf_short.getvalue())

        # Live staging repo check when sibling checkout exists
        default_root = audit._default_staging_root()
        if default_root is not None:
            live = audit.run_audit_suite(default_root)
            self.assertFalse(_has_float(live))
            self.assertTrue(live["anchors"]["all_anchors_matched"])
            self.assertEqual(live["anchors"]["anchors_verified"], len(audit.ANCHOR_SPECS))


if __name__ == "__main__":
    unittest.main()
