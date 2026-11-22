#!/usr/bin/env python3
"""Isolated R5 adversarial and boundary test suite for songe_distill_governance_audit.py."""

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

sys.path.append(str(Path(__file__).resolve().parent))
import songe_distill_governance_audit as mod


def _has_any_float(obj: object) -> bool:
    if isinstance(obj, float):
        return True
    if isinstance(obj, dict):
        return any(_has_any_float(v) for v in obj.values())
    if isinstance(obj, list):
        return any(_has_any_float(v) for v in obj)
    return False


def _valid_governance_config() -> dict[str, object]:
    sha = hashlib.sha256(b"pinned-base-and-tokenizer").hexdigest()
    return {
        "vocab_clip": Fraction(1, 1),
        "bregman_normalized": True,
        "fused_serving_artifact": True,
        "fused_outputs_rejudged": True,
        "quick_dream_enabled": True,
        "rule_requires_explicit_user_approval": True,
        "review_fail_closed": True,
        "hindsight_fence_escaped": True,
        "control_requires_bearer_token": True,
        "installation_id_publicly_disclosed": False,
        "root_routes_guarded": True,
        "base_fingerprint_mode": "content_sha256",
        "includes_tokenizer_and_gguf": True,
        "base_sha256": sha,
        "body_secret_redaction_enabled": True,
        "sample_recorded_body": "stdout: tests passed",
        "strict_json_verdict_only": True,
        "runtime_pip_require_hashes": True,
        "eval_temperature": Fraction(0, 1),
        "eval_top_p": Fraction(1, 1),
    }


def _make_fake_repo(root: Path, commit: str, *, symbolic_head: bool, corrupt_anchor: bool) -> None:
    git_dir = root / ".git"
    if symbolic_head:
        ref_dir = git_dir / "refs" / "heads"
        ref_dir.mkdir(parents=True, exist_ok=True)
        (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        (ref_dir / "main").write_text(f"{commit}\n", encoding="utf-8")
    else:
        git_dir.mkdir(parents=True, exist_ok=True)
        (git_dir / "HEAD").write_text(f"{commit}\n", encoding="utf-8")
    for idx, (_fid, rel_path, expected_line, needle) in enumerate(mod.ANCHOR_SPECS):
        target = root / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        lines = target.read_text(encoding="utf-8").splitlines() if target.exists() else []
        while len(lines) < expected_line:
            lines.append("# filler")
        lines[expected_line - 1] = "corrupted" if (corrupt_anchor and idx == 0) else needle
        target.write_text("\n".join(lines) + "\n", encoding="utf-8")


class TestClippedKlTheorem(unittest.TestCase):
    def test_ln_rational_interval_bounds_and_guards(self) -> None:
        self.assertEqual(mod.ln_rational_interval(Fraction(1, 1)), (Fraction(0, 1), Fraction(0, 1)))
        lo2, hi2 = mod.ln_rational_interval(Fraction(2, 1), terms=10)
        self.assertGreater(lo2, Fraction(693147, 1000000))
        self.assertLess(hi2, Fraction(693148, 1000000))
        lo_half, hi_half = mod.ln_rational_interval(Fraction(1, 2), terms=10)
        self.assertEqual(lo_half, -hi2)
        self.assertEqual(hi_half, -lo2)
        for bad in (
            (Fraction(0, 1), 6),
            (Fraction(-1, 2), 6),
            (2.0, 6),
            (Fraction(2, 1), 0),
            (Fraction(2, 1), True),
        ):
            with self.assertRaises(ValueError):
                mod.ln_rational_interval(*bad)  # type: ignore[arg-type]

    def test_songe_clipped_kl_gradient_reversal_and_gibbs_violation(self) -> None:
        p = [Fraction(1, 2), Fraction(1, 2)]
        q_near = [Fraction(1, 16), Fraction(15, 16)]
        q_far = [Fraction(1, 32), Fraction(31, 32)]
        # At default vocab_clip = 1, q_far (further from P!) has strictly lower loss than q_near!
        near_lo, _ = mod.songe_clipped_kl_interval(p, q_near, Fraction(1, 1))
        _, far_hi = mod.songe_clipped_kl_interval(p, q_far, Fraction(1, 1))
        self.assertLess(far_hi, near_lo)

        # At clip = 1/4 (< 1/e), Gibbs inequality fails strictly (< 0 = KL(P || P))!
        _, neg_hi = mod.songe_clipped_kl_interval(p, q_far, Fraction(1, 4))
        self.assertLess(neg_hi, Fraction(0, 1))

        # Bregman-normalized repair restores >= 0 globally AND monotone pull toward P in saturated regime
        q_sat_near = [Fraction(1, 64), Fraction(63, 64)]
        q_sat_far = [Fraction(1, 128), Fraction(127, 128)]
        b_near_lo, b_near_hi = mod.bregman_clipped_kl_interval(p, q_sat_near, Fraction(1, 1))
        b_far_lo, _ = mod.bregman_clipped_kl_interval(p, q_sat_far, Fraction(1, 1))
        self.assertGreater(b_near_lo, Fraction(0, 1))
        self.assertGreater(b_far_lo, b_near_hi)
        self.assertEqual(
            mod.bregman_clipped_kl_interval(p, p, Fraction(1, 4)),
            (Fraction(0, 1), Fraction(0, 1)),
        )

        # Exact saturated softmax logit gradients have opposite sign
        grads = mod.binary_saturated_logit_gradients(Fraction(1, 2), Fraction(1, 64))
        self.assertEqual(grads["songe_dL_dz0"], {"num": 1, "den": 128})
        self.assertEqual(grads["bregman_dL_dz0"], {"num": -31, "den": 4096})

    def test_kl_and_gradient_input_guards(self) -> None:
        p = [Fraction(1, 2), Fraction(1, 2)]
        for fn in (mod.songe_clipped_kl_interval, mod.bregman_clipped_kl_interval):
            for bad in (
                ("not-list", p, Fraction(1, 1)),
                ([Fraction(1, 1)], p, Fraction(1, 1)),
                ([Fraction(0, 1), Fraction(1, 1)], p, Fraction(1, 1)),
                ([Fraction(1, 3), Fraction(1, 3)], p, Fraction(1, 1)),
                ([0.5, 0.5], p, Fraction(1, 1)),
                (p, [Fraction(1, 3), Fraction(1, 3), Fraction(1, 3)], Fraction(1, 1)),
                (p, p, Fraction(0, 1)),
                (p, p, 1.0),
            ):
                with self.assertRaises(ValueError):
                    fn(*bad)  # type: ignore[arg-type]
        for bad_grad in (
            (0.5, Fraction(1, 16)),
            (Fraction(1, 2), 0.1),
            (Fraction(0, 1), Fraction(1, 16)),
            (Fraction(1, 1), Fraction(1, 16)),
            (Fraction(1, 2), Fraction(0, 1)),
            (Fraction(1, 2), Fraction(1, 2)),
            (Fraction(1, 2), Fraction(3, 4)),
        ):
            with self.assertRaises(ValueError):
                mod.binary_saturated_logit_gradients(*bad_grad)  # type: ignore[arg-type]


class TestBootstrapAndClusteredVilleGate(unittest.TestCase):
    def test_ville_and_bootstrap_degeneracy_exact(self) -> None:
        self.assertEqual(mod.ville_mixture_ratio(0, 0), Fraction(1, 1))
        self.assertEqual(mod.ville_mixture_ratio(8, 8), Fraction(511, 9))
        self.assertEqual(mod.ville_mixture_ratio(9, 9), Fraction(1023, 10))
        for bad in ((-1, 0), (2, -1), (2, 3), (True, 0), (1, True)):
            with self.assertRaises(ValueError):
                mod.ville_mixture_ratio(*bad)  # type: ignore[arg-type]

        b12 = mod.songe_bootstrap_unanimous_null_risk(1, 2)
        self.assertEqual(b12["per_scale_null_false_accept"], {"num": 1, "den": 2})
        self.assertEqual(b12["multi_scale_null_fwer"], {"num": 3, "den": 4})
        self.assertTrue(b12["songe_accepts"])
        for bad in ((0, 2), (2, 0), (True, 2), (2, True)):
            with self.assertRaises(ValueError):
                mod.songe_bootstrap_unanimous_null_risk(*bad)  # type: ignore[arg-type]

    def test_hardened_clustered_ville_gate_all_reasons_and_guards(self) -> None:
        # 9 independent wins across K=2, alpha=1/20 (threshold=80), exact min_conversations=9 boundary
        convs9 = [(f"c{i}", 1) for i in range(9)]
        ok = mod.hardened_clustered_ville_gate(
            convs9, Fraction(1, 20), 2, 9, True, Fraction(1, 20), Fraction(1, 20)
        )
        self.assertTrue(ok["accepted"])
        self.assertEqual(ok["reasons"], [])
        self.assertEqual(ok["independent_conversations"], 9)

        # Exact lead_ratio == threshold boundary: M_2(2) = 7/3 == 2*1 / (6/7)
        convs2 = [("c0", 1), ("c1", 1)]
        ok_eq = mod.hardened_clustered_ville_gate(
            convs2, Fraction(6, 7), 1, 2, True, Fraction(0, 1), Fraction(1, 20)
        )
        self.assertTrue(ok_eq["accepted"])
        self.assertEqual(ok_eq["lead_ratio"], {"num": 7, "den": 3})
        self.assertEqual(ok_eq["threshold"], {"num": 7, "den": 3})

        # Single conversation with 9 whitespace/case-padded variants collapses to 1 cluster (SNG-BYPASS-02)
        one_conv = [
            ("conv-1", 1), ("conv-1 ", 1), (" conv-1", 1), ("  conv-1  ", 1),
            ("\nconv-1", 1), ("conv-1\t", 1), ("CONV-1", 1), (" Conv-1\n", 1), ("\tCONV-1 ", 1),
        ]
        fail_cluster = mod.hardened_clustered_ville_gate(
            one_conv, Fraction(1, 20), 2, 5, True, Fraction(0, 1), Fraction(1, 20)
        )
        self.assertFalse(fail_cluster["accepted"])
        self.assertEqual(fail_cluster["independent_conversations"], 1)
        self.assertIn("INSUFFICIENT_INDEPENDENT_CONVERSATIONS", fail_cluster["reasons"])
        self.assertIn("SUPERMARTINGALE_THRESHOLD_NOT_MET", fail_cluster["reasons"])

        # Conversation losses & ties counted properly
        mixed = [(f"c{i}", 1) for i in range(9)] + [("loss-c", -1), ("tie-c", 1), ("tie-c", -1)]
        res_mixed = mod.hardened_clustered_ville_gate(
            mixed, Fraction(1, 20), 1, 5, True, Fraction(0, 1), Fraction(1, 20)
        )
        self.assertEqual(res_mixed["conversation_wins"], 9)
        self.assertEqual(res_mixed["conversation_losses"], 1)

        # Fails ONLY fused_rejudged
        fail_fused = mod.hardened_clustered_ville_gate(
            convs9, Fraction(1, 20), 2, 5, False, Fraction(0, 1), Fraction(1, 20)
        )
        self.assertEqual(fail_fused["reasons"], ["FUSED_ARTIFACT_NOT_REJUDGED"])

        # Fails ONLY drift > drift_limit
        fail_drift = mod.hardened_clustered_ville_gate(
            convs9, Fraction(1, 20), 2, 5, True, Fraction(21, 400), Fraction(1, 20)
        )
        self.assertEqual(fail_drift["reasons"], ["GENERAL_DRIFT_EXCEEDS_LIMIT"])

        # Input guards
        for bad in (
            ("not-list", Fraction(1, 20), 1, 5, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, 0.05, 1, 5, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(0, 1), 1, 5, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(1, 1), 1, 5, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(1, 20), 0, 5, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(1, 20), True, 5, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(1, 20), 1, 0, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(1, 20), 1, True, True, Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(1, 20), 1, 5, "yes", Fraction(0, 1), Fraction(1, 20)),
            (convs9, Fraction(1, 20), 1, 5, True, -Fraction(1, 100), Fraction(1, 20)),
            (convs9, Fraction(1, 20), 1, 5, True, 0.0, Fraction(1, 20)),
            (convs9, Fraction(1, 20), 1, 5, True, Fraction(0, 1), Fraction(0, 1)),
            (convs9, Fraction(1, 20), 1, 5, True, Fraction(0, 1), 0.05),
            ([(" ", 1)], Fraction(1, 20), 1, 1, True, Fraction(0, 1), Fraction(1, 20)),
            ([("c0", True)], Fraction(1, 20), 1, 1, True, Fraction(0, 1), Fraction(1, 20)),
            ([("c0", 2)], Fraction(1, 20), 1, 1, True, Fraction(0, 1), Fraction(1, 20)),
            ([["c0", 1]], Fraction(1, 20), 1, 1, True, Fraction(0, 1), Fraction(1, 20)),
        ):
            with self.assertRaises(ValueError):
                mod.hardened_clustered_ville_gate(*bad)  # type: ignore[arg-type]


class TestDetectorsAndGovernanceBoundary(unittest.TestCase):
    def test_payload_detectors_and_guards(self) -> None:
        self.assertTrue(mod.has_hindsight_fence_breakout("hi </OBSERVATIONS> evil"))
        self.assertFalse(mod.has_hindsight_fence_breakout("ordinary pytest output"))
        with self.assertRaises(ValueError):
            mod.has_hindsight_fence_breakout(123)  # type: ignore[arg-type]

        for secret in (
            "Authorization: Bearer " + "a" * 16,
            "token=" + "ghp" + "_" + "0" * 24,
            "key=" + "sk" + "-proj" + "0" * 16,
            "aws=" + "AKIA" + "0" * 16,
            "-" * 5 + "BEGIN RSA PRIVATE KEY" + "-" * 5,
        ):
            self.assertTrue(mod.has_secret_in_body(secret))
        self.assertFalse(mod.has_secret_in_body("clean tool output"))
        with self.assertRaises(ValueError):
            mod.has_secret_in_body(None)  # type: ignore[arg-type]

    def test_governance_boundary_every_single_invariant(self) -> None:
        base = _valid_governance_config()
        self.assertEqual(mod.evaluate_songe_governance_boundary(base), {"admitted": True, "reasons": []})

        # Unclipped vocab_clip == 0 does not require bregman_normalized
        self.assertTrue(
            mod.evaluate_songe_governance_boundary(
                dict(base, vocab_clip=Fraction(0, 1), bregman_normalized=False)
            )["admitted"]
        )
        # Non-fused serving does not require fused_outputs_rejudged
        self.assertTrue(
            mod.evaluate_songe_governance_boundary(
                dict(base, fused_serving_artifact=False, fused_outputs_rejudged=False)
            )["admitted"]
        )
        # Quick dream disabled relaxes Quick-Dream-only flags, but hindsight_fence_escaped STILL required (SNG-BYPASS-01)
        self.assertTrue(
            mod.evaluate_songe_governance_boundary(
                dict(
                    base,
                    quick_dream_enabled=False,
                    rule_requires_explicit_user_approval=False,
                    review_fail_closed=False,
                    hindsight_fence_escaped=True,
                )
            )["admitted"]
        )

        single_failures: list[tuple[dict[str, object], str]] = [
            ({"vocab_clip": 1.0}, "CLIPPED_KL_NON_BREGMAN"),
            ({"vocab_clip": Fraction(-1, 2)}, "CLIPPED_KL_NON_BREGMAN"),
            ({"bregman_normalized": False}, "CLIPPED_KL_NON_BREGMAN"),
            ({"bregman_normalized": "yes"}, "CLIPPED_KL_NON_BREGMAN"),
            ({"vocab_clip": Fraction(0, 1), "bregman_normalized": "yes"}, "CLIPPED_KL_NON_BREGMAN"),
            ({"fused_serving_artifact": "yes"}, "FUSED_ARTIFACT_NOT_REJUDGED"),
            ({"fused_serving_artifact": False, "fused_outputs_rejudged": "yes"}, "FUSED_ARTIFACT_NOT_REJUDGED"),
            ({"fused_outputs_rejudged": False}, "FUSED_ARTIFACT_NOT_REJUDGED"),
            ({"quick_dream_enabled": "yes"}, "PROMPT_RULE_INJECTION_UNSANITIZED"),
            ({"quick_dream_enabled": False, "hindsight_fence_escaped": False}, "PROMPT_RULE_INJECTION_UNSANITIZED"),
            ({"quick_dream_enabled": False, "rule_requires_explicit_user_approval": "yes"}, "PROMPT_RULE_INJECTION_UNSANITIZED"),
            ({"quick_dream_enabled": False, "review_fail_closed": "yes"}, "PROMPT_RULE_INJECTION_UNSANITIZED"),
            ({"rule_requires_explicit_user_approval": False}, "PROMPT_RULE_INJECTION_UNSANITIZED"),
            ({"review_fail_closed": False}, "PROMPT_RULE_INJECTION_UNSANITIZED"),
            ({"hindsight_fence_escaped": False}, "PROMPT_RULE_INJECTION_UNSANITIZED"),
            ({"control_requires_bearer_token": False}, "CONTROL_API_UNAUTHENTICATED"),
            ({"installation_id_publicly_disclosed": True}, "CONTROL_API_UNAUTHENTICATED"),
            ({"installation_id_publicly_disclosed": 0}, "CONTROL_API_UNAUTHENTICATED"),
            ({"root_routes_guarded": False}, "CONTROL_API_UNAUTHENTICATED"),
            ({"base_fingerprint_mode": "stat_dir_only"}, "BASE_FINGERPRINT_NOT_CRYPTOGRAPHIC"),
            ({"includes_tokenizer_and_gguf": False}, "BASE_FINGERPRINT_NOT_CRYPTOGRAPHIC"),
            ({"base_sha256": "short"}, "BASE_FINGERPRINT_NOT_CRYPTOGRAPHIC"),
            ({"base_sha256": "z" * 64}, "BASE_FINGERPRINT_NOT_CRYPTOGRAPHIC"),
            ({"body_secret_redaction_enabled": False}, "BODY_SECRET_REDACTION_MISSING"),
            ({"sample_recorded_body": 123}, "BODY_SECRET_REDACTION_MISSING"),
            ({"sample_recorded_body": "Bearer secret_token_12345"}, "BODY_SECRET_REDACTION_MISSING"),
            ({"strict_json_verdict_only": False}, "JUDGE_VERDICT_REGEX_FALLBACK"),
            ({"runtime_pip_require_hashes": False}, "UNPINNED_RUNTIME_PIP_INSTALL"),
            ({"eval_temperature": 0.0}, "EVAL_SAMPLING_NONDETERMINISTIC"),
            ({"eval_temperature": False}, "EVAL_SAMPLING_NONDETERMINISTIC"),
            ({"eval_temperature": Fraction(4, 5)}, "EVAL_SAMPLING_NONDETERMINISTIC"),
            ({"eval_top_p": 1.0}, "EVAL_SAMPLING_NONDETERMINISTIC"),
            ({"eval_top_p": True}, "EVAL_SAMPLING_NONDETERMINISTIC"),
            ({"eval_top_p": Fraction(19, 20)}, "EVAL_SAMPLING_NONDETERMINISTIC"),
        ]
        for overrides, expected_reason in single_failures:
            res = mod.evaluate_songe_governance_boundary(dict(base, **overrides))
            self.assertFalse(res["admitted"], f"expected reject for {overrides}")
            self.assertEqual(res["reasons"], [expected_reason])


class TestAnchorsSuiteAndCli(unittest.TestCase):
    def test_inspect_repo_symbolic_detached_mismatch_and_corrupt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _make_fake_repo(root, mod.PINNED_COMMIT, symbolic_head=True, corrupt_anchor=False)
            ok = mod.inspect_songe_repo(root)
            self.assertTrue(ok["commit_matches"])
            self.assertTrue(ok["all_anchors_matched"])
            self.assertEqual(ok["anchors_verified"], len(mod.ANCHOR_SPECS))

            _make_fake_repo(root, "0" * 40, symbolic_head=False, corrupt_anchor=False)
            wrong = mod.inspect_songe_repo(root)
            self.assertFalse(wrong["commit_matches"])
            self.assertFalse(wrong["all_anchors_matched"])

            _make_fake_repo(root, mod.PINNED_COMMIT, symbolic_head=False, corrupt_anchor=True)
            corrupt = mod.inspect_songe_repo(root)
            self.assertTrue(corrupt["commit_matches"])
            self.assertFalse(corrupt["all_anchors_matched"])
            self.assertEqual(corrupt["anchors_verified"], len(mod.ANCHOR_SPECS) - 1)

            (root / mod.ANCHOR_SPECS[0][1]).write_text("short\n", encoding="utf-8")
            self.assertFalse(mod.inspect_songe_repo(root)["all_anchors_matched"])

    def test_run_audit_suite_standalone_zero_float_and_proofs(self) -> None:
        res = mod.run_audit_suite(None)
        self.assertFalse(_has_any_float(res))
        self.assertEqual(res["anchors"]["anchor_mode"], "standalone")
        self.assertEqual(res["anchors"]["anchors_total"], len(mod.ANCHOR_SPECS))
        self.assertFalse(res["anchors"]["all_anchors_matched"])

        proofs = res["proofs"]
        self.assertTrue(proofs["sng01_clipped_kl_theorem"]["default_clip_1_far_strictly_lower"])
        self.assertTrue(proofs["sng01_clipped_kl_theorem"]["clip_1_4_gibbs_violated_negative"])
        self.assertTrue(proofs["sng01_clipped_kl_theorem"]["bregman_clip1_sat_far_strictly_higher"])

        g = proofs["sng02_03_gate_bootstrap_vs_ville"]
        self.assertTrue(g["songe_bootstrap_n1_k2"]["songe_accepts"])
        self.assertEqual(g["songe_bootstrap_n1_k2"]["multi_scale_null_fwer"], {"num": 3, "den": 4})
        self.assertFalse(g["ville_3_moments_1_conv_unfused"]["accepted"])
        self.assertFalse(g["ville_8_convs_k2_rejected"]["accepted"])
        self.assertTrue(g["ville_9_convs_k2_accepted"]["accepted"])

        det = proofs["sng04_07_payload_detectors"]
        self.assertTrue(det["hindsight_breakout_detected"])
        self.assertTrue(det["body_secret_detected"])
        self.assertTrue(det["redacted_body_clean"])

        gov = proofs["sng01_to_08_governance_boundary"]
        self.assertFalse(gov["legacy_risky_admitted"])
        self.assertEqual(gov["legacy_risky_reason_count"], 9)
        self.assertTrue(gov["hardened_admitted"])

        body = dict(res)
        digest = body.pop("canonical_sha256")
        expected = hashlib.sha256(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        self.assertEqual(digest, expected)

    def test_cli_main_and_default_repo_resolution(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            fake_repo = tmp_path / "repo"
            _make_fake_repo(fake_repo, mod.PINNED_COMMIT, symbolic_head=True, corrupt_anchor=False)
            cert_path = tmp_path / "cert.json"

            buf = io.StringIO()
            with patch("sys.stdout", buf):
                rc = mod.main(["--repo", str(fake_repo), "--json", "--write-cert", str(cert_path)])
            self.assertEqual(rc, 0)
            self.assertTrue(json.loads(buf.getvalue())["anchors"]["all_anchors_matched"])
            self.assertEqual(cert_path.read_text(encoding="utf-8"), buf.getvalue())

            buf_human = io.StringIO()
            with patch("sys.stdout", buf_human):
                rc2 = mod.main(["--standalone"])
            self.assertEqual(rc2, 0)
            self.assertIn("standalone", buf_human.getvalue())
            self.assertIn("sha256=", buf_human.getvalue())

            with patch.object(mod, "_default_repo_path", return_value=fake_repo):
                buf_auto = io.StringIO()
                with patch("sys.stdout", buf_auto):
                    rc3 = mod.main(["--json"])
                self.assertEqual(rc3, 0)
                self.assertEqual(json.loads(buf_auto.getvalue())["anchors"]["anchor_mode"], "live_readonly")

            with patch.object(mod, "__file__", str(tmp_path / "arm2" / "script.py")):
                self.assertIsNone(mod._default_repo_path())
            (tmp_path / "repos" / "songe" / ".git").mkdir(parents=True, exist_ok=True)
            (tmp_path / "repos" / "songe" / ".git" / "HEAD").write_text(
                f"{mod.PINNED_COMMIT}\n", encoding="utf-8"
            )
            with patch.object(mod, "__file__", str(tmp_path / "arm2" / "script.py")):
                self.assertEqual(mod._default_repo_path(), (tmp_path / "repos" / "songe").resolve())


if __name__ == "__main__":
    unittest.main()
