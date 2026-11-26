#!/usr/bin/env python3
"""Executable adversarial controls for the evaluator, not the candidate."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("ratchet_001_evaluation", HERE / "run.py")
if spec is None or spec.loader is None:
    raise ValueError("cannot load evaluator")
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


class HarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = {case["id"]: case for case in json.loads((HERE / "corpus.json").read_text(encoding="utf-8"))["cases"]}

    def test_false_accept_control(self) -> None:
        outcome = evaluation.classify(self.cases["G01"], {"admitted": True, "reasons": []}, 0, False)
        self.assertEqual(outcome, "false_accept")

    def test_crash_is_not_kill(self) -> None:
        self.assertEqual(evaluation.classify(self.cases["G01"], None, 1, False), "operational_failure")
        self.assertEqual(evaluation.classify(self.cases["G22"], None, 1, False), "false_reject")

    def test_reason_bound_kill(self) -> None:
        self.assertEqual(evaluation.classify(self.cases["G01"], {"admitted": False, "reasons": ["CLIPPED_KL_NON_BREGMAN"]}, 0, False), "kill")
        self.assertEqual(evaluation.classify(self.cases["G01"], {"admitted": False, "reasons": ["OTHER"]}, 0, False), "wrong_reason")

    def test_independent_gradient(self) -> None:
        result = evaluation.independent_gradient_reference(self.cases["Q00"])
        self.assertEqual(result["songe_dL_dz0"], {"num": 1, "den": 100})
        self.assertEqual(result["bregman_dL_dz0"], {"num": -2, "den": 25})

    def test_unicode_cluster_reference(self) -> None:
        result = evaluation.independent_cluster_reference(self.cases["C03"]["request"]["input"])
        self.assertEqual(result["independent_conversations"], 3)
        self.assertEqual(result["conversation_wins"], 2)
        self.assertEqual(result["conversation_losses"], 0)

    def test_receipt_float_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "float"):
            evaluation.canonical({"value": 1.5})
        self.assertEqual(self.cases["G25"]["request"]["input"]["eval_temperature"], 0.0)
        self.assertEqual(evaluation.parse_input_json('{"value":0.0}'), {"value": 0.0})
        with self.assertRaisesRegex(ValueError, "float"):
            evaluation.parse_json('{"value":0.0}')

    def test_duplicate_receipt_key_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate"):
            evaluation.parse_json('{"value":1,"value":2}')

    def test_chain_rejects_tampering(self) -> None:
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "observations").mkdir()
            item = {"schema": "warp-drive.ratchet-001.receipt.v1", "sequence": 0, "previous_sha256": None, "case": "G00", "mode": "normal", "outcome": "pass", "elapsed_ms": 1, "observation_sha256": evaluation.sha256_text("{}\n"), "candidate_head": "test"}
            item["receipt_sha256"] = evaluation.sha256_text(evaluation.canonical(item))
            (root / "receipts.jsonl").write_text(evaluation.canonical(item) + "\n", encoding="utf-8")
            (root / "observations" / "normal-G00.json").write_text("{}\n", encoding="utf-8")
            (root / "SUMMARY.json").write_text(evaluation.canonical({"terminal_receipt_sha256": item["receipt_sha256"]}), encoding="utf-8")
            self.assertTrue(evaluation.verify_chain(root))
            item["elapsed_ms"] = 2
            (root / "receipts.jsonl").write_text(evaluation.canonical(item) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest"):
                evaluation.verify_chain(root)

    def test_pinned_ast_and_ring0(self) -> None:
        framework_path = os.environ.get("ALETHEIA_RATCHET_MODULE")
        if framework_path is None:
            self.fail("pinned framework path required")
        framework = evaluation.load_pinned_framework()
        first = "def score(x):\n    return x + 1\n"
        noop = "# changed comment\ndef score(x):\n    return x + 1  # still unchanged\n"
        changed = "def score(x):\n    return x + 2\n"
        self.assertEqual(framework.ast_canonical_digest(first), framework.ast_canonical_digest(noop))
        self.assertNotEqual(framework.ast_canonical_digest(first), framework.ast_canonical_digest(changed))
        base = {"oracle": "exact", "verifier": "v1", "heldout": ["G01"]}
        self.assertTrue(framework.check_ring0_lock(base, copy.deepcopy(base)))
        with self.assertRaises(Exception):
            framework.check_ring0_lock(base, {**base, "oracle": "self_consistency"})

    def test_corpus_is_deterministic(self) -> None:
        import subprocess
        import sys
        before = (HERE / "corpus.json").read_bytes()
        completed = subprocess.run([sys.executable, "-I", "-B", str(HERE / "generate_corpus.py")], check=False, capture_output=True)
        self.assertEqual(completed.returncode, 0)
        self.assertEqual((HERE / "corpus.json").read_bytes(), before)
        self.assertEqual(len(self.cases), 44)


if __name__ == "__main__":
    unittest.main()
