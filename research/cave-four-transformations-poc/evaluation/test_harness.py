#!/usr/bin/env python3
"""Adversarial controls for the POC runner and receipt checker."""

import ast
import copy
import datetime
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from run import (
    ROOT,
    append_receipt,
    canonical,
    classify,
    locked_command,
    parse_json,
    public_output,
    sha256_text,
    source_files,
    validate_target,
    verify_lock,
    verify_run,
    write_summary,
)


class HarnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.lock, cls.cases, cls.lock_sha256 = verify_lock(ROOT)
        cls.case_by_id = {case["id"]: case for case in cls.cases["cases"]}

    def output_for(self, case, outcome):
        if case["kind"] == "summary":
            verdict = "PASS" if outcome == "pass" else "FAIL" if outcome == "fail" else None
            if verdict is None:
                return "traceback: stopped before verdict\n"
            return "SUMMARY " + case["summary_id"] + " SMOKE " + verdict + " | recorded\n"
        if outcome == "pass":
            suffix = "\nPASS" if case["kind"] == "units" else ""
            return case["pass_marker"] + suffix + "\n"
        return "crashed\n"

    def return_code_for(self, outcome):
        if outcome == "pass":
            return 0
        if outcome == "fail":
            return 1
        return 2

    def make_run(self, raw):
        run_dir = Path(raw)
        receipts = []
        previous = None
        sequence = 0
        for case in self.cases["cases"]:
            for mode, expected in case["expected"].items():
                stem = case["id"] + "-" + mode
                stdout = self.output_for(case, expected)
                stderr = ""
                (run_dir / (stem + ".stdout.txt")).write_text(stdout, encoding="utf-8")
                (run_dir / (stem + ".stderr.txt")).write_text(stderr, encoding="utf-8")
                body = {
                    "case": case["id"],
                    "mode": mode,
                    "oracle": case["oracle"],
                    "command": locked_command(case, mode, self.cases),
                    "timeout_seconds": case["timeout_seconds"],
                    "return_code": self.return_code_for(expected),
                    "timed_out": False,
                    "elapsed_ms": 1,
                    "observed": expected,
                    "expected": expected,
                    "matched": True,
                    "stdout_file": stem + ".stdout.txt",
                    "stderr_file": stem + ".stderr.txt",
                    "stdout_sha256": sha256_text(stdout),
                    "stderr_sha256": sha256_text(stderr),
                    "stdout_redactions": 0,
                    "stderr_redactions": 0,
                    "target_commit": self.cases["target"]["commit"],
                    "lock_sha256": self.lock_sha256,
                }
                receipt = append_receipt(run_dir, previous, sequence, body)
                receipts.append(receipt)
                previous = receipt["receipt_sha256"]
                sequence += 1
        write_summary(run_dir, receipts, self.cases["target"]["commit"], self.lock_sha256)
        source = {
            "schema": "warp-drive.cave-four-transformations.source.v1",
            "target": self.cases["target"],
            "aletheia": self.cases["aletheia"],
            "lock_sha256": self.lock_sha256,
            "recorded_utc": "2026-11-22T00:00:00Z",
        }
        (run_dir / "SOURCE.json").write_text(canonical(source) + "\n", encoding="utf-8")
        return run_dir

    def copy_locked_sources(self, raw):
        root = Path(raw)
        (root / "evaluation").mkdir()
        for path in source_files(ROOT):
            destination = root / path.relative_to(ROOT)
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, destination)
        shutil.copy2(ROOT / "LOCK.json", root / "LOCK.json")
        return root

    def test_correct_by_construction_run(self):
        with tempfile.TemporaryDirectory() as raw:
            result = verify_run(self.make_run(raw))
            self.assertTrue(result["chain_valid"])
            self.assertEqual(result["receipt_count"], 18)
            self.assertEqual(result["status"], "REFERENCE_REPLAY_COMPLETE")

    def test_false_accept_is_operational_failure(self):
        case = self.case_by_id["K1"]
        output = "SUMMARY K1 SMOKE FAIL | false accept\n"
        self.assertEqual(classify(case, 0, output), "operational_failure")
        self.assertEqual(classify(case, 1, output), "fail")

    def test_false_fail_is_operational_failure(self):
        case = self.case_by_id["K1"]
        output = "SUMMARY K1 SMOKE PASS | false fail\n"
        self.assertEqual(classify(case, 1, output), "operational_failure")
        self.assertEqual(classify(case, 0, output), "pass")

    def test_crash_and_timeout_are_not_negative_results(self):
        case = self.case_by_id["K3"]
        self.assertEqual(classify(case, 1, "traceback\n"), "operational_failure")
        self.assertEqual(classify(case, None, "SUMMARY K3 SMOKE FAIL | timeout\n", True), "operational_failure")

    def test_summary_must_be_unique_complete_and_terminal(self):
        case = self.case_by_id["K2"]
        self.assertEqual(classify(case, 1, "SUMMARY K2 SMOKE FAIL | x\nSUMMARY K2 SMOKE FAIL | y\n"), "operational_failure")
        self.assertEqual(classify(case, 1, "SUMMARY K2 SMOKE FAIL |\n"), "operational_failure")
        self.assertEqual(classify(case, 1, "prefix SUMMARY K2 SMOKE FAIL | x\n"), "operational_failure")
        self.assertEqual(classify(case, 1, "SUMMARY K2 SMOKE FAIL | x\nFAIL after summary\n"), "operational_failure")
        self.assertEqual(classify(case, 1, "SUMMARY K2 SMOKE FAIL | x\n\n"), "operational_failure")
        self.assertEqual(classify(case, 1, "harmless prefix\nSUMMARY K2 SMOKE FAIL | x\n"), "fail")

    def test_unit_and_review_markers_have_locked_terminal_shapes(self):
        for case_id in ("U01", "R01"):
            case = self.case_by_id[case_id]
            marker = case["pass_marker"]
            valid_tail = marker + ("\nPASS" if case_id == "U01" else "") + "\n"
            self.assertEqual(classify(case, 0, valid_tail), "pass")
            self.assertEqual(classify(case, 0, "harmless prefix\n" + valid_tail), "pass")
            self.assertEqual(classify(case, 0, "PASS\n"), "operational_failure")
            self.assertEqual(classify(case, 0, marker + "\nFAIL after marker\n"), "operational_failure")
            self.assertEqual(classify(case, 0, marker + "\n" + valid_tail), "operational_failure")
            self.assertEqual(classify(case, 0, marker + " suffix\n"), "operational_failure")
            self.assertEqual(classify(case, 0, "prefix " + marker + "\n"), "operational_failure")
        unit = self.case_by_id["U01"]
        self.assertEqual(classify(unit, 0, unit["pass_marker"] + "\n"), "operational_failure")
        self.assertEqual(classify(unit, 0, unit["pass_marker"] + "\nFAIL\n"), "operational_failure")
        self.assertEqual(classify(unit, 1, unit["pass_marker"] + "\nPASS\n"), "operational_failure")

    def test_rebuilt_chain_cannot_hide_trailing_failure(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            receipts = [parse_json(line) for line in (run_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()]
            for index, receipt in enumerate(receipts):
                if receipt["case"] not in ("U01", "R01", "K1"):
                    continue
                path = run_dir / receipt["stdout_file"]
                path.write_text(path.read_text(encoding="utf-8") + "FAIL after accepted output\n", encoding="utf-8")
                receipt["stdout_sha256"] = sha256_text(path.read_text(encoding="utf-8"))
            previous = None
            lines = []
            for receipt in receipts:
                receipt["previous_sha256"] = previous
                receipt.pop("receipt_sha256", None)
                digest = sha256_text(canonical(receipt))
                receipt["receipt_sha256"] = digest
                previous = digest
                lines.append(canonical(receipt))
            (run_dir / "receipts.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
            write_summary(run_dir, receipts, self.cases["target"]["commit"], self.lock_sha256)
            with self.assertRaisesRegex(ValueError, "outcome"):
                verify_run(run_dir)

    def test_strict_json(self):
        with self.assertRaisesRegex(ValueError, "duplicate"):
            parse_json('{"value":1,"value":2}')
        for text in ('{"value":1.5}', '{"value":NaN}', '{"value":Infinity}'):
            with self.assertRaises(ValueError):
                parse_json(text)
        with self.assertRaisesRegex(ValueError, "floating"):
            canonical({"value": 1.5})

    def test_receipt_digest_tamper(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            lines = (run_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
            receipt = parse_json(lines[0])
            receipt["elapsed_ms"] = 2
            lines[0] = canonical(receipt)
            (run_dir / "receipts.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "digest"):
                verify_run(run_dir)

    def test_output_digest_tamper(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            path = run_dir / "K1-plain.stdout.txt"
            path.write_text(path.read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "output digest"):
                verify_run(run_dir)

    def test_summary_tamper(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            summary = parse_json((run_dir / "SUMMARY.json").read_text(encoding="utf-8"))
            summary["real_data_readiness"] = "READY"
            (run_dir / "SUMMARY.json").write_text(canonical(summary) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "summary"):
                verify_run(run_dir)

    def test_extra_receipt_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            with (run_dir / "receipts.jsonl").open("a", encoding="utf-8") as handle:
                handle.write((run_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()[0] + "\n")
            with self.assertRaisesRegex(ValueError, "coverage"):
                verify_run(run_dir)

    def test_lock_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = self.copy_locked_sources(raw)
            (root / "PROTOCOL.md").write_text((root / "PROTOCOL.md").read_text(encoding="utf-8") + "changed\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                verify_lock(root)

    def test_wrong_target_rejected(self):
        with self.assertRaisesRegex(ValueError, "target commit mismatch"):
            validate_target(ROOT, self.cases)

    def test_public_output_redacts_local_paths(self):
        with tempfile.TemporaryDirectory() as raw:
            checkout = Path(raw) / "checkout"
            target = checkout / "suite"
            run_dir = Path(raw) / "run"
            paths = [
                str(Path(sys.prefix)) + "/lib/python.py",
                "/" + "Users" + "/example/private/file",
                "/" + "home" + "/example/private/file",
                "/opt/homebrew/private/file",
                "/var/folders/example/private/file",
                "/private/var/example/private/file",
            ]
            text, count = public_output(" ".join([str(target) + "/error", *paths]), checkout, target, run_dir)
            for path in [str(target), *paths]:
                self.assertNotIn(path, text)
            self.assertIn("<target>", text)
            self.assertIn("<python-home>", text)
            self.assertEqual(text.count("<local-path>"), len(paths) - 1)
            self.assertGreaterEqual(count, len(paths) + 1)

    def test_unlisted_public_file_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            (run_dir / "unlisted.txt").write_text("unlisted evidence\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "public manifest"):
                verify_run(run_dir)

    def test_unexpected_source_field_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            source = parse_json((run_dir / "SOURCE.json").read_text(encoding="utf-8"))
            source["unexpected"] = "unbound"
            (run_dir / "SOURCE.json").write_text(canonical(source) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "source schema"):
                verify_run(run_dir)

    def test_unredacted_public_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            run_dir = self.make_run(raw)
            path = run_dir / "U01-plain.stderr.txt"
            path.write_text("/var/folders/example/private/file\n", encoding="utf-8")
            receipt_lines = (run_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
            receipt = parse_json(receipt_lines[0])
            receipt["stderr_sha256"] = sha256_text(path.read_text(encoding="utf-8"))
            receipt["stderr_redactions"] = 1
            receipt.pop("receipt_sha256", None)
            receipt["receipt_sha256"] = sha256_text(canonical(receipt))
            receipt_lines[0] = canonical(receipt)
            (run_dir / "receipts.jsonl").write_text("\n".join(receipt_lines) + "\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "forbidden path"):
                verify_run(run_dir)

    def test_no_bare_assert_in_trust_path(self):
        for path in source_files(ROOT):
            if path.suffix != ".py":
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            bare = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Assert)]
            self.assertEqual(bare, [], str(path))


if __name__ == "__main__":
    unittest.main()
