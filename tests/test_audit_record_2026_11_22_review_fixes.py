"""Regression tests for the 2026-11-26 review fixes on the audits/2026-11-22 record (PR #43 review).

Covers the review items closed on 2026-11-26:
- WD43-01: falsify_probe.py manifest-sha parse bug and uncaught crashes on fail-closed
  branches (F3/F6 wrapped), plus the same crash class in laneA_probes.py (P2 wrapped).
- WD43-02: internal bus/agent metadata removed from the public audit record.
- WD43-03: checkers run on stdlib-only Python or skip the optional-dependency check
  with a clear SKIP message (jsonschema / pytest).
- WD43-04: doc/manifest contradictions in the audit README and issues.md.
- CodeQL clear-text logging: laneD_checker.py prints digests, never raw file text.

Each test fails on the unfixed checker/doc code (verified by reasoning against the
pre-fix file contents; no git revert was used).
"""

import hashlib
import importlib.util
import io
import re
import json
import subprocess
import sys
import unittest
from contextlib import contextmanager, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "audits" / "2026-11-22"
CHECKERS = AUDIT / "checkers"

# Internal coordination names are matched by SHA-256 of the lowercased word,
# so this public file does not carry them. Generic bus pointers are matched by
# pattern.
FORBIDDEN_WORD_SHA256 = {
    "e42edcc44a64a41c049d5a2c9741d5b049ad442d1722f7885ff644b67a437084",
    "4451eb2f43d95fcc3ab30d59b0ebeed1a8bfad8ab65f5c6b797d2f611aa8df1d",
}
FORBIDDEN_PATTERNS = [re.compile(r"\bbus\s+seq\b", re.I), re.compile(r"\bseq\s+\d{3,}\b", re.I)]


def forbidden_hits(text):
    hits = [pat.pattern for pat in FORBIDDEN_PATTERNS if pat.search(text)]
    for word in re.findall(r"[A-Za-z][A-Za-z0-9-]*", text):
        if hashlib.sha256(word.lower().encode("utf-8")).hexdigest() in FORBIDDEN_WORD_SHA256:
            hits.append("internal-name")
    return hits


def run_checker(name, *args):
    return subprocess.run(
        [sys.executable, "-I", "-B", str(CHECKERS / name), *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )


@contextmanager
def blocked(*module_names):
    """Make the named imports raise ImportError, simulating a stdlib-only host."""
    saved = {m: sys.modules.get(m) for m in module_names}
    for m in module_names:
        sys.modules[m] = None
    try:
        yield
    finally:
        for m, old in saved.items():
            if old is None:
                sys.modules.pop(m, None)
            else:
                sys.modules[m] = old


def load_checker(name):
    spec = importlib.util.spec_from_file_location(
        "audit_checker_under_test_" + name.replace(".py", ""), CHECKERS / name
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def exec_checker_capturing(name):
    """Run a checker script in-process, returning (stdout, raised exception or None)."""
    buf = io.StringIO()
    exc = None
    try:
        with redirect_stdout(buf):
            load_checker(name)
    except BaseException as e:  # the unfixed scripts raise at import time
        exc = e
    return buf.getvalue(), exc


class TestAuditRecordReviewFixes2026_11_26(unittest.TestCase):
    # WD43-01: manifest sha256 file compare must use the first whitespace field.
    def test_falsify_probe_manifest_file_sha_uses_first_field(self):
        r = run_checker("falsify_probe.py")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("MAN_file_sha_match=True", r.stdout)
        self.assertNotIn("MAN_file_sha_match=False", r.stdout)

    # WD43-01: F3/F6 probes must not crash on fail-closed branches; they emit
    # raise:<ExcType> lines like F1/F4/F9/F10 already do.
    def test_falsify_probe_emits_f3_and_f6_lines_on_fixed_tree(self):
        r = run_checker("falsify_probe.py")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("F3_nan_verdict=", r.stdout)
        self.assertIn("F6_bool_id=", r.stdout)
        self.assertIn("F3_nan_verdict=raise:ControllerError", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    # WD43-01 (same crash class, found live on the merged tree): laneA_probes P2.
    def test_laneA_probes_p2_wrapped_and_runs_clean(self):
        r = run_checker("laneA_probes.py")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        self.assertIn("P2_nan_policy:", r.stdout)
        self.assertNotIn("Traceback", r.stderr)

    # WD43-02: no internal bus/agent/sequence tokens anywhere in the audit record.
    def test_no_internal_bus_metadata_in_audit_record(self):
        hits = []
        for p in sorted(AUDIT.rglob("*")):
            if p.is_file():
                text = p.read_text(encoding="utf-8", errors="ignore")
                if forbidden_hits(text):
                    hits.append(f"{p.relative_to(AUDIT)}")
        self.assertEqual(hits, [])

    # WD43-03: laneB_checker skips schema rows with a clear message when
    # jsonschema is absent instead of crashing with ModuleNotFoundError.
    def test_laneB_skips_schema_checks_without_jsonschema(self):
        with blocked("jsonschema"):
            buf = io.StringIO()
            exc = None
            rc = None
            try:
                with redirect_stdout(buf):
                    mod = load_checker("laneB_checker.py")
                    rc = mod.main(["laneB_checker.py", str(ROOT)])
            except BaseException as e:  # noqa: BLE001
                exc = e
        self.assertIsNone(exc)
        self.assertEqual(rc, 0)
        self.assertIn("SKIP schema_checks jsonschema not installed", buf.getvalue())
        self.assertIn("SUMMARY", buf.getvalue())

    # WD43-03: laneA_probes3 runs with inline stdlib fakes, no pytest needed.
    def test_laneA_probes3_runs_with_stdlib_only(self):
        with blocked("pytest", "test_experiment_controller"):
            out, exc = exec_checker_capturing("laneA_probes3.py")
        self.assertIsNone(exc)
        self.assertIn("P8_mount_before_digest_record", out)
        self.assertIn("digest_recorded_before_mount=", out)

    # WD43-03: laneA_probes2 P8 prints a clear SKIP (not an ERR) without pytest.
    def test_laneA_probes2_p8_skip_message_without_pytest(self):
        with blocked("pytest", "test_experiment_controller"):
            out, exc = exec_checker_capturing("laneA_probes2.py")
        self.assertIsNone(exc)
        self.assertIn("P8_order_fakes: SKIP", out)
        self.assertNotIn("P8_order_fakes: ERR", out)

    # WD43-03: falsify_probe schema rows skip with a clear message without jsonschema.
    def test_falsify_probe_schema_skip_without_jsonschema(self):
        with blocked("jsonschema"):
            out, exc = exec_checker_capturing("falsify_probe.py")
        self.assertIsNone(exc)
        self.assertIn("SCHEMA_check=skip:jsonschema-not-installed", out)
        self.assertIn("SCHEMA_steelman_check=skip:jsonschema-not-installed", out)
        self.assertNotIn("ModuleNotFoundError", out)

    # WD43-03: run_pytest_iso skips cleanly (rc 0, clear message) without pytest.
    def test_run_pytest_iso_skips_cleanly_without_pytest(self):
        with blocked("pytest"):
            out, exc = exec_checker_capturing("run_pytest_iso.py")
        self.assertIsInstance(exc, SystemExit)
        self.assertEqual(exc.code, 0)
        self.assertIn("SKIP", out)
        self.assertIn("pytest", out)

    # CodeQL clear-text logging: laneD prints digests, never raw file text, and
    # parses manifest.sha256 with split()[0] (no trailing filename in the value).
    def test_laneD_output_redacted_and_manifest_field_is_bare_digest(self):
        r = run_checker("laneD_checker.py")
        self.assertEqual(r.returncode, 0, r.stderr[-500:])
        data = json.loads(r.stdout)
        for raw_key in ("pyproject_text", "init_text_repr", "gitignore_text", "LICENSE_first200"):
            self.assertNotIn(raw_key, data)
        self.assertRegex(data["pyproject_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(data["init_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(data["pyproject_dependencies_count"], 0)
        expected = hashlib.sha256(
            (ROOT / "experiments/demo-2026-11-22/manifest.json").read_bytes()
        ).hexdigest()
        self.assertEqual(data["manifest_sha256_file"], expected)
        self.assertNotIn(" ", data["manifest_sha256_file"])

    # WD43-04: doc contradictions resolved in the audit README and issues.md,
    # and MANIFEST.sha256 holds digest+filename lines that verify.
    def test_doc_contradictions_resolved_and_manifest_verifies(self):
        readme = (AUDIT / "README.md").read_text(encoding="utf-8")
        issues = (AUDIT / "issues.md").read_text(encoding="utf-8")
        self.assertNotIn("Byte counts sit in MANIFEST.sha256", readme)
        self.assertIn("SHA-256 digests and file names only", readme)
        self.assertIn("15 counted defects plus 1 open product question", readme)
        self.assertNotIn("Nothing has been filed", readme)
        self.assertNotIn("Nothing below has been filed", issues)
        self.assertIn("so its hash changes with every commit and is not pinned", readme)
        manifest = (AUDIT / "MANIFEST.sha256").read_text(encoding="utf-8")
        lines = [l for l in manifest.splitlines() if l.strip()]
        self.assertEqual(len(lines), 10)
        for line in lines:
            self.assertRegex(line, r"^[0-9a-f]{64}  \S+$")
            digest, rel = line.split(None, 1)
            path = AUDIT / rel.strip()
            self.assertTrue(path.exists(), rel)
            actual = hashlib.sha256(path.read_bytes()).hexdigest()
            self.assertEqual(digest, actual, rel)


if __name__ == "__main__":
    unittest.main()
