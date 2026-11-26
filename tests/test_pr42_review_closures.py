"""Regression tests closing PR #42 review findings (WD42-01..04 + LICENSE note).

Each test fails on the unfixed code:
- WD42-01: --check must ignore build-time metadata (source_main_sha), the
  records must cover every studies/ directory, and the git ref choice must
  fall back to HEAD when no origin remote exists.
- WD42-02: pinned_commit must be read from the certificate files (a list of
  declared commits, or null when none is declared), never hardcoded.
- WD42-03: workflows must bind github.repository via env:, pin actions to
  commit SHAs, distinguish API failure from a non-Actions Pages source, and
  run the Python checks as python3 -I -B.
- WD42-04: the static site counts must match the tree (scripts/check_site.py
  fails otherwise) and every page footer must cite the same main sha.
- BLOCKING 1 (test-count relabel): no page may put "counted at main" next
  to a test-runner total, and home plus verifier must carry the branch-head
  label with the pytest command and main 3a458ac's own figures (256/2, 139/2).
- Vendor LICENSE carries no extra leading blank line.
"""

from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
DOCS = ROOT / "docs"


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


be = _load("build_expeditions", SCRIPTS / "build_expeditions.py")


def _run_check(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", "-B", *args],
        cwd=ROOT, capture_output=True, text=True,
    )


class WD42_01_CheckIndependentOfMainSha(unittest.TestCase):
    def test_check_ignores_build_time_metadata(self):
        data = be.build()
        tampered = json.loads(json.dumps(data))
        tampered["source_main_sha"] = "deadbee"
        tampered["generated_at"] = "other"
        self.assertTrue(be.fresh(tampered, data), "source_main_sha must not gate --check")
        changed = json.loads(json.dumps(data))
        changed["records"][0]["summary"] = changed["records"][0]["summary"] + " x"
        self.assertFalse(be.fresh(changed, data), "record changes must still fail --check")

    def test_records_cover_every_study_dir(self):
        studies = {d.name for d in (ROOT / "studies").iterdir() if d.is_dir()}
        records = be.build()["records"]
        study_slugs = {r["slug"] for r in records if r["kind"] == "study"}
        self.assertEqual(study_slugs, studies)
        proc = _run_check("scripts/build_expeditions.py", "--check")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_ref_falls_back_to_head_without_origin(self):
        self.assertEqual(be.choose_ref("origin\nupstream\n", True), "origin/main")
        self.assertEqual(be.choose_ref("upstream\n", True), "HEAD")
        self.assertEqual(be.choose_ref("origin\n", False), "HEAD")
        self.assertEqual(be.choose_ref("", False), "HEAD")


class WD42_02_PinnedCommitsFromCertificates(unittest.TestCase):
    def _certs(self, study: str) -> list[Path]:
        return sorted((ROOT / "studies" / study).glob("*certificate*.json"))

    def test_collector_reads_declared_fields(self):
        self.assertEqual(
            be.pinned_commits(self._certs("expedition-reinforce-zero-tii")),
            ["136aca87", "a22153de"],
        )
        self.assertEqual(be.pinned_commits(self._certs("expedition-songe-distill-governance")), ["5b7b1376"])
        self.assertEqual(be.pinned_commits(self._certs("expedition-weight-iteration-bridge")), ["e3899d3e"])
        self.assertIsNone(be.pinned_commits(self._certs("expedition-bounded-controller")))
        self.assertIsNone(be.pinned_commits(self._certs("expedition-bareiss-gram-cert")))

    def test_records_match_their_certificates(self):
        by_slug = {r["slug"]: r for r in be.build()["records"]}
        for study in sorted(d.name for d in (ROOT / "studies").iterdir() if d.is_dir()):
            rec = by_slug[study]
            self.assertEqual(rec["pinned_commit"], be.pinned_commits(self._certs(study)),
                             f"{study} pinned_commit must equal the certificate-declared set")
            self.assertNotEqual(rec["pinned_commit"], "e3899d3e",
                                "hardcoded e3899d3e is the unfixed behaviour")

    def test_schema_allows_list_or_null(self):
        schema = json.loads((DOCS / "data" / "expeditions.schema.json").read_text())
        t = schema["properties"]["records"]["items"]["properties"]["pinned_commit"]["type"]
        self.assertIn("array", t)
        self.assertIn("null", t)


class WD42_03_Workflows(unittest.TestCase):
    def setUp(self):
        self.pages = (ROOT / ".github" / "workflows" / "pages.yml").read_text()
        self.site = (ROOT / ".github" / "workflows" / "site.yml").read_text()

    def test_actions_pinned_to_commit_shas(self):
        pins = [
            ("actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4", (self.pages, self.site)),
            ("actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4", (self.site,)),
            ("actions/upload-pages-artifact@56afc609e74202658d3ffba0e8f6dda462b719fa # v3", (self.pages,)),
            ("actions/deploy-pages@d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e # v4", (self.pages,)),
        ]
        for needle, texts in pins:
            for text in texts:
                self.assertIn(needle, text)
        for text in (self.pages, self.site):
            for m in re.findall(r"uses:\s*(.+)$", text, re.M):
                self.assertRegex(m.strip(), r"@[0-9a-f]{40} # v\d+$", f"unpinned action {m}")

    def test_repository_bound_via_env_not_interpolated(self):
        self.assertIn("REPO: ${{ github.repository }}", self.pages)
        self.assertIn('"https://api.github.com/repos/$REPO/pages"', self.pages)
        self.assertNotIn("repos/${{ github.repository }}", self.pages,
                         "github.repository must not be interpolated inside run:")
        self.assertEqual(self.pages.count("${{ github.repository }}"), 1,
                         "the expression may only appear in the env: binding")

    def test_api_errors_fail_and_are_distinguished(self):
        self.assertNotIn("|| true", self.pages)
        self.assertIn("::error::API call failed", self.pages)
        self.assertIn('elif [ "$code" = "404" ]', self.pages)
        self.assertIn('if [ "$type" = "workflow" ]', self.pages)
        self.assertIn("publish=false", self.pages)

    def test_pages_checkout_fetches_full_history(self):
        self.assertRegex(
            self.pages,
            r"actions/checkout@[0-9a-f]{40} # v4\n\s+with:\n\s+persist-credentials: false\n\s+fetch-depth: 0",
        )

    def test_python_checks_run_isolated(self):
        for text in (self.pages, self.site):
            self.assertIn("python3 -I -B scripts/check_site.py", text)
            self.assertIn("python3 -I -B scripts/build_expeditions.py --check", text)


class WD42_04_SiteCountsMatchTree(unittest.TestCase):
    def test_site_gate_passes(self):
        proc = _run_check("scripts/check_site.py")
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_module_counts_match_tree(self):
        mods = {p.name: p.read_bytes().count(b"\n")
                for p in sorted((ROOT / "src" / "warp_modeld").glob("*.py"))}
        arch = (DOCS / "architecture" / "index.html").read_text()
        rows = {k: int(v) for k, v in re.findall(r'<th scope="row"><code>([^<]+)</code></th><td>(\d+)</td>', arch)}
        self.assertEqual(rows, mods)
        mmap = (DOCS / "assets" / "module-map.js").read_text()
        js_mods = {k: int(v) for k, v in re.findall(r'\["([^"]+)", (\d+),', mmap)}
        self.assertEqual(js_mods, mods)
        self.assertIn(f"Total: {sum(mods.values())} lines", arch)

    def test_every_page_cites_the_same_current_main_sha(self):
        pages = sorted(DOCS.rglob("*.html"))
        shas = set()
        for p in pages:
            m = re.search(r"This site cites main at ([0-9a-f]+)", p.read_text())
            self.assertIsNotNone(m, f"{p} footer missing main sha")
            shas.add(m.group(1))
        self.assertEqual(shas, {"3a458ac"})

    def test_runner_totals_labelled_by_commit_not_main(self):
        runner = re.compile(r"pytest|unittest|test files")
        for p in sorted(DOCS.rglob("*.html")):
            for line in p.read_text().splitlines():
                if "counted at main" in line and runner.search(line):
                    self.fail(f"{p.name} labels a test-runner total as counted at main: {line.strip()}")
        home = (DOCS / "index.html").read_text()
        ver = (DOCS / "verifier" / "index.html").read_text()
        for text, name in ((home, "home"), (ver, "verifier")):
            self.assertIn("counted on this branch head (main 3a458ac plus PR 42's test file)", text, name)
            self.assertIn("PYTHONPATH=src python3 -B -m pytest -q tests/", text, name)
            self.assertIn(
                "At main 3a458ac itself: pytest 256 passed, 2 skipped; unittest 139 ran, 2 skipped",
                text, name,
            )


class VendorLicenseLeadingBlankLine(unittest.TestCase):
    def test_no_leading_blank_line(self):
        data = (ROOT / "docs" / "assets" / "vendor" / "LICENSE").read_bytes()
        self.assertFalse(data.startswith(b"\n"))
        self.assertTrue(data.startswith(b" " * 33 + b"Apache License"))


if __name__ == "__main__":
    unittest.main()
