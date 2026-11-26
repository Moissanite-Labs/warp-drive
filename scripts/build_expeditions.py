#!/usr/bin/env python3
"""Build docs/data/expeditions.json from studies/ and the demo manifest.
Stdlib only. Deterministic: indent 2, sort_keys, trailing newline, tmp file
plus os.replace. generated_at and source_main_sha are build-time metadata;
--check ignores both so CI proves freshness without gating on unrelated
commits to main (source_main_sha changes on every main commit). Dates come
from git log on origin/main, falling back to HEAD when no origin remote (or
no resolvable origin/main) exists."""
import json, os, re, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "data" / "expeditions.json"
# Curated one-sentence summaries. Each cites its README line basis.
SUMMARIES = {
    # studies/expedition-gram-cert-upgrades/README.md title line 1.
    "expedition-gram-cert-upgrades": "Checked Stage 2 Gram certificate upgrades with exact integer arithmetic and adversarial mutation tests.",
    # studies/expedition-trust-boundary-verifier/README.md title line 1.
    "expedition-trust-boundary-verifier": "Checked runtime, sandbox and cross-repo trust boundaries with two non-importing verifier suites.",
    # studies/expedition-bounded-controller/README.md scope notice lines 3-5.
    "expedition-bounded-controller": "Checked a study-only bounded experiment controller with synthetic digests and a fake runtime.",
    # studies/expedition-bareiss-gram-cert/README.md title line 1.
    "expedition-bareiss-gram-cert": "Checked a fraction-free Bareiss gate for stacked adapter Gram certificates with a dual oracle.",
    # studies/expedition-weight-iteration-bridge/README.md title line 1.
    "expedition-weight-iteration-bridge": "Checked governed weight iteration and multi-bank state isolation with exact fractions.",
    # studies/expedition-latent-lattice-2611-21608/README.md title line 1.
    "expedition-latent-lattice-2611-21608": "Checked latent lattice language model claims and a 4-bank isolation bridge with exact rational arithmetic.",
    # studies/expedition-reinforce-zero-tii/README.md title line 1.
    "expedition-reinforce-zero-tii": "Checked REINFORCE-Zero and zero-mismatch-rl governance claims with an exact Taylor-interval verifier against pinned read-only external checkouts.",
    # studies/expedition-siliconcordat-d5-audit104r4/README.md title line 1.
    "expedition-siliconcordat-d5-audit104r4": "Checked the siliconcordat discussion-5 portal extraction and two-zone airlock contracts with pure rational invariants.",
    # studies/expedition-songe-distill-governance/README.md title line 1.
    "expedition-songe-distill-governance": "Checked songe distillation governance and security boundaries against a pinned read-only songe checkout.",
    # experiments/demo-2026-11-22/manifest.json suites block.
    "demo-2026-11-22": "Demo lane contract with frozen suites and preregistered thresholds. It is not a study and has not run live.",
}
SCOPES = {
    "expedition-bounded-controller": "logic_check_fake_runtime, mock_contract",
    "expedition-trust-boundary-verifier": "non-importing logic checks, live read-only anchors",
    "expedition-latent-lattice-2611-21608": "standalone reference gates with exact arithmetic, not wired into src/",
    "expedition-reinforce-zero-tii": "standalone exact verifier, pinned read-only external checkouts",
    "expedition-siliconcordat-d5-audit104r4": "pure-rational portal invariants, standalone and pinned live modes",
    "expedition-songe-distill-governance": "standalone governance gates, pinned read-only songe checkout",
}

def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()

def choose_ref(remotes, origin_main_exists):
    # Main-branch ref for dates and the footer sha. Falls back to HEAD when
    # no origin remote exists or origin/main does not resolve (shallow or
    # differently named remote), so nothing depends on a hardcoded sha.
    if "origin" in remotes.split() and origin_main_exists:
        return "origin/main"
    return "HEAD"

def main_ref():
    return choose_ref(git("remote"), bool(git("rev-parse", "--verify", "--quiet", "origin/main")))

def last_touch(path):
    return git("log", "-1", "--format=%cs", main_ref(), "--", path) or "unknown"

COMMIT_RE = re.compile(r"[0-9a-f]{40}")

def pinned_commits(certs):
    """Pinned commit shas declared by the certificate files themselves.
    Any key containing "pinned" whose value is a 40-hex commit sha (or a
    dict of them, e.g. pinned_head_shas / pinned_read_only_anchors) counts;
    sha256 digests of files are not commits and are skipped. Returns the
    sorted unique 8-char prefixes, or None when nothing is declared."""
    found = set()
    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if "pinned" in k.lower():
                    for x in (v.values() if isinstance(v, dict) else [v]):
                        if isinstance(x, str) and COMMIT_RE.fullmatch(x):
                            found.add(x[:8])
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    for c in certs:
        walk(json.loads(c.read_text()))
    return sorted(found) or None

def audit_ids(readme, certs):
    text = readme.read_text(errors="replace") if readme.exists() else ""
    m = re.search(r"AUDIT-\d+R?\d?", text)
    readme_id = m.group(0) if m else None
    if "AUDIT-062R" in text and "AUDIT-065" in text:
        readme_id = "AUDIT-062R + AUDIT-065"
    json_ids = []
    for c in certs:
        data = json.loads(c.read_text())
        aid = data.get("audit_id") or (data.get("certificate") or {}).get("audit_id")
        if aid and aid not in json_ids:
            json_ids.append(aid)
    return readme_id, (" + ".join(json_ids) if json_ids else None)

def verdict_words(certs):
    words = []
    for c in certs:
        data = json.loads(c.read_text())
        flat = json.dumps(data)
        for w in ("PROMOTED", "REJECTED", "CONTROL_BASE_PASS", "ALL_VERIFIED"):
            if w in flat and w not in words:
                words.append(w)
        v = data.get("verdict")
        if isinstance(v, str) and v not in words:
            words.append(v)
    return words

def build():
    records = []
    for folder in sorted((ROOT / "studies").iterdir()):
        if not folder.is_dir():
            continue
        certs = sorted(folder.glob("*certificate*.json"))
        readme_id, json_id = audit_ids(folder / "README.md", certs)
        rel = "studies/" + folder.name
        records.append({
            "slug": folder.name,
            "name": folder.name.replace("expedition-", "").replace("-", " ").title(),
            "audit_id_readme": readme_id,
            "audit_id_json": json_id,
            "kind": "study",
            "summary": SUMMARIES.get(folder.name, "See the study README."),
            "verdicts": verdict_words(certs),
            "evidence_scope": SCOPES.get(folder.name),
            "has_certificate": bool(certs),
            "pinned_commit": pinned_commits(certs),
            "git_last_touch": last_touch(rel),
            "repo_path": rel,
        })
    manifest = json.loads((ROOT / "experiments/demo-2026-11-22/manifest.json").read_text())
    suites = manifest.get("suites", {})
    counts = ", ".join(str(suites[k]["cases"]) for k in ("task", "retention_iid", "retention_shifted", "safety_canaries") if k in suites)
    records.append({
        "slug": "demo-2026-11-22",
        "name": "Demo lane 2026-11-22",
        "audit_id_readme": None,
        "audit_id_json": None,
        "kind": "demo",
        "summary": SUMMARIES["demo-2026-11-22"] + " Suite cases: " + counts + ". Split leakage: 110 of 112 task cases reuse a seen pair, 20 distinct pairs.",
        "verdicts": [],
        "evidence_scope": "preregistered thresholds, unverified live; tokenizer digest unverified",
        "has_certificate": False,
        "pinned_commit": None,
        "git_last_touch": last_touch("experiments/demo-2026-11-22"),
        "repo_path": "experiments/demo-2026-11-22",
    })
    records.sort(key=lambda r: (r["git_last_touch"], r["slug"]), reverse=True)
    return {
        "generated_at": "build-time",
        "source_main_sha": git("rev-parse", main_ref())[:7] or "unknown",
        "notice": "Pinned commits are the ones each certificate declares (null when a certificate declares none); certificates pin older commits and do not certify current main. Dates are git last-touch dates on the main branch (origin/main, or HEAD when no origin remote exists), not authored expedition dates.",
        "records": records,
    }

def fresh(old, new):
    """--check comparison. generated_at and source_main_sha are build-time
    metadata and are excluded, so --check stays independent of unrelated
    commits to main."""
    a, b = dict(old), dict(new)
    for d in (a, b):
        d.pop("generated_at", None)
        d.pop("source_main_sha", None)
    return a == b

def main():
    data = build()
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("expeditions.json missing"); return 1
        old = json.loads(OUT.read_text())
        if not fresh(old, data):
            print("expeditions.json is stale; run scripts/build_expeditions.py"); return 1
        print("expeditions data is fresh"); return 0
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    tmp.write_text(text)
    os.replace(tmp, OUT)
    print("wrote", OUT, len(text), "bytes,", len(data["records"]), "records")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
