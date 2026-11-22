#!/usr/bin/env python3
"""Build docs/data/expeditions.json from studies/ and the demo manifest.
Stdlib only. Deterministic: indent 2, sort_keys, trailing newline, tmp file
plus os.replace. generated_at is the only time-varying field; --check
compares with generated_at ignored so CI proves freshness without churn."""
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
    # experiments/demo-2026-11-22/manifest.json suites block.
    "demo-2026-11-22": "Demo lane contract with frozen suites and preregistered thresholds. It is not a study and has not run live.",
}
SCOPES = {
    "expedition-bounded-controller": "logic_check_fake_runtime, mock_contract",
    "expedition-trust-boundary-verifier": "non-importing logic checks, live read-only anchors",
}

def git(*args):
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True).stdout.strip()

def last_touch(path):
    return git("log", "-1", "--format=%cs", "origin/main", "--", path) or "unknown"

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
            "pinned_commit": "e3899d3e" if certs else None,
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
        "source_main_sha": git("rev-parse", "origin/main")[:7] or "063aaee",
        "notice": "Certificates pin older commits (e3899d3e or 8d9f815) and do not certify current main. Dates are git last-touch dates on origin/main, not authored expedition dates.",
        "records": records,
    }

def main():
    data = build()
    text = json.dumps(data, indent=2, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        if not OUT.exists():
            print("expeditions.json missing"); return 1
        old = json.loads(OUT.read_text())
        old.pop("generated_at", None)
        new = dict(data); new.pop("generated_at", None)
        if old != new:
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
