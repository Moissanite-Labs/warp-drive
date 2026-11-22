#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
import json
import pathlib
import re
import subprocess
import sys
import hashlib

ROOT = pathlib.Path(__file__).resolve().parents[3]
out = {}
errs = []

def need(cond, msg):
    if not cond:
        errs.append(msg)

# git head
head = subprocess.check_output(["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True).strip()
out["head"] = head
tracked = subprocess.check_output(["git", "-C", str(ROOT), "ls-files"], text=True).splitlines()
out["tracked_count"] = len(tracked)
out["tracked"] = tracked

# modules: src/warp_modeld/*.py inc __init__
mods = sorted((ROOT / "src/warp_modeld").glob("*.py"))
out["modules_inc_init"] = len(mods)
out["modules_names"] = [p.name for p in mods]
out["modules_excl_init"] = len([p for p in mods if p.name != "__init__.py"])
# lines: count lines per file (python readlines)
total_lines = 0
per = {}
for p in mods:
    n = len(p.read_text(encoding="utf-8").splitlines())
    per[p.name] = n
    total_lines += n
out["lines_total_inc_init"] = total_lines
out["lines_per_module"] = per
out["lines_excl_init"] = total_lines - per.get("__init__.py", 0)
# also wc -l semantics (newline count)
wc_total = 0
for p in mods:
    wc_total += p.read_bytes().count(b"\n")
out["lines_wc_style"] = wc_total
# init lines detail
initp = ROOT / "src/warp_modeld/__init__.py"
out["init_text_repr"] = repr(initp.read_text(encoding="utf-8")) if initp.exists() else None

# test files
t_all = sorted((ROOT / "tests").glob("*.py"))
out["tests_all_py"] = [p.name for p in t_all]
out["tests_all_py_count"] = len(t_all)
t_test = sorted((ROOT / "tests").glob("test_*.py"))
out["test_files_testprefix"] = [p.name for p in t_test]
out["test_files_testprefix_count"] = len(t_test)
# studies tests
study_tests = sorted(ROOT.rglob("studies/**/test_*.py"))
out["studies_test_files"] = [str(p.relative_to(ROOT)) for p in study_tests]

# canaries
vc = json.loads((ROOT / "schemas/verifier-canaries.json").read_text(encoding="utf-8"))
out["verifier_canaries_len"] = len(vc["canaries"])
out["verifier_canary_ids"] = [c["canary_id"] for c in vc["canaries"]]

# demo suites
def suite_n(rel):
    d = json.loads((ROOT / rel).read_text(encoding="utf-8"))
    if "cases" in d:
        return (len(d["cases"]), d.get("n_cases"))
    if "canary_ids" in d:
        return (len(d["canary_ids"]), d.get("n_canaries"))
    return (None, None)
out["suite_task"] = suite_n("experiments/demo-2026-11-22/suites/task.json")
out["suite_retention_iid"] = suite_n("experiments/demo-2026-11-22/suites/retention_iid.json")
out["suite_retention_shifted"] = suite_n("experiments/demo-2026-11-22/suites/retention_shifted.json")
out["suite_safety"] = suite_n("experiments/demo-2026-11-22/suites/safety_canaries.json")
audit = json.loads((ROOT / "experiments/demo-2026-11-22/audit/split_leakage.json").read_text(encoding="utf-8"))
out["audit_reusing"] = audit["reusing_train_pair"]
out["audit_held_out"] = audit["held_out_states"]
out["audit_fraction"] = audit["reuse_fraction"]
# verify combined digest
order = ["experiments/demo-2026-11-22/suites/task.json", "experiments/demo-2026-11-22/suites/retention_iid.json", "experiments/demo-2026-11-22/suites/retention_shifted.json", "experiments/demo-2026-11-22/suites/safety_canaries.json"]
h = hashlib.sha256()
for rel in order:
    h.update((ROOT / rel).read_bytes())
out["combined_digest_recomputed"] = h.hexdigest()
manifest = json.loads((ROOT / "experiments/demo-2026-11-22/manifest.json").read_text(encoding="utf-8"))
out["combined_digest_pinned"] = manifest["digests"]["combined_suites"]
out["manifest_sha256_file"] = (ROOT / "experiments/demo-2026-11-22/manifest.sha256").read_text(encoding="utf-8").strip()
out["manifest_file_sha256"] = hashlib.sha256((ROOT / "experiments/demo-2026-11-22/manifest.json").read_bytes()).hexdigest()

# LICENSE / NOTICE
out["LICENSE_exists"] = (ROOT / "LICENSE").exists()
lic = (ROOT / "LICENSE").read_text(encoding="utf-8", errors="replace") if (ROOT / "LICENSE").exists() else ""
out["LICENSE_first200"] = lic[:200]
out["NOTICE_exists_root"] = (ROOT / "NOTICE").exists()
out["NOTICE_paths_tracked"] = [t for t in tracked if "NOTICE" in t]
out["LICENSE_paths_tracked"] = [t for t in tracked if "LICENSE" in t]

# CRLF among tracked files
crlf = []
for t in tracked:
    b = (ROOT / t).read_bytes()
    if b"\r\n" in b:
        crlf.append(t)
out["crlf_files"] = crlf

# tracked artifacts
arts = [t for t in tracked if "__pycache__" in t or t.endswith(".pyc") or "/dist/" in t or "/build/" in t or t.endswith(".egg-info") or ".egg-info/" in t]
out["tracked_artifacts"] = arts
out["gitignore_text"] = (ROOT / ".gitignore").read_text(encoding="utf-8") if (ROOT / ".gitignore").exists() else None

# home path leaks: absolute home prefixes in tracked text files, count hits per file (no values beyond path prefix count)
home_hits_files = {}
for t in tracked:
    try:
        txt = (ROOT / t).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        continue
    c = txt.count("/" + "Users" + "/") + txt.count("/" + "home" + "/")
    if c:
        home_hits_files[t] = c
out["home_leak_files_counts"] = home_hits_files

# secret-shaped patterns: counts only, never values. Patterns kept narrow.
patterns = {
    "gh_token": r"gh[oprsu]_[A-Za-z0-9_]{20,}",
    "aws_key": r"AKIA[0-9A-Z]{16}",
    "private_key_header": r"BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY",
    "cerebras_or_api_key_assign": r"(CEREBRAS_API_KEY|OPENAI_API_KEY|api[_-]?key\s*[:=])",
    "bearer_token": r"Bearer\s+[A-Za-z0-9_\-\.]{20,}",
    "generic_hex_secret_assign": r"(secret|password|passwd)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
}
secret_counts = {}
for name, pat in patterns.items():
    total = 0
    files = 0
    for t in tracked:
        txt = (ROOT / t).read_text(encoding="utf-8", errors="ignore")
        m = len(re.findall(pat, txt))
        if m:
            total += m
            files += 1
    secret_counts[name] = {"hits": total, "files": files}
# BEGIN PRIVATE KEY appears in canary must_not_contain - note context by file name only
pk_files = []
for t in tracked:
    txt = (ROOT / t).read_text(encoding="utf-8", errors="ignore")
    if "BEGIN PRIVATE KEY" in txt or "PRIVATE KEY" in txt:
        pk_files.append(t)
out["private_key_string_files"] = pk_files
out["secret_pattern_counts"] = secret_counts

# pyproject raw
out["pyproject_text"] = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

# blueprint files count
bp = sorted([str(p.relative_to(ROOT)) for p in ROOT.rglob("blueprints/**") if p.is_file()])
out["blueprint_files"] = bp
out["blueprint_count"] = len(bp)
# schemas
sc = sorted([p.name for p in (ROOT / "schemas").glob("*") if p.is_file()])
out["schema_files"] = sc
# studies dirs
out["studies_dirs"] = sorted([p.name for p in (ROOT / "studies").iterdir() if p.is_dir()])

# live timing / cerebras strings present in README (line refs)
readme_lines = (ROOT / "README.md").read_text(encoding="utf-8").splitlines()
out["readme_lines_total"] = len(readme_lines)
# find quantitative tokens
out["readme_53_present"] = ["53" in l for l in readme_lines]
# record matching line numbers for key needles without copying secrets (these are doc claims)
needles = ["53 passing", "16.71", "4.90", "4.22", "84,384", "UNVERIFIED", "zero-dependency", "lattice", "Cerebras", "three calls"]
hits = {}
for n in needles:
    hits[n] = [i + 1 for i, l in enumerate(readme_lines) if n.lower() in l.lower()]
out["readme_needle_lines"] = hits

print(json.dumps(out, indent=2, sort_keys=True))
if errs:
    print("ERRORS:" + json.dumps(errs), file=sys.stderr)
    sys.exit(1)
sys.exit(0)
