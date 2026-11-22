#!/usr/bin/env python3
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys

repo = Path(sys.argv[1]).resolve()
manifest_path = repo / "research/iteration-2026-11-21/MANIFEST.json"
manifest_bytes = manifest_path.read_bytes()
manifest = json.loads(manifest_bytes)
root = (repo / manifest["root"]).resolve()
errors = []
seen = set()
tracked = set(subprocess.check_output(
    ["git", "-C", str(repo), "ls-files", "-z", "--", manifest["root"]],
).decode("utf-8").split("\0"))
tracked.discard("")
relative_tracked = {
    PurePosixPath(path).relative_to(PurePosixPath(manifest["root"])).as_posix()
    for path in tracked
}
expected = {entry["path"] for entry in manifest["files"]}
if len(expected) != len(manifest["files"]):
    errors.append("duplicate manifest paths")
if manifest["file_count"] != len(manifest["files"]):
    errors.append("file_count does not equal entry count")
if manifest.get("manifest_excluded") is not True:
    errors.append("manifest_excluded is not true")
if "MANIFEST.json" in expected:
    errors.append("manifest unexpectedly lists itself")
missing = sorted(expected - relative_tracked)
uncovered = sorted(relative_tracked - expected - {"MANIFEST.json"})
if missing:
    errors.append(f"manifest entries absent from tracked tree: {missing}")
if uncovered:
    errors.append(f"tracked files omitted from manifest: {uncovered}")
checked = 0
for entry in manifest["files"]:
    rel = entry["path"]
    p = PurePosixPath(rel)
    if p.is_absolute() or ".." in p.parts:
        errors.append(f"unsafe path: {rel}")
        continue
    path = root / rel
    if not path.is_file() or path.is_symlink():
        errors.append(f"missing, non-file, or symlink: {rel}")
        continue
    data = path.read_bytes()
    actual_hash = hashlib.sha256(data).hexdigest()
    if len(data) != entry["bytes"]:
        errors.append(f"length mismatch: {rel}: expected {entry['bytes']}, got {len(data)}")
    if actual_hash != entry["sha256"]:
        errors.append(f"hash mismatch: {rel}: expected {entry['sha256']}, got {actual_hash}")
    checked += 1
result = {
    "repo": str(repo),
    "root": manifest["root"],
    "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
    "declared_file_count": manifest["file_count"],
    "manifest_entry_count": len(manifest["files"]),
    "tracked_files_excluding_manifest": len(relative_tracked - {"MANIFEST.json"}),
    "checked_files": checked,
    "missing": missing,
    "uncovered": uncovered,
    "errors": errors,
    "ok": not errors,
}
print(json.dumps(result, indent=2, sort_keys=True))
sys.exit(1 if errors else 0)
