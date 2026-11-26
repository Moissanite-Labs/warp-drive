#!/usr/bin/env python3
"""Write the source hash lock before any POC execution."""

from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from run import ROOT, canonical, parse_json, sha256_bytes, source_files


def main():
    cases = parse_json((ROOT / "cases.json").read_text(encoding="utf-8"))
    files = {str(path.relative_to(ROOT)): sha256_bytes(path.read_bytes()) for path in source_files(ROOT)}
    lock = {
        "schema": "warp-drive.cave-four-transformations.lock.v1",
        "target_commit": cases["target"]["commit"],
        "aletheia_commit": cases["aletheia"]["commit"],
        "cases_sha256": sha256_bytes((ROOT / "cases.json").read_bytes()),
        "files": files,
    }
    (ROOT / "LOCK.json").write_text(canonical(lock) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
