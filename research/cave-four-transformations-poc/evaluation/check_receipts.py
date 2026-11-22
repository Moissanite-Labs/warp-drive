#!/usr/bin/env python3
"""Verify an existing POC run without executing Cave's tests."""

import argparse
import json
from pathlib import Path
import sys

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

from run import verify_run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="clean Cave checkout at the locked commit")
    parser.add_argument("--run", required=True, help="existing receipt directory")
    args = parser.parse_args()
    result = verify_run(Path(args.run), checkout=Path(args.target))
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] == "REFERENCE_REPLAY_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
