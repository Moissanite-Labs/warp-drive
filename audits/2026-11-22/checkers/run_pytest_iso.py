#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
import sys
from pathlib import Path
_R = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_R / "src"))
sys.path.insert(0, str(_R))
import pytest
sys.exit(pytest.main(sys.argv[1:]))
