#!/usr/bin/env python3
# Audit checker copy, 2026-11-22. Run from the repo root, for example: python3 -I -B audits/2026-11-22/checkers/<name>.py
# The repo root is derived from this file location. No edit is needed.
import sys
from pathlib import Path
_R = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_R / "src"))
sys.path.insert(0, str(_R))
try:
    import pytest
except ImportError:
    print("SKIP: pytest is not importable in this isolated run (python3 -I -B on a stdlib-only host); "
          "run 'PYTHONPATH=src python3 -B -m pytest <args>' on a host where pytest is installed")
    sys.exit(0)
sys.exit(pytest.main(sys.argv[1:]))
