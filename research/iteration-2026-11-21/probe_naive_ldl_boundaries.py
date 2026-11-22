#!/usr/bin/env python3
"""Replay preregistered T6 controls against the merged study."""
from __future__ import annotations

import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent.parent
STUDY = ROOT / "studies" / "expedition-bareiss-gram-cert"
sys.path.insert(0, str(STUDY))

from bareiss_gram_gate import bareiss_symmetric_inertia, naive_rational_ldl_scale_bits  # noqa: E402


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def main() -> None:
    singular_psd_cases = (
        [[0]],
        [[0, 0], [0, 1]],
        [[1, 1], [1, 1]],
    )
    observed = []
    for matrix in singular_psd_cases:
        result = bareiss_symmetric_inertia(matrix)
        require(result["is_psd"], "singular PSD fixture rejected")
        bits = naive_rational_ldl_scale_bits(matrix)
        require(bits == 1, "unexpected naive-LDL comparison result")
        observed.append({
            "matrix": matrix,
            "inertia": list(result["inertia"]),
            "naive_ldl_bits": bits,
        })

    indefinite = [[0, 1], [1, 0]]
    primary = bareiss_symmetric_inertia(indefinite)
    require(not primary["is_psd"], "primary gate accepted an indefinite matrix")
    diagnostic_bits = naive_rational_ldl_scale_bits(indefinite)
    require(diagnostic_bits == 1, "diagnostic boundary changed")

    print(json.dumps({
        "schema": "warp-drive-research-t6/v1",
        "source_base": "38a7072f8d23fe865b4d48d1da285a6db4fc14d1",
        "singular_psd_cases": observed,
        "suspected_singular_psd_failure_reproduced": False,
        "indefinite_control": {
            "matrix": indefinite,
            "primary_gate_is_psd": primary["is_psd"],
            "diagnostic_only_naive_ldl_bits": diagnostic_bits,
        },
        "scope": "No claimed singular-PSD crash reproduced. The naive helper remains a diagnostic, not a PSD oracle.",
        "novelty": "N0",
    }, indent=2))


if __name__ == "__main__":
    main()
