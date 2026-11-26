#!/usr/bin/env python3
"""Materialize the immutable v1 case list from the reviewed corpus specification."""

from __future__ import annotations

import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SONGE = "studies/expedition-songe-distill-governance/songe_distill_governance_audit.py"


def dump(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")) + "\n"


def main() -> int:
    source = json.loads((ROOT / "corpus.build.json").read_text(encoding="utf-8"))
    cases = []
    valid = source["governance_valid"]
    cases.append({"id": "G00", "target": SONGE, "request": {"op": "governance", "input": valid}, "expect": "admit"})
    for mutant in source["governance_mutants"]:
        config = copy.deepcopy(valid)
        for key in mutant.get("delete", []):
            del config[key]
        config.update(mutant.get("set", {}))
        case = {key: value for key, value in mutant.items() if key not in {"set", "delete"}}
        case.setdefault("expect", "reject")
        case.update({"target": SONGE, "request": {"op": "governance", "input": config}})
        cases.append(case)
    for item in source["gate_cases"]:
        request = copy.deepcopy(source["gate_defaults"])
        request["conversation_outcomes"] = item["conversation_outcomes"]
        request.update(item.get("set", {}))
        case = {key: value for key, value in item.items() if key not in {"set", "conversation_outcomes"}}
        case.update({"target": SONGE, "request": {"op": "cluster_gate", "input": request}})
        cases.append(case)
    for item in source["gradient_cases"]:
        case = dict(item)
        case.update({"target": SONGE, "request": {"op": "binary_gradients", "input": {"p0": item["p0"], "q0": item["q0"]}}, "expect": "exact"})
        cases.append(case)
    ids = [case["id"] for case in cases]
    if len(ids) != len(set(ids)):
        raise ValueError("duplicate case id")
    document = {"schema": "warp-drive.ratchet-001.cases.v1", "cases": cases}
    (ROOT / "corpus.json").write_text(dump(document), encoding="utf-8", newline="\n")
    print(len(cases))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
