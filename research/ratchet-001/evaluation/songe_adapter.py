#!/usr/bin/env python3
"""Minimal interface between a fixed case and the verifier under test."""

from __future__ import annotations

import argparse
from fractions import Fraction
import importlib.util
import json
import math
from pathlib import Path
from typing import Any


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _decode_exact(value: Any) -> Any:
    if isinstance(value, dict):
        if set(value) == {"num", "den"}:
            num = value["num"]
            den = value["den"]
            if type(num) is not int or type(den) is not int:
                raise ValueError("rational numerator and denominator must be integers")
            if den <= 0 or math.gcd(abs(num), den) != 1:
                raise ValueError("rational must be canonical with positive denominator")
            return Fraction(num, den)
        return {key: _decode_exact(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_decode_exact(item) for item in value]
    return value


def _load_module(target: Path) -> Any:
    spec = importlib.util.spec_from_file_location("ratchet_001_verifier_under_test", target)
    if spec is None or spec.loader is None:
        raise ValueError("cannot load verifier under test")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _invoke(module: Any, request: dict[str, Any]) -> Any:
    op = request["op"]
    data = _decode_exact(request["input"])
    if op == "governance":
        return module.evaluate_songe_governance_boundary(data)
    if op == "cluster_gate":
        outcomes = data["conversation_outcomes"]
        if not isinstance(outcomes, list):
            raise ValueError("conversation_outcomes must be a list")
        converted = []
        for item in outcomes:
            if not isinstance(item, list) or len(item) != 2:
                raise ValueError("each outcome must be a two-element list")
            converted.append((item[0], item[1]))
        return module.hardened_clustered_ville_gate(
            converted,
            data["alpha"],
            data["num_scales"],
            data["min_conversations"],
            data["fused_rejudged"],
            data["drift"],
            data["drift_limit"],
        )
    if op == "binary_gradients":
        return module.binary_saturated_logit_gradients(data["p0"], data["q0"])
    raise ValueError("unknown operation")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--case", type=Path, required=True)
    args = parser.parse_args()
    request = json.loads(args.case.read_text(encoding="utf-8"), object_pairs_hook=_unique_object)
    if not isinstance(request, dict) or set(request) != {"op", "input"}:
        raise ValueError("case request must contain exactly op and input")
    result = _invoke(_load_module(args.target), request)
    rendered = json.dumps(
        result,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
