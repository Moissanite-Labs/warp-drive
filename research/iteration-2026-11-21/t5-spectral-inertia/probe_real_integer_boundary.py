#!/usr/bin/env python3
"""Bounded exact cross-oracle probe for Foundation-0/spectral-inertia main.

Read-only trial artifact under /tmp. No test is accepted by a bare assert.
"""
from __future__ import annotations

from collections import Counter
from fractions import Fraction
import importlib.util
import itertools
import json
import math
from pathlib import Path
import sys
from typing import Any

if len(sys.argv) != 3:
    raise SystemExit("usage: probe_real_integer_boundary.py SPECTRAL_REPO BAREISS_ORACLE")
REPO = Path(sys.argv[1]).resolve()
ORACLE = Path(sys.argv[2]).resolve()
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from spectral_inertia.dual_oracle import (  # noqa: E402
    oracle_faddeev_descartes_sturm,
    produce_pldl_certificate,
    verify_inertia_dual_oracle,
)
from spectral_inertia.exact_qi import CertError, Qi, ZERO, cmat_eye, matrix_to_json  # noqa: E402

spec = importlib.util.spec_from_file_location("external_bareiss_gram_gate", ORACLE)
if spec is None or spec.loader is None:
    raise RuntimeError("cannot load external Bareiss oracle")
bareiss_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bareiss_module)
bareiss_symmetric_inertia = bareiss_module.bareiss_symmetric_inertia


def req(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def to_qi(M: list[list[Fraction | int]]) -> list[list[Qi]]:
    return [[Qi(Fraction(v)) for v in row] for row in M]


def clear_denominators(M: list[list[Fraction | int]]) -> tuple[int, list[list[int]]]:
    scale = 1
    for row in M:
        for value in row:
            scale = math.lcm(scale, Fraction(value).denominator)
    req(scale > 0, "nonpositive clearing scale")
    return scale, [[int(Fraction(value) * scale) for value in row] for row in M]


def symmetric_matrices(n: int, values: list[int]):
    positions = [(i, j) for i in range(n) for j in range(i, n)]
    for upper in itertools.product(values, repeat=len(positions)):
        M = [[0 for _ in range(n)] for _ in range(n)]
        for (i, j), value in zip(positions, upper):
            M[i][j] = value
            M[j][i] = value
        yield M


def check_matrix(M: list[list[Fraction | int]], label: str) -> dict[str, Any]:
    scale, integer_scaled = clear_denominators(M)
    external = bareiss_symmetric_inertia(integer_scaled)
    expected = tuple(external["inertia"])
    M_qi = to_qi(M)
    produced = produce_pldl_certificate(M_qi)
    dual = verify_inertia_dual_oracle(produced, mode="pldl")
    spectral = oracle_faddeev_descartes_sturm(M_qi)
    actual = tuple(dual["inertia"])
    req(actual == expected, f"{label}: dual={actual}, Bareiss={expected}, M={M}")
    req(tuple(spectral["sturm_inertia"]) == expected, f"{label}: Sturm mismatch")
    return {
        "label": label,
        "inertia": actual,
        "singular": actual[2] > 0,
        "zero_diagonal": all(Fraction(M[i][i]) == 0 for i in range(len(M))),
        "producer_used_2x2": any(
            produced["D"][i][j] != "0"
            for i in range(len(M))
            for j in range(len(M))
            if abs(i - j) == 1
        ),
        "clearing_scale": scale,
    }


def direct_payload(M: list[list[int]], claim: list[int]) -> dict[str, Any]:
    n = len(M)
    return {
        "M": matrix_to_json(to_qi(M)),
        "P": list(range(n)),
        "L": matrix_to_json(cmat_eye(n)),
        "D": matrix_to_json(to_qi(M)),
        "claim": claim,
    }


def main() -> None:
    counts: Counter[str] = Counter()
    inertias: Counter[tuple[int, int, int]] = Counter()
    checked = 0
    max_clearing_scale = 1

    for n, values in ((2, [-2, -1, 0, 1, 2]), (3, [-1, 0, 1])):
        for index, M in enumerate(symmetric_matrices(n, values)):
            result = check_matrix(M, f"exhaustive_n{n}_{index}")
            checked += 1
            inertias[result["inertia"]] += 1
            counts["singular" if result["singular"] else "nonsingular"] += 1
            counts["zero_diagonal" if result["zero_diagonal"] else "nonzero_diagonal"] += 1
            counts["producer_2x2" if result["producer_used_2x2"] else "producer_1x1_only"] += 1

    rational_cases = [
        [[Fraction(1, 2), Fraction(1, 3)], [Fraction(1, 3), Fraction(2, 9)]],
        [[Fraction(0), Fraction(2, 3)], [Fraction(2, 3), Fraction(0)]],
        [[Fraction(-3, 2), Fraction(1, 5)], [Fraction(1, 5), Fraction(-2, 3)]],
        [[Fraction(3, 2), Fraction(0)], [Fraction(0), Fraction(0)]],
        [[Fraction(0), Fraction(1, 2), Fraction(0)], [Fraction(1, 2), Fraction(0), Fraction(0)], [Fraction(0), Fraction(0), Fraction(0)]],
        [[Fraction(2), Fraction(1), Fraction(0)], [Fraction(1), Fraction(1, 2), Fraction(1, 3)], [Fraction(0), Fraction(1, 3), Fraction(-1, 4)]],
    ]
    for index, M in enumerate(rational_cases):
        result = check_matrix(M, f"targeted_rational_{index}")
        checked += 1
        inertias[result["inertia"]] += 1
        max_clearing_scale = max(max_clearing_scale, result["clearing_scale"])

    # Producer/optimizer-isolated replay: explicit valid P=M permutation, L=I, D=M.
    witness = [[0, 1, 0], [1, 0, 0], [0, 0, 0]]
    witness_inertia = [1, 1, 1]
    replay = verify_inertia_dual_oracle(direct_payload(witness, witness_inertia), mode="pldl")
    req(replay["inertia"] == (1, 1, 1), "direct explicit-certificate replay failed")
    req(bareiss_symmetric_inertia(witness)["inertia"] == (1, 1, 1), "Bareiss replay mismatch")

    # Must-fail negative control: same explicit identity certificate with false inertia claim.
    try:
        verify_inertia_dual_oracle(direct_payload(witness, [2, 1, 0]), mode="pldl")
    except CertError as exc:
        negative_control = {"killed": True, "code": exc.code}
        req(exc.code == "INERTIA_CLAIM_MISMATCH", f"unexpected negative-control code {exc.code}")
    else:
        negative_control = {"killed": False, "code": None}
        raise RuntimeError("negative control survived: false inertia was accepted")

    report = {
        "verdict": "N0_NO_COUNTEREXAMPLE",
        "scope": "all real symmetric 2x2 matrices with entries [-2,2], all real symmetric 3x3 matrices with entries [-1,0,1], plus 6 rational-cleared matrices",
        "checked_matrices": checked,
        "inertia_histogram": {str(key): value for key, value in sorted(inertias.items())},
        "coverage": dict(sorted(counts.items())),
        "max_rational_clearing_scale": max_clearing_scale,
        "producer_optimizer_isolated_replay": {
            "matrix": witness,
            "certificate": "P=[0,1,2], L=I, D=M (no producer/search/optimizer used)",
            "inertia": list(replay["inertia"]),
            "descartes": list(replay["oracle2_descartes"]),
            "sturm": list(replay["oracle2_sturm"]),
            "bareiss": witness_inertia,
        },
        "negative_control": negative_control,
        "external_oracle": "Bareiss on positive integer denominator-cleared real symmetric matrices only",
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
