#!/usr/bin/env python3
"""Run and independently score the locked Ratchet 001 corpus."""

from __future__ import annotations

import argparse
from fractions import Fraction
import hashlib
import importlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import unicodedata
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
EVALUATION = ROOT / "evaluation"
MODES = {"normal": ["-I", "-B"], "optimized": ["-I", "-O", "-B"], "warnings": ["-I", "-B", "-W", "error"]}
TARGET_KEY = "studies/expedition-songe-distill-governance/songe_distill_governance_audit.py"
CAP_MS = 900000
PER_CASE_SECONDS = 30


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def canonical(value: Any) -> str:
    def check(item: Any) -> None:
        if isinstance(item, float):
            raise ValueError("float in receipt")
        if isinstance(item, dict):
            for key, child in item.items():
                require(type(key) is str, "non-string receipt key")
                check(child)
        elif isinstance(item, list):
            for child in item:
                check(child)
    check(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def parse_json(text: str) -> Any:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    value = json.loads(text, object_pairs_hook=unique, parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)))
    canonical(value)
    return value


def load_pinned_framework() -> Any:
    framework_path = os.environ.get("ALETHEIA_RATCHET_MODULE")
    require(framework_path is not None, "pinned Aletheia ratchet module path missing")
    framework_file = Path(framework_path).resolve()
    pin = parse_json((EVALUATION / "FRAMEWORK_PIN.json").read_text(encoding="utf-8"))
    require(hashlib.sha256(framework_file.read_bytes()).hexdigest() == pin["aletheia"]["ratchet_module_sha256"], "pinned Aletheia module digest mismatch")
    package_root = framework_file.parent
    package_spec = importlib.util.spec_from_file_location("aletheia", package_root / "__init__.py", submodule_search_locations=[str(package_root)])
    require(package_spec is not None and package_spec.loader is not None, "cannot import pinned Aletheia package")
    package = importlib.util.module_from_spec(package_spec)
    sys.modules["aletheia"] = package
    package_spec.loader.exec_module(package)
    return importlib.import_module("aletheia.ratchet")


def locked_tree_hash() -> tuple[str, dict[str, str]]:
    hashes = {}
    for path in sorted(EVALUATION.rglob("*")):
        if path.is_file() and path.name not in {"LOCK.json", "corpus.json"} and "__pycache__" not in path.parts:
            hashes[path.relative_to(EVALUATION).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    hashes["corpus.json"] = hashlib.sha256((EVALUATION / "corpus.json").read_bytes()).hexdigest()
    tree_hash = sha256_text(canonical(hashes))
    lock_path = EVALUATION / "LOCK.json"
    if lock_path.exists():
        lock = parse_json(lock_path.read_text(encoding="utf-8"))
        require(lock["tree_sha256"] == tree_hash and lock["files"] == hashes, "locked evaluation tree changed")
    return tree_hash, hashes


def fraction(value: dict[str, int]) -> Fraction:
    require(type(value) is dict and set(value) == {"num", "den"}, "invalid rational")
    require(type(value["num"]) is int and type(value["den"]) is int, "non-integer rational")
    return Fraction(value["num"], value["den"])


def rat(value: Fraction) -> dict[str, int]:
    return {"num": value.numerator, "den": value.denominator}


def independent_cluster_reference(data: dict[str, Any]) -> dict[str, Any]:
    alpha = fraction(data["alpha"])
    num_scales = data["num_scales"]
    minimum = data["min_conversations"]
    drift = fraction(data["drift"])
    drift_limit = fraction(data["drift_limit"])
    require(type(num_scales) is int and type(minimum) is int and type(data["fused_rejudged"]) is bool, "invalid gate types")
    groups: dict[str, list[int]] = {}
    for raw_id, score in data["conversation_outcomes"]:
        require(type(raw_id) is str and raw_id and type(score) is int and score in {-1, 0, 1}, "invalid outcome")
        canonical_id = unicodedata.normalize("NFC", raw_id).strip().casefold()
        require(bool(canonical_id), "empty normalized conversation")
        groups.setdefault(canonical_id, []).append(score)
    wins = sum(sum(scores) > 0 for scores in groups.values())
    losses = sum(sum(scores) < 0 for scores in groups.values())
    decisive = wins + losses
    numerator = sum(math.comb(decisive + 1, index) for index in range(wins + 1))
    ratio = Fraction(numerator, (decisive + 1) * math.comb(decisive, wins)) if decisive else Fraction(1)
    threshold = Fraction(2 * num_scales) / alpha
    reasons = []
    if len(groups) < minimum:
        reasons.append("INSUFFICIENT_INDEPENDENT_CONVERSATIONS")
    if not data["fused_rejudged"]:
        reasons.append("FUSED_ARTIFACT_NOT_REJUDGED")
    if ratio < threshold:
        reasons.append("SUPERMARTINGALE_THRESHOLD_NOT_MET")
    if drift > drift_limit:
        reasons.append("GENERAL_DRIFT_EXCEEDS_LIMIT")
    return {"accepted": not reasons, "reasons": reasons, "independent_conversations": len(groups), "conversation_wins": wins, "conversation_losses": losses, "lead_ratio": rat(ratio), "threshold": rat(threshold)}


def independent_gradient_reference(case: dict[str, Any]) -> dict[str, dict[str, int]]:
    p0 = fraction(case["request"]["input"]["p0"])
    q0 = fraction(case["request"]["input"]["q0"])
    return {"songe_dL_dz0": rat((1 - p0) * q0), "bregman_dL_dz0": rat(-(1 - q0 - (1 - p0)) * q0)}


def classify(case: dict[str, Any], output: Any, returncode: int, timed_out: bool) -> str:
    expected = case["expect"]
    if timed_out:
        return "timeout"
    if returncode != 0:
        return "false_reject" if expected == "admit" else "operational_failure"
    if type(output) is not dict:
        return "malformed_receipt"
    if case["request"]["op"] == "governance":
        admitted = output.get("admitted")
        reasons = output.get("reasons")
        if type(admitted) is not bool or type(reasons) is not list or any(type(reason) is not str for reason in reasons) or admitted != (len(reasons) == 0):
            return "malformed_receipt"
        if expected == "admit":
            return "pass" if admitted else "false_reject"
        if admitted:
            return "false_accept"
        required = case["required_reason"]
        return "kill" if required in reasons else "wrong_reason"
    if case["request"]["op"] == "cluster_gate":
        if case.get("required_reason") == "INVALID_INPUT":
            if output.get("accepted") is True:
                return "false_accept"
            reasons = output.get("reasons")
            return "kill" if type(reasons) is list and "INVALID_INPUT" in reasons else "wrong_reason"
        reference = independent_cluster_reference(case["request"]["input"])
        if output != reference:
            return "reference_mismatch"
        if expected == "reject" and output["accepted"]:
            return "false_accept"
        if expected == "reject" and case["required_reason"] not in output["reasons"]:
            return "wrong_reason"
        return "pass" if output["accepted"] else "kill"
    if case["request"]["op"] == "binary_gradients":
        return "pass" if output == independent_gradient_reference(case) else "exact_mismatch"
    raise ValueError("unknown operation")


def run(run_dir: Path) -> dict[str, Any]:
    tree_hash, _ = locked_tree_hash()
    require(run_dir.parent == ROOT / "runs", "run directory must be under runs")
    require(not (run_dir / "SUMMARY.json").exists(), "refusing to overwrite completed run")
    candidate = run_dir / "candidate"
    require(candidate.is_dir(), "candidate directory missing")
    source = json.loads((run_dir / "SOURCE.json").read_text(encoding="utf-8"))
    cases_document = parse_json((EVALUATION / "corpus.json").read_text(encoding="utf-8"))
    cases = cases_document["cases"]
    (run_dir / "requests").mkdir(exist_ok=True)
    (run_dir / "observations").mkdir(exist_ok=True)
    for case in cases:
        (run_dir / "requests" / f"{case['id']}.json").write_text(canonical(case["request"]) + "\n", encoding="utf-8")
    receipts = []
    previous = None
    total_ms = 0
    for mode, flags in MODES.items():
        for case in cases:
            remaining_ms = CAP_MS - total_ms
            if remaining_ms <= 0:
                returncode, output, elapsed_ms, timed_out, error_type = 0, None, 0, True, "ComputeCap"
            else:
                command = [sys.executable, *flags, "evaluation/songe_adapter.py", "--target", str(run_dir / "candidate" / TARGET_KEY), "--case", str(run_dir / "requests" / f"{case['id']}.json")]
                started = time.monotonic_ns()
                try:
                    completed = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=min(PER_CASE_SECONDS, remaining_ms / 1000), check=False, env={"PATH": os.environ.get("PATH", ""), "PYTHONHASHSEED": "0"})
                    elapsed_ms = (time.monotonic_ns() - started) // 1000000
                    returncode = completed.returncode
                    timed_out = False
                    error_type = None if returncode == 0 else "SubprocessError"
                    try:
                        output = parse_json(completed.stdout) if returncode == 0 else None
                        if returncode == 0:
                            error_type = None
                    except (ValueError, json.JSONDecodeError):
                        output = None
                        error_type = "MalformedOutput"
                        returncode = 2
                except subprocess.TimeoutExpired:
                    elapsed_ms = (time.monotonic_ns() - started) // 1000000
                    returncode, output, timed_out, error_type = 124, None, True, "Timeout"
            total_ms += elapsed_ms
            outcome = classify(case, output, returncode, timed_out)
            observation = {"schema": "warp-drive.ratchet-001.observation.v1", "case": case["id"], "mode": mode, "outcome": outcome, "returncode": returncode, "timed_out": timed_out, "error_type": error_type, "output": output}
            observation_text = canonical(observation) + "\n"
            observation_path = run_dir / "observations" / f"{mode}-{case['id']}.json"
            observation_path.write_text(observation_text, encoding="utf-8")
            receipt = {"schema": "warp-drive.ratchet-001.receipt.v1", "sequence": len(receipts), "previous_sha256": previous, "case": case["id"], "mode": mode, "outcome": outcome, "elapsed_ms": elapsed_ms, "observation_sha256": sha256_text(observation_text), "candidate_head": source["head"]}
            receipt_text = canonical(receipt)
            previous = sha256_text(receipt_text)
            receipt["receipt_sha256"] = previous
            receipts.append(receipt)
            (run_dir / "receipts.jsonl").write_text("\n".join(canonical(item) for item in receipts) + "\n", encoding="utf-8")
    outcomes_by_case = {case["id"]: {mode: next(item["outcome"] for item in receipts if item["mode"] == mode and item["case"] == case["id"]) for mode in MODES} for case in cases}
    parity_divergences = sum(len(set(outcomes.values())) != 1 for outcomes in outcomes_by_case.values())
    counts = {name: 0 for name in ["pass", "kill", "false_accept", "false_reject", "operational_failure", "wrong_reason", "reference_mismatch", "exact_mismatch", "malformed_receipt", "timeout"]}
    for item in receipts:
        counts[item["outcome"]] += 1
    target_source = (candidate / TARGET_KEY).read_text(encoding="utf-8")
    module = load_pinned_framework()
    summary = {"schema": "warp-drive.ratchet-001.summary.v1", "evaluation_tree_sha256": tree_hash, "candidate_head": source["head"], "candidate_source_sha256": hashlib.sha256((candidate / TARGET_KEY).read_bytes()).hexdigest(), "candidate_ast_sha256": module.ast_canonical_digest(target_source), "case_count": len(cases), "execution_count": len(receipts), "compute_cap_ms": CAP_MS, "elapsed_ms": total_ms, "parity_divergences": parity_divergences, "counts": counts, "outcomes_by_case": outcomes_by_case, "terminal_receipt_sha256": previous}
    text = canonical(summary) + "\n"
    (run_dir / "SUMMARY.json").write_text(text, encoding="utf-8")
    return summary


def verify_chain(run_dir: Path) -> bool:
    previous = None
    lines = (run_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
    require(lines, "empty chain")
    for sequence, line in enumerate(lines):
        item = parse_json(line)
        digest = item.pop("receipt_sha256")
        require(item["sequence"] == sequence and item["previous_sha256"] == previous, "chain linkage failure")
        require(sha256_text(canonical(item)) == digest, "receipt digest failure")
        observation = (run_dir / "observations" / f"{item['mode']}-{item['case']}.json").read_text(encoding="utf-8")
        require(sha256_text(observation) == item["observation_sha256"], "observation digest failure")
        previous = digest
    summary = parse_json((run_dir / "SUMMARY.json").read_text(encoding="utf-8"))
    require(summary["terminal_receipt_sha256"] == previous, "terminal digest mismatch")
    return True


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["run", "verify", "tree"])
    parser.add_argument("--run-dir", type=Path)
    args = parser.parse_args()
    if args.command == "tree":
        tree_hash, hashes = locked_tree_hash()
        print(canonical({"tree_sha256": tree_hash, "files": hashes}))
        return 0
    require(args.run_dir is not None, "--run-dir required")
    run_dir = args.run_dir
    if args.command == "run":
        print(canonical(run(run_dir)))
    else:
        print(canonical({"chain_valid": verify_chain(run_dir)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
