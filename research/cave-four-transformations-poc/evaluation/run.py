#!/usr/bin/env python3
"""Locked reference replay for Cave's four-transformations known-answer suite."""

from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

import numpy as np

ROOT = Path(__file__).resolve().parent.parent
SCHEMA = "warp-drive.cave-four-transformations.receipt.v1"
SUMMARY_SCHEMA = "warp-drive.cave-four-transformations.summary.v1"


def reject_float(value):
    raise ValueError("floating-point values are forbidden in receipts")


def reject_constant(value):
    raise ValueError("non-finite JSON number: " + value)


def no_duplicate_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key: " + key)
        result[key] = value
    return result


def parse_json(text):
    return json.loads(text, object_pairs_hook=no_duplicate_pairs, parse_constant=reject_constant, parse_float=reject_float)


def canonical(value):
    def walk(item):
        if isinstance(item, float):
            raise ValueError("floating-point values are forbidden in receipts")
        if isinstance(item, dict):
            return {key: walk(item[key]) for key in sorted(item)}
        if isinstance(item, list):
            return [walk(entry) for entry in item]
        if item is None or isinstance(item, (str, int, bool)):
            return item
        raise ValueError("unsupported receipt type: " + type(item).__name__)

    return json.dumps(walk(value), sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()


def sha256_text(text):
    return sha256_bytes(text.encode("utf-8"))


def source_files(root=ROOT):
    files = [root / "PREREG.md", root / "PROTOCOL.md", root / "cases.json"]
    files.extend(sorted((root / "evaluation").glob("*.py")))
    return files


def verify_lock(root=ROOT):
    lock_path = root / "LOCK.json"
    lock = parse_json(lock_path.read_text(encoding="utf-8"))
    if lock.get("schema") != "warp-drive.cave-four-transformations.lock.v1":
        raise ValueError("unknown lock schema")
    expected_names = [str(path.relative_to(root)) for path in source_files(root)]
    locked = lock.get("files")
    if not isinstance(locked, dict) or sorted(locked) != sorted(expected_names):
        raise ValueError("locked source file set differs from the harness")
    for name in expected_names:
        if sha256_bytes((root / name).read_bytes()) != locked[name]:
            raise ValueError("locked source hash mismatch: " + name)
    cases = parse_json((root / "cases.json").read_text(encoding="utf-8"))
    if lock.get("cases_sha256") != sha256_bytes((root / "cases.json").read_bytes()):
        raise ValueError("case digest mismatch")
    if lock.get("target_commit") != cases["target"]["commit"]:
        raise ValueError("target commit differs between lock and cases")
    return lock, cases, sha256_bytes(lock_path.read_bytes())


def git_output(checkout, args):
    completed = subprocess.run(["git", "-C", str(checkout), *args], check=False, capture_output=True, text=True, encoding="utf-8")
    if completed.returncode != 0:
        raise ValueError("git target inspection failed: " + completed.stderr.strip())
    return completed.stdout.strip()


def validate_target(checkout, cases):
    checkout = Path(checkout).resolve()
    actual = git_output(checkout, ["rev-parse", "HEAD"])
    expected = cases["target"]["commit"]
    if actual != expected:
        raise ValueError("target commit mismatch: expected " + expected + ", got " + actual)
    dirty = git_output(checkout, ["status", "--porcelain", "--untracked-files=all"])
    if dirty:
        raise ValueError("target worktree is not clean")
    target = checkout / cases["target"]["root"]
    if not target.is_dir():
        raise ValueError("target suite directory is missing")
    return target, actual


def validate_environment(cases):
    python_version = sys.version.split()[0]
    if python_version != cases["python"]:
        raise ValueError("Python version mismatch: expected " + cases["python"] + ", got " + python_version)
    if np.__version__ != cases["numpy"]:
        raise ValueError("numpy version mismatch: expected " + cases["numpy"] + ", got " + np.__version__)


def public_output(text, checkout, target, run_dir):
    replacements = 0
    raw_paths = [Path(checkout), Path(target), Path(run_dir), Path.home(), Path(sys.prefix)]
    paths = raw_paths + [path.resolve() for path in raw_paths]
    labels = ["<checkout>", "<target>", "<run>", "<home>", "<python-home>"] * 2
    for path, label in sorted(zip(paths, labels), key=lambda pair: len(str(pair[0])), reverse=True):
        raw = str(path)
        if raw and raw != "/":
            replacements += text.count(raw)
            text = text.replace(raw, label)
    pattern = re.compile(r"(?<![A-Za-z0-9_])/(?:Users|home|opt/homebrew|private/var|var/folders|tmp)/[^\s\"']+")
    text, count = pattern.subn("<local-path>", text)
    replacements += count
    return text, replacements


def summary_line(stdout, summary_id):
    output_lines = stdout.splitlines()
    lines = [line for line in output_lines if line.startswith("SUMMARY ")]
    prefix = "SUMMARY " + summary_id + " SMOKE "
    matching = [line for line in lines if line.startswith(prefix)]
    if not output_lines or output_lines[-1] not in lines or len(lines) != 1 or len(matching) != 1:
        return None
    match = re.fullmatch(re.escape(prefix) + r"(PASS|FAIL) \| .+", matching[0])
    if match is None:
        return None
    return match.group(1)


def classify(case, return_code, stdout, timed_out=False):
    if timed_out:
        return "operational_failure"
    if case["kind"] == "summary":
        verdict = summary_line(stdout, case["summary_id"])
        if verdict == "PASS" and return_code == 0:
            return "pass"
        if verdict == "FAIL" and return_code == 1:
            return "fail"
        return "operational_failure"
    if case["kind"] in ("units", "review"):
        lines = stdout.splitlines()
        expected_tail = [case["pass_marker"], "PASS"] if case["kind"] == "units" else [case["pass_marker"]]
        if return_code == 0 and lines[-len(expected_tail):] == expected_tail and lines.count(case["pass_marker"]) == 1:
            return "pass"
        return "operational_failure"
    return "protocol_error"


def locked_command(case, mode, cases):
    script = "<target>/" + case["script"]
    return ["<python>", *cases["modes"][mode], script, *case["args"]]


def execute_case(case, mode, checkout, target, run_dir, cases):
    command = [sys.executable, *cases["modes"][mode], str(target / case["script"]), *case["args"]]
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LC_ALL": "C",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "OMP_NUM_THREADS": "1",
        "OPENBLAS_NUM_THREADS": "1",
        "MKL_NUM_THREADS": "1",
        "NUMEXPR_NUM_THREADS": "1",
    }
    started = time.monotonic_ns()
    timed_out = False
    try:
        completed = subprocess.run(command, cwd=target, env=env, check=False, capture_output=True, timeout=case["timeout_seconds"])
        return_code = completed.returncode
        stdout_bytes = completed.stdout
        stderr_bytes = completed.stderr
    except subprocess.TimeoutExpired as error:
        timed_out = True
        return_code = None
        stdout_bytes = error.stdout or b""
        stderr_bytes = error.stderr or b""
    elapsed_ms = (time.monotonic_ns() - started) // 1_000_000
    stdout = stdout_bytes.decode("utf-8", errors="replace")
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    stdout, stdout_redactions = public_output(stdout, checkout, target, run_dir)
    stderr, stderr_redactions = public_output(stderr, checkout, target, run_dir)
    stem = case["id"] + "-" + mode
    (run_dir / (stem + ".stdout.txt")).write_text(stdout, encoding="utf-8")
    (run_dir / (stem + ".stderr.txt")).write_text(stderr, encoding="utf-8")
    outcome = classify(case, return_code, stdout, timed_out)
    return {
        "case": case["id"],
        "mode": mode,
        "oracle": case["oracle"],
        "command": locked_command(case, mode, cases),
        "timeout_seconds": case["timeout_seconds"],
        "return_code": return_code,
        "timed_out": timed_out,
        "elapsed_ms": elapsed_ms,
        "observed": outcome,
        "expected": case["expected"][mode],
        "matched": outcome == case["expected"][mode],
        "stdout_file": stem + ".stdout.txt",
        "stderr_file": stem + ".stderr.txt",
        "stdout_sha256": sha256_text(stdout),
        "stderr_sha256": sha256_text(stderr),
        "stdout_redactions": stdout_redactions,
        "stderr_redactions": stderr_redactions,
    }


def append_receipt(run_dir, previous, sequence, body):
    receipt = {"schema": SCHEMA, "sequence": sequence, "previous_sha256": previous, **body}
    digest = sha256_text(canonical(receipt))
    receipt["receipt_sha256"] = digest
    with (run_dir / "receipts.jsonl").open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(canonical(receipt) + "\n")
    return receipt


def parity_groups(receipts):
    groups = {}
    for receipt in receipts:
        groups.setdefault(receipt["case"], []).append(receipt)
    parity = []
    for case, items in sorted(groups.items()):
        if len(items) < 2:
            continue
        first = items[0]
        identical = all(item["stdout_sha256"] == first["stdout_sha256"] and item["observed"] == first["observed"] for item in items[1:])
        parity.append({"case": case, "modes": [item["mode"] for item in items], "stdout_and_outcome_equal": identical})
    return parity


def write_summary(run_dir, receipts, target_commit, lock_sha256):
    counts = collections.Counter(item["observed"] for item in receipts)
    mismatches = [item["case"] + ":" + item["mode"] for item in receipts if not item["matched"]]
    parity = parity_groups(receipts)
    complete = not mismatches and all(item["stdout_and_outcome_equal"] for item in parity)
    summary = {
        "schema": SUMMARY_SCHEMA,
        "novelty": "N0",
        "evidence_class": "reference_replay",
        "scientific_size": "smoke_not_a_full_result",
        "real_data_readiness": "BLOCKED",
        "target_commit": target_commit,
        "lock_sha256": lock_sha256,
        "receipt_count": len(receipts),
        "outcome_counts": dict(sorted(counts.items())),
        "mismatches": mismatches,
        "parity": parity,
        "status": "REFERENCE_REPLAY_COMPLETE" if complete else "REPRODUCTION_MISMATCH",
        "terminal_receipt_sha256": receipts[-1]["receipt_sha256"] if receipts else None,
    }
    (run_dir / "SUMMARY.json").write_text(canonical(summary) + "\n", encoding="utf-8")
    return summary


def run_replay(checkout, run_dir, root=ROOT):
    checkout = Path(checkout).resolve()
    run_dir = Path(run_dir).resolve()
    lock, cases, lock_sha256 = verify_lock(root)
    validate_environment(cases)
    target, target_commit = validate_target(checkout, cases)
    if run_dir.exists():
        raise ValueError("run output directory already exists")
    run_dir.mkdir(parents=True)
    source = {
        "schema": "warp-drive.cave-four-transformations.source.v1",
        "target": cases["target"],
        "aletheia": cases["aletheia"],
        "lock_sha256": lock_sha256,
        "recorded_utc": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
    }
    (run_dir / "SOURCE.json").write_text(canonical(source) + "\n", encoding="utf-8")
    receipts = []
    previous = None
    for sequence, (case, mode) in enumerate((case, mode) for case in cases["cases"] for mode in case["expected"]):
        body = execute_case(case, mode, checkout, target, run_dir, cases)
        body.update({"target_commit": target_commit, "lock_sha256": lock_sha256})
        receipt = append_receipt(run_dir, previous, sequence, body)
        receipts.append(receipt)
        previous = receipt["receipt_sha256"]
        print(case["id"], mode, receipt["observed"], "match=" + str(receipt["matched"]).lower(), flush=True)
    validate_target(checkout, cases)
    summary = write_summary(run_dir, receipts, target_commit, lock_sha256)
    verify_run(run_dir, root=root, checkout=checkout)
    print(json.dumps({"status": summary["status"], "receipts": len(receipts), "outcomes": summary["outcome_counts"]}, sort_keys=True))
    return summary


def expected_public_files(cases):
    files = {"SOURCE.json", "SUMMARY.json", "receipts.jsonl"}
    for case in cases["cases"]:
        for mode in case["expected"]:
            stem = case["id"] + "-" + mode
            files.update((stem + ".stdout.txt", stem + ".stderr.txt"))
    return files


def verify_public_boundary(run_dir, cases):
    entries = []
    for path in run_dir.rglob("*"):
        if path.is_symlink():
            raise ValueError("run directory contains a symbolic link")
        entries.append(path)
        if path.is_dir():
            raise ValueError("run directory contains an unlisted directory")
    names = {path.relative_to(run_dir).as_posix() for path in entries}
    if names != expected_public_files(cases):
        raise ValueError("run file set differs from the locked public manifest")
    pattern = "/(?:Users|home|opt/" + "homebrew|private/var|var/folders|tmp|Library)/|"
    pattern += "Co-authored-" + "by:|" + "ha" + "fiz"
    forbidden = re.compile(pattern, re.IGNORECASE)
    for path in entries:
        data = path.read_bytes()
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ValueError("public run file is not UTF-8: " + path.name) from error
        if forbidden.search(text):
            raise ValueError("public output contains a forbidden path or attribution: " + path.name)


def verify_run(run_dir, root=ROOT, checkout=None):
    run_dir = Path(run_dir).resolve()
    lock, cases, lock_sha256 = verify_lock(root)
    verify_public_boundary(run_dir, cases)
    if lock["target_commit"] != cases["target"]["commit"]:
        raise ValueError("target binding mismatch")
    expected_pairs = [(case["id"], mode) for case in cases["cases"] for mode in case["expected"]]
    case_by_id = {case["id"]: case for case in cases["cases"]}
    receipts = []
    previous = None
    lines = (run_dir / "receipts.jsonl").read_text(encoding="utf-8").splitlines()
    if len(lines) != len(expected_pairs):
        raise ValueError("receipt count differs from locked coverage")
    for sequence, (line, expected_pair) in enumerate(zip(lines, expected_pairs)):
        receipt = parse_json(line)
        if receipt.get("schema") != SCHEMA or receipt.get("sequence") != sequence or receipt.get("previous_sha256") != previous:
            raise ValueError("receipt chain binding failure at sequence " + str(sequence))
        digest = receipt.get("receipt_sha256")
        unsigned = {key: value for key, value in receipt.items() if key != "receipt_sha256"}
        if digest != sha256_text(canonical(unsigned)):
            raise ValueError("receipt digest mismatch at sequence " + str(sequence))
        if (receipt.get("case"), receipt.get("mode")) != expected_pair:
            raise ValueError("receipt case order differs from lock")
        case = case_by_id[receipt["case"]]
        mode = receipt["mode"]
        if receipt.get("command") != locked_command(case, mode, cases):
            raise ValueError("receipt command differs from lock")
        for field, expected in (("oracle", case["oracle"]), ("timeout_seconds", case["timeout_seconds"]), ("expected", case["expected"][mode]), ("target_commit", cases["target"]["commit"]), ("lock_sha256", lock_sha256)):
            if receipt.get(field) != expected:
                raise ValueError("receipt field mismatch: " + field)
        stem = receipt["case"] + "-" + mode
        if receipt.get("stdout_file") != stem + ".stdout.txt" or receipt.get("stderr_file") != stem + ".stderr.txt":
            raise ValueError("receipt output path differs from locked naming")
        stdout_path = run_dir / receipt["stdout_file"]
        stderr_path = run_dir / receipt["stderr_file"]
        stdout = stdout_path.read_text(encoding="utf-8")
        stderr = stderr_path.read_text(encoding="utf-8")
        if sha256_text(stdout) != receipt["stdout_sha256"] or sha256_text(stderr) != receipt["stderr_sha256"]:
            raise ValueError("output digest mismatch")
        observed = classify(case, receipt["return_code"], stdout, receipt["timed_out"])
        if observed != receipt["observed"]:
            raise ValueError("receipt outcome does not follow from stored output")
        if receipt["matched"] != (observed == case["expected"][mode]):
            raise ValueError("receipt match flag is incorrect")
        receipts.append(receipt)
        previous = digest
    summary = parse_json((run_dir / "SUMMARY.json").read_text(encoding="utf-8"))
    counts = collections.Counter(item["observed"] for item in receipts)
    mismatches = [item["case"] + ":" + item["mode"] for item in receipts if not item["matched"]]
    parity = parity_groups(receipts)
    complete = not mismatches and all(item["stdout_and_outcome_equal"] for item in parity)
    expected_summary = {
        "schema": SUMMARY_SCHEMA,
        "novelty": "N0",
        "evidence_class": "reference_replay",
        "scientific_size": "smoke_not_a_full_result",
        "real_data_readiness": "BLOCKED",
        "target_commit": cases["target"]["commit"],
        "lock_sha256": lock_sha256,
        "receipt_count": len(receipts),
        "outcome_counts": dict(sorted(counts.items())),
        "mismatches": mismatches,
        "parity": parity,
        "status": "REFERENCE_REPLAY_COMPLETE" if complete else "REPRODUCTION_MISMATCH",
        "terminal_receipt_sha256": previous,
    }
    if summary != expected_summary:
        raise ValueError("summary differs from measured receipts")
    source = parse_json((run_dir / "SOURCE.json").read_text(encoding="utf-8"))
    expected_source_keys = {"schema", "target", "aletheia", "lock_sha256", "recorded_utc"}
    if set(source) != expected_source_keys or source.get("schema") != "warp-drive.cave-four-transformations.source.v1":
        raise ValueError("source schema mismatch")
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", source.get("recorded_utc", "")) is None:
        raise ValueError("source timestamp mismatch")
    if source.get("target") != cases["target"] or source.get("aletheia") != cases["aletheia"] or source.get("lock_sha256") != lock_sha256:
        raise ValueError("source binding mismatch")
    if checkout is not None:
        validate_target(Path(checkout), cases)
    return {"chain_valid": True, "receipt_count": len(receipts), "status": summary["status"], "outcome_counts": summary["outcome_counts"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", required=True, help="clean Cave checkout at the locked commit")
    parser.add_argument("--output", required=True, help="new directory for run receipts")
    parser.add_argument("--check", action="store_true", help="verify an existing run instead of executing it")
    args = parser.parse_args()
    try:
        if args.check:
            result = verify_run(Path(args.output), checkout=Path(args.target))
        else:
            result = run_replay(Path(args.target), Path(args.output))
        print(canonical(result))
        return 0 if result["status"] == "REFERENCE_REPLAY_COMPLETE" else 1
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print("PROTOCOL_ERROR:", str(error), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
