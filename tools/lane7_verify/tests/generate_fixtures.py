#!/usr/bin/env python3
"""Regenerate the golden fixtures in tests/fixtures/ deterministically.

This script is a fixture generator, not part of the verifier: it is the one
place under tools/lane7_verify that imports warp_modeld. It runs the repo's
own fake controller — the FakeCompiler / FakeRuntime / FakeLifecycle
adapters copied verbatim from tests/test_experiment_controller.py — against
the frozen contract at --exp-dir, then normalizes the wall-clock fields
(ts_utc, evaluate_ms, compile_ms) to fixed values and recomputes the hash
chain, so the output is byte-identical on every run. The verifier itself
(tools/lane7_verify/verify.py) stays zero-import from warp_modeld.

The fakes prove control flow and receipt shape only, never adapted-model
evidence: no checkpoint, GPU, or live server is touched.

Usage (from the repo root):

    PYTHONPATH=src python3 -B tools/lane7_verify/tests/generate_fixtures.py \
        --exp-dir experiments/demo-2026-11-22 \
        --out tools/lane7_verify/tests/fixtures
"""

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]

# Wall-clock fields normalized so regeneration is byte-identical.
FIXED_TS = "2026-11-22T00:00:00+00:00"
FIXED_EVAL_MS = 2.5
FIXED_COMPILE_MS = 12.5

# Same environment block as tests/test_experiment_controller.py.
ENVIRONMENT = {
    "gpu": "fake-test-gpu (logic check only)",
    "llama_cpp_build": "b12549",
    "llama_cpp_commit": "8af68d486",
    "os": "test",
    "vram_mib": None,
}

# Same passing fake measurements as tests/test_experiment_controller.py:
# the frozen margin rule covers 84 adapter and 36 baseline probe requests.
PASSING_SUITES = {
    "task": {
        "top1": 0.58,
        "contested_fix_fraction": 0.15,
        "break_fraction": 0.03,
    },
    "retention_iid": {"mean_kl": 0.10, "top1_agreement": 0.97},
    "retention_shifted": {"mean_kl": 0.20},
    "safety_canaries": {"canaries_run": 9, "failures": []},
}
ADAPTER_MARGINS = (-0.10, 0.0, 0.18) * 28
BASELINE_MARGINS = (-1.0, -0.9, -0.81) * 12
PASSING_MARGINS = {
    "threshold": -0.37,
    "adapter_requests": 84,
    "baseline_requests": 36,
    "margins_adapter": list(ADAPTER_MARGINS),
    "margins_baseline": list(BASELINE_MARGINS),
}


def sha256_canonical(payload) -> str:
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(body).hexdigest()


def fake_adapter_sha(candidate) -> str:
    payload = json.dumps(candidate.digest_input(), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class FakeCompiler:
    """Stands in for the Weft compiler; records calls, invents nothing."""

    def __init__(self, repo: str, commit: str) -> None:
        self.repo = repo
        self.commit = commit
        self.calls: list = []

    def compile(self, candidate, parent_sha256):
        self.calls.append((candidate.candidate_id, parent_sha256))
        from warp_modeld.experiment import CompileResult

        return CompileResult(
            adapter_sha256=fake_adapter_sha(candidate),
            command="weft.compiler.BetaEditNullspaceProjector.commit_patch",
            command_version="%s@%s" % (self.repo, self.commit[:12]),
            timing_ms=FIXED_COMPILE_MS,
            compiler_repo=self.repo,
            compiler_commit=self.commit,
        )


class FakeRuntime:
    """Stands in for the llama-server scoring seam; records call order."""

    def __init__(self) -> None:
        self.suites = dict(PASSING_SUITES)
        self.margins = dict(PASSING_MARGINS)
        from warp_modeld.experiment import BaselineCheck

        self.baseline = BaselineCheck(max_logit_diff=0.0, exact_matches=14, sequences=14)
        self.calls: list = []
        self.mounted: list = []

    def mount_adapter(self, adapter_sha256, lora_scale):
        self.calls.append(("mount", adapter_sha256))
        self.mounted.append((adapter_sha256, lora_scale))
        return 3.0

    def score_suite(self, suite_name, cases):
        self.calls.append(("score_suite", suite_name))
        return dict(self.suites[suite_name])

    def probe_margins(self):
        self.calls.append(("probe_margins",))
        return dict(self.margins)

    def verify_baseline(self):
        self.calls.append(("verify_baseline",))
        return self.baseline


class FakeLifecycle:
    """Stands in for the Warp lifecycle rollback."""

    def __init__(self, banks) -> None:
        self.banks = tuple(banks)
        self.calls: list = []

    def rollback(self, reason):
        from warp_modeld.experiment import LifecycleRollback

        self.calls.append(reason)
        return LifecycleRollback(banks_flushed=self.banks, slots_flushed=(0,))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exp-dir", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    sys.path.insert(0, str(REPO / "src"))
    from warp_modeld.experiment import ExperimentController, ReceiptLog, load_contract
    from warp_modeld.state_banks import ALL_STATE_BANKS

    exp_dir = Path(args.exp_dir)
    if not exp_dir.is_absolute():
        exp_dir = REPO / exp_dir
    out = Path(args.out)
    if not out.is_absolute():
        out = REPO / out
    out.mkdir(parents=True, exist_ok=True)

    contract = load_contract(exp_dir)
    log_path = out / "receipts.jsonl"
    if log_path.exists():
        log_path.unlink()
    controller = ExperimentController(
        contract=contract,
        compiler=FakeCompiler(contract.compiler_repo, contract.compiler_commit),
        runtime=FakeRuntime(),
        lifecycle=FakeLifecycle(ALL_STATE_BANKS),
        receipts=ReceiptLog(log_path),
        environment=ENVIRONMENT,
    )
    verdict, receipt = controller.run_experiment(
        {"eta": 0.01, "lambda": 1, "lora_scale": 1.0, "quant": "bf16"},
        actual_parent_sha256=contract.parent_sha256,
    )
    if verdict.verdict != "ACCEPT":
        raise SystemExit("fake run did not ACCEPT: %s" % verdict)

    # Normalize wall-clock fields, fix the receipt event hash, rechain.
    receipt["timings_ms"]["evaluate"] = FIXED_EVAL_MS
    entries = controller.receipts.read_all()
    for entry in entries:
        entry["ts_utc"] = FIXED_TS
        if entry["event"] == "evaluated":
            entry["evaluate_ms"] = FIXED_EVAL_MS
        if entry["event"] == "candidate_digest_recorded":
            entry["compile_ms"] = FIXED_COMPILE_MS
        if entry["event"] == "receipt":
            entry["receipt_sha256"] = sha256_canonical(receipt)
    prev = "0" * 64
    for index, entry in enumerate(entries, start=1):
        entry["seq"] = index
        entry["prev_sha256"] = prev
        if entry["event"] == "sealed":
            # Recompute the seal against the normalized chain.
            entry["entry_count"] = index - 1
            entry["chain_head"] = prev
        body = {k: v for k, v in entry.items() if k != "entry_sha256"}
        entry["entry_sha256"] = sha256_canonical(body)
        prev = entry["entry_sha256"]

    (out / "receipt.json").write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n")
    log_path.write_text("".join(json.dumps(e, sort_keys=True) + "\n" for e in entries))
    print(json.dumps({
        "verdict": verdict.verdict,
        "candidate_id": receipt["candidate"]["candidate_id"],
        "manifest_sha256": receipt["manifest_sha256"],
        "suite_sha256": receipt["suite_sha256"],
        "receipt_sha256": sha256_canonical(receipt),
        "log_entries": len(entries),
        "events": [e["event"] for e in entries],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
