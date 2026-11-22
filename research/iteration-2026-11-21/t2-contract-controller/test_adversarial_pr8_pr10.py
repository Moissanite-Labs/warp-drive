"""Preregistered adversarial integration checks; temporary review only."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest

from tests.test_experiment_controller import (
    ENVIRONMENT,
    PARENT_SHA,
    BaselineCheck,
    FakeCompiler,
    FakeLifecycle,
    FakeRuntime,
    ReceiptLog,
    passing_measurements,
)
from warp_modeld.errors import ContractDriftError, ControllerError, StateFlushError
from warp_modeld.experiment import (
    ExperimentController,
    Measurements,
    apply_acceptance_policy,
    load_contract,
)

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments" / "demo-2026-11-22"


def make_controller(tmp_path, contract=None, runtime=None):
    return ExperimentController(
        contract=contract or load_contract(EXP),
        compiler=FakeCompiler(),
        runtime=runtime or FakeRuntime(),
        lifecycle=FakeLifecycle(),
        receipts=ReceiptLog(tmp_path / "receipts.jsonl"),
        environment=ENVIRONMENT,
    )


@pytest.mark.parametrize(
    "relative",
    ["audit/split_leakage.json", "scripts/generate_suites.py"],
)
def test_contract_drift_rejects_every_manifest_pinned_file(tmp_path, relative):
    copied = tmp_path / "exp"
    shutil.copytree(EXP, copied)
    target = copied / relative
    if target.suffix == ".json":
        payload = json.loads(target.read_text(encoding="utf-8"))
        payload["held_out_states"] = -1
        target.write_text(json.dumps(payload), encoding="utf-8")
    else:
        target.write_text(target.read_text(encoding="utf-8") + "\n# drift\n", encoding="utf-8")
    with pytest.raises(ContractDriftError):
        load_contract(copied)


def test_candidate_digest_receipt_precedes_every_score(tmp_path):
    events = []

    class OrderedReceipts(ReceiptLog):
        def append(self, event, **fields):
            if event == "candidate_digest_recorded":
                events.append("digest")
            return super().append(event, **fields)

    class OrderedRuntime(FakeRuntime):
        def score_suite(self, suite_name, cases):
            events.append("score:" + suite_name)
            return super().score_suite(suite_name, cases)

    ctl = make_controller(tmp_path, runtime=OrderedRuntime())
    ctl.receipts = OrderedReceipts(tmp_path / "ordered.jsonl")
    candidate = ctl.propose({"eta": 0.01, "lora_scale": 1.0})
    ctl.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)
    ctl.evaluate()
    assert events == [
        "digest",
        "score:task",
        "score:retention_iid",
        "score:retention_shifted",
        "score:safety_canaries",
    ]


def test_failed_mount_cannot_evaluate_without_digest_receipt(tmp_path):
    class MountFails(FakeRuntime):
        def mount_adapter(self, adapter_sha256, lora_scale):
            self.calls.append(("mount", adapter_sha256))
            raise RuntimeError("mount failed after partial activation")

    ctl = make_controller(tmp_path, runtime=MountFails())
    candidate = ctl.propose({"eta": 0.01, "lora_scale": 1.0})
    with pytest.raises(RuntimeError, match="mount failed"):
        ctl.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)
    with pytest.raises(ControllerError, match="no bound candidate"):
        ctl.evaluate()


@pytest.mark.parametrize("key", ["thresholds", "acceptance_policy", "policy"])
def test_candidate_cannot_override_acceptance_policy(tmp_path, key):
    ctl = make_controller(tmp_path)
    with pytest.raises(ControllerError, match="unknown candidate keys"):
        ctl.run_experiment(
            {"eta": 0.01, "lora_scale": 1.0, key: {"task": {"top1_min": 0}}},
            actual_parent_sha256=PARENT_SHA,
        )


def test_decision_api_has_no_caller_threshold_override(tmp_path):
    ctl = make_controller(tmp_path)
    contract = load_contract(EXP)
    candidate = ctl.propose({"eta": 0.01, "lora_scale": 1.0})
    measurements = Measurements(**passing_measurements(contract))
    with pytest.raises(TypeError):
        ctl.promote_or_reject(candidate, measurements, thresholds={"task": {"top1_min": 0}})


def test_scoring_failure_rolls_back_and_emits_no_success(tmp_path):
    class ScoringFails(FakeRuntime):
        def score_suite(self, suite_name, cases):
            super().score_suite(suite_name, cases)
            raise RuntimeError("scoring disconnected")

    ctl = make_controller(tmp_path, runtime=ScoringFails())
    with pytest.raises(RuntimeError, match="scoring disconnected"):
        ctl.run_experiment(
            {"eta": 0.01, "lora_scale": 1.0}, actual_parent_sha256=PARENT_SHA
        )
    assert ctl.lifecycle.calls == ["experiment_rollback"]
    events = [entry["event"] for entry in ctl.receipts.read_all()]
    assert "verdict" not in events and "receipt" not in events


def test_rollback_requires_frozen_14_sequence_probe(tmp_path):
    runtime = FakeRuntime(
        baseline=BaselineCheck(max_logit_diff=0.0, exact_matches=1, sequences=1)
    )
    ctl = make_controller(tmp_path, runtime=runtime)
    with pytest.raises(StateFlushError):
        ctl.rollback()


def test_receipt_log_detects_edit_duplicate_and_stale_parent(tmp_path):
    edited = ReceiptLog(tmp_path / "edited.jsonl")
    edited.append("first", value=1)
    edited.append("second", value=2)
    lines = edited.path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    first["value"] = 99
    lines[0] = json.dumps(first, sort_keys=True)
    edited.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not edited.verify()

    duplicate = ReceiptLog(tmp_path / "duplicate.jsonl")
    duplicate.append("first", value=1)
    duplicate.append("second", value=2)
    lines = duplicate.path.read_text(encoding="utf-8").splitlines()
    duplicate.path.write_text("\n".join(lines + [lines[0]]) + "\n", encoding="utf-8")
    assert not duplicate.verify()

    stale = ReceiptLog(tmp_path / "stale.jsonl")
    stale.append("first", value=1)
    stale.append("second", value=2)
    lines = stale.path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    second["prev_sha256"] = "0" * 64
    body = {key: value for key, value in second.items() if key != "entry_sha256"}
    canonical = json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    second["entry_sha256"] = hashlib.sha256(canonical).hexdigest()
    lines[1] = json.dumps(second, sort_keys=True)
    stale.path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not stale.verify()


def test_receipt_log_detects_suffix_truncation(tmp_path):
    log = ReceiptLog(tmp_path / "truncated.jsonl")
    log.append("first", value=1)
    log.append("second", value=2)
    lines = log.path.read_text(encoding="utf-8").splitlines()
    log.path.write_text(lines[0] + "\n", encoding="utf-8")
    assert not log.verify()


def test_empty_margin_evidence_cannot_pass_acceptance():
    contract = load_contract(EXP)
    fields = passing_measurements(contract)
    fields.update(
        margins_adapter=(),
        margins_baseline=(),
        margin_adapter_requests=0,
        margin_baseline_requests=0,
    )
    verdict = apply_acceptance_policy(Measurements(**fields), contract.thresholds)
    assert verdict.verdict == "REJECT"


def test_zero_of_nine_canaries_cannot_pass_acceptance():
    contract = load_contract(EXP)
    fields = passing_measurements(contract)
    fields.update(safety_canaries_run=0, safety_failures=())
    verdict = apply_acceptance_policy(Measurements(**fields), contract.thresholds)
    assert verdict.verdict == "REJECT"
