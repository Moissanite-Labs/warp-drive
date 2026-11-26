"""Tests for the bounded experiment controller (issue #5).

Fake compiler and runtime adapters only: these tests prove control flow,
validation, ordering, and failure handling. They are logic checks, never
adapted-model evidence, and never touch a checkpoint, a GPU, or a live
server. One test loads the real frozen contract from
experiments/demo-2026-11-22 and runs a full fake experiment against it.
"""

import hashlib
import json
from pathlib import Path

import pytest

from warp_modeld.errors import (
    CheckpointMismatchError,
    ContractDriftError,
    ControllerError,
    StateFlushError,
    UnverifiedLoraOverrideError,
)
from warp_modeld.experiment import (
    BaselineCheck,
    CompileResult,
    ExperimentController,
    LifecycleRollback,
    ReceiptLog,
    WarpModeldLifecycle,
    apply_acceptance_policy,
    build_receipt,
    check_control,
    load_contract,
    make_control,
    propose_candidate,
)
from warp_modeld.state_banks import ALL_STATE_BANKS, BankFlushReceipt

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments" / "demo-2026-11-22"

PARENT_SHA = "10cc391b403021dd11c614679d2fd92f611c3681d29e29651b717316965d61e1"
COMPILER_REPO = "siliconcordat/weft"
COMPILER_COMMIT = "5d7eac03696c2ff07ec70308b23b86a1d4088c1e"
ENVIRONMENT = {
    "gpu": "fake-test-gpu (logic check only)",
    "llama_cpp_build": "b12549",
    "llama_cpp_commit": "8af68d486",
    "os": "test",
    "vram_mib": None,
}


def fake_adapter_sha(candidate) -> str:
    payload = json.dumps(candidate.digest_input(), sort_keys=True).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class FakeCompiler:
    """Stands in for the Weft compiler; records calls, invents nothing."""

    def __init__(self) -> None:
        self.calls: list = []

    def compile(self, candidate, parent_sha256):
        self.calls.append((candidate.candidate_id, parent_sha256))
        return CompileResult(
            adapter_sha256=fake_adapter_sha(candidate),
            command="weft.compiler.BetaEditNullspaceProjector.commit_patch",
            command_version=f"{COMPILER_REPO}@{COMPILER_COMMIT[:12]}",
            timing_ms=12.5,
            compiler_repo=COMPILER_REPO,
            compiler_commit=COMPILER_COMMIT,
        )


CANARIES = 9

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

# The frozen margin rule: 84 adapter and 36 baseline probe requests.
ADAPTER_MARGINS = (-0.10, 0.0, 0.18) * 28
BASELINE_MARGINS = (-1.0, -0.9, -0.81) * 12

PASSING_MARGINS = {
    "threshold": -0.37,
    "adapter_requests": 84,
    "baseline_requests": 36,
    "margins_adapter": list(ADAPTER_MARGINS),
    "margins_baseline": list(BASELINE_MARGINS),
}


class FakeRuntime:
    """Stands in for the llama-server scoring seam; records call order."""

    def __init__(self, suites=None, margins=None, baseline=None) -> None:
        self.suites = dict(PASSING_SUITES if suites is None else suites)
        self.margins = dict(PASSING_MARGINS if margins is None else margins)
        self.baseline = baseline or BaselineCheck(
            max_logit_diff=0.0, exact_matches=14, sequences=14
        )
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

    def __init__(self, banks=ALL_STATE_BANKS) -> None:
        self.banks = tuple(banks)
        self.calls: list = []

    def rollback(self, reason):
        self.calls.append(reason)
        return LifecycleRollback(banks_flushed=self.banks, slots_flushed=(0,))


@pytest.fixture()
def contract():
    return load_contract(EXP)


@pytest.fixture()
def controller(contract, tmp_path):
    return ExperimentController(
        contract=contract,
        compiler=FakeCompiler(),
        runtime=FakeRuntime(),
        lifecycle=FakeLifecycle(),
        receipts=ReceiptLog(tmp_path / "receipts.jsonl"),
        environment=ENVIRONMENT,
    )


def passing_measurements(contract):
    return {
        "task_top1": 0.58,
        "task_contested_fix_fraction": 0.15,
        "task_break_fraction": 0.03,
        "margin_threshold": -0.37,
        "margins_adapter": ADAPTER_MARGINS,
        "margins_baseline": BASELINE_MARGINS,
        "margin_adapter_requests": 84,
        "margin_baseline_requests": 36,
        "iid_mean_kl": 0.10,
        "iid_top1_agreement": 0.97,
        "shifted_mean_kl": 0.20,
        "safety_canaries_run": 9,
        "safety_failures": (),
        "rollback_exact_matches": 14,
        "rollback_sequences": 14,
        "rollback_max_logit_diff": 0.0,
    }


# --- contract loading -------------------------------------------------------


def test_load_contract_verifies_digests(contract):
    assert contract.experiment == "demo-2026-11-22"
    assert contract.parent_sha256 == PARENT_SHA
    assert contract.repair_budget_max_rounds == 3
    assert contract.rank == 8
    assert contract.target_layer == 31
    assert contract.target_tensor == "ffn_up"
    assert contract.margin_threshold == -0.37
    assert contract.combined_suite_sha256 == (
        "abc72b6a63bb6e1deb16ff052a6a4ba37a2545d3196c2653b0d742f0e21e74f9"
    )
    assert len(contract.suites["task"]["cases"]) == 112
    assert len(contract.suites["retention_iid"]["cases"]) == 24
    assert len(contract.suites["retention_shifted"]["cases"]) == 80
    assert len(contract.suites["safety_canaries"]["canary_ids"]) == 9


def test_load_contract_rejects_tampered_suite(tmp_path):
    import shutil

    copied = tmp_path / "exp"
    shutil.copytree(EXP, copied)
    task_path = copied / "suites" / "task.json"
    data = json.loads(task_path.read_text(encoding="utf-8"))
    data["n_cases"] = 113
    task_path.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(ContractDriftError):
        load_contract(copied)


def test_load_contract_rejects_missing_file(tmp_path):
    import shutil

    copied = tmp_path / "exp"
    shutil.copytree(EXP, copied)
    (copied / "thresholds.json").unlink()
    with pytest.raises(ContractDriftError):
        load_contract(copied)


# --- propose_candidate ------------------------------------------------------


def test_propose_valid_candidate(contract):
    candidate = propose_candidate(
        {"eta": 0.01, "lambda": 1, "lora_scale": 1.0, "quant": "bf16"},
        contract,
        candidate_id="cand-a",
    )
    assert candidate.rank == 8
    assert candidate.target_layer == 31
    assert candidate.target_tensor == "ffn_up"
    assert candidate.config_digest() == candidate.config_digest()
    assert candidate.config_dict()["lambda"] == 1


def test_propose_defaults_to_pinned_target_and_bf16(contract):
    candidate = propose_candidate({"eta": 0.01, "lora_scale": 0.0}, contract)
    assert candidate.rank == 8
    assert candidate.target_layer == 31
    assert candidate.quant == "bf16"
    assert candidate.candidate_id.startswith("cand-")


@pytest.mark.parametrize(
    "raw",
    [
        {"eta": 0.001, "lora_scale": 1.0},
        {"eta": 0.03, "lora_scale": 1.0},
        {"eta": True, "lora_scale": 1.0},
        {"eta": float("nan"), "lora_scale": 1.0},
        {"eta": 0.01, "lora_scale": 0.5},
        {"eta": 0.01, "lora_scale": -1.0},
        {"eta": 0.01, "lora_scale": 1.0, "rank": 16},
        {"eta": 0.01, "lora_scale": 1.0, "target_layer": 30},
        {"eta": 0.01, "lora_scale": 1.0, "target_tensor": "ffn_down"},
        {"eta": 0.01, "lora_scale": 1.0, "lambda": 5},
        {"eta": 0.01, "lora_scale": 1.0, "lambda": "unknown"},
        {"eta": 0.01, "lora_scale": 1.0, "quant": "fp8"},
        {"eta": 0.01, "lora_scale": 1.0, "surprise": 1},
        {"lora_scale": 1.0},
        {"eta": 0.01},
    ],
)
def test_propose_rejects_malformed_candidates(contract, raw):
    with pytest.raises(ControllerError):
        propose_candidate(raw, contract)


@pytest.mark.parametrize("key", ["lora", "adapter_path", "adapter_sha256", "lora_scaled", "weights"])
def test_propose_rejects_raw_lora_overrides(contract, key):
    with pytest.raises(UnverifiedLoraOverrideError):
        propose_candidate({"eta": 0.01, "lora_scale": 1.0, key: "x"}, contract)


def test_propose_accepts_mean_eigenvalue_lambda(contract):
    candidate = propose_candidate(
        {"eta": 0.01, "lambda": "mean_eigenvalue", "lora_scale": 1.0}, contract
    )
    assert candidate.lam == "mean_eigenvalue"


def test_make_control_builds_both_controls(contract):
    base = make_control(contract, "base-control")
    assert base.control_id == "base-control"
    assert base.lora_scale == 0.0
    regressed = make_control(contract, "regressed-control")
    assert regressed.control_id == "regressed-control"
    assert regressed.lora_scale == -1.0
    with pytest.raises(ControllerError):
        make_control(contract, "no-such-control")


# --- compile_and_bind -------------------------------------------------------


def test_compile_records_digest_before_evaluation(controller, tmp_path):
    candidate = controller.propose({"eta": 0.01, "lora_scale": 1.0})
    result = controller.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)
    assert result.adapter_sha256 == fake_adapter_sha(candidate)
    entries = controller.receipts.read_all()
    events = [e["event"] for e in entries]
    assert events.index("candidate_digest_recorded") < len(events)
    digest_entry = entries[events.index("candidate_digest_recorded")]
    assert digest_entry["hash_recorded_before_evaluation"] is True
    assert digest_entry["adapter_sha256"] == result.adapter_sha256
    # No scoring call happened before the digest entry: the runtime log
    # holds only the mount call so far.
    assert controller.runtime.calls == [("mount", result.adapter_sha256)]
    # Mid-run the log is not sealed yet, so only the chain is checked.
    assert controller.receipts.verify_chain()
    assert not controller.receipts.verify()


def test_compile_rejects_checkpoint_drift_before_compiler_call(controller):
    candidate = controller.propose({"eta": 0.01, "lora_scale": 1.0})
    with pytest.raises(CheckpointMismatchError):
        controller.compile_and_bind(candidate, actual_parent_sha256="0" * 64)
    assert controller.compiler.calls == []
    assert controller.runtime.calls == []


def test_compile_rejects_wrong_compiler_commit(contract, tmp_path):
    class WrongCompiler(FakeCompiler):
        def compile(self, candidate, parent_sha256):
            result = super().compile(candidate, parent_sha256)
            return CompileResult(
                adapter_sha256=result.adapter_sha256,
                command=result.command,
                command_version=result.command_version,
                timing_ms=result.timing_ms,
                compiler_repo=COMPILER_REPO,
                compiler_commit="0" * 40,
            )

    ctl = ExperimentController(
        contract=contract,
        compiler=WrongCompiler(),
        runtime=FakeRuntime(),
        lifecycle=FakeLifecycle(),
        receipts=ReceiptLog(tmp_path / "receipts.jsonl"),
        environment=ENVIRONMENT,
    )
    candidate = ctl.propose({"eta": 0.01, "lora_scale": 1.0})
    with pytest.raises(ControllerError):
        ctl.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)


def test_evaluate_refuses_unbound_candidate(controller):
    with pytest.raises(ControllerError):
        controller.evaluate()


# --- acceptance policy ------------------------------------------------------


def test_policy_accepts_passing_measurements(contract):
    from warp_modeld.experiment import Measurements

    verdict = apply_acceptance_policy(
        Measurements(**passing_measurements(contract)),
        contract.thresholds,
        expected_canaries=CANARIES,
    )
    assert verdict.verdict == "ACCEPT"
    assert verdict.failed_gates == ()


@pytest.mark.parametrize(
    "change",
    [
        {"task_top1": 0.55},
        {"task_contested_fix_fraction": 0.09},
        {"task_break_fraction": 0.09},
        {"margins_adapter": ADAPTER_MARGINS[:-1] + (-0.40,)},
        {"margins_baseline": BASELINE_MARGINS[:-1] + (-0.30,)},
        {"iid_mean_kl": 0.26},
        {"iid_top1_agreement": 0.94},
        {"shifted_mean_kl": 0.41},
        {"safety_failures": ("canary-1",)},
        {"rollback_exact_matches": 13},
        {"rollback_max_logit_diff": 0.001},
    ],
)
def test_policy_rejects_each_failing_gate(contract, change):
    from warp_modeld.experiment import Measurements

    fields = passing_measurements(contract)
    fields.update(change)
    verdict = apply_acceptance_policy(
        Measurements(**fields), contract.thresholds, expected_canaries=CANARIES
    )
    assert verdict.verdict == "REJECT"
    assert verdict.failed_gates
    assert verdict.reasons


def test_policy_cannot_be_changed_by_a_proposal(contract):
    # There is no parameter that carries thresholds into the policy call
    # other than the frozen mapping; a tampered copy is a different
    # mapping and is not the loaded contract.
    from warp_modeld.experiment import Measurements

    tampered = json.loads(json.dumps(contract.thresholds))
    tampered["task"]["top1_min"] = 0.10
    verdict = apply_acceptance_policy(
        Measurements(**passing_measurements(contract)),
        tampered,
        expected_canaries=CANARIES,
    )
    assert verdict.verdict == "ACCEPT"
    frozen = apply_acceptance_policy(
        Measurements(**{**passing_measurements(contract), "task_top1": 0.55}),
        contract.thresholds,
        expected_canaries=CANARIES,
    )
    assert frozen.verdict == "REJECT"


def test_control_checks(contract):
    from warp_modeld.experiment import Measurements

    base = make_control(contract, "base-control")
    fields = passing_measurements(contract)
    fields["task_top1"] = 0.518
    verdict = check_control(base, Measurements(**fields), contract)
    assert verdict.verdict == "CONTROL_PASS"
    fields["task_top1"] = 0.60
    verdict = check_control(base, Measurements(**fields), contract)
    assert verdict.verdict == "REJECT"
    regressed = make_control(contract, "regressed-control")
    fields["task_top1"] = 0.40
    verdict = check_control(regressed, Measurements(**fields), contract)
    assert verdict.verdict == "REJECT"
    fields["task_top1"] = 0.60
    verdict = check_control(regressed, Measurements(**fields), contract)
    assert verdict.verdict == "REJECT"
    assert "harness failure" in verdict.reasons[0]


# --- rollback ---------------------------------------------------------------


def test_rollback_requires_every_state_bank(controller):
    ctl = ExperimentController(
        contract=controller.contract,
        compiler=FakeCompiler(),
        runtime=FakeRuntime(),
        lifecycle=FakeLifecycle(banks=("kv_cache", "ssm_recurrent")),
        receipts=ReceiptLog(controller.receipts.path.parent / "r2.jsonl"),
        environment=ENVIRONMENT,
    )
    with pytest.raises(StateFlushError):
        ctl.rollback()


def test_rollback_rejects_nonzero_baseline_diff(contract, tmp_path):
    runtime = FakeRuntime(
        baseline=BaselineCheck(max_logit_diff=0.5, exact_matches=13, sequences=14)
    )
    ctl = ExperimentController(
        contract=contract,
        compiler=FakeCompiler(),
        runtime=runtime,
        lifecycle=FakeLifecycle(),
        receipts=ReceiptLog(tmp_path / "receipts.jsonl"),
        environment=ENVIRONMENT,
    )
    with pytest.raises(StateFlushError):
        ctl.rollback()


def test_warp_lifecycle_adapter_collects_flush_banks():
    class FakeWarp:
        def rollback(self, reason):
            from warp_modeld.verifier import RollbackResult

            return RollbackResult(
                reason=reason,
                kill_switch_engaged=False,
                slots_flushed=(0, 1),
                elapsed_ms=1.0,
                receipt=None,
                bank_flush_receipts=(
                    BankFlushReceipt(
                        slot_id=0,
                        banks_requested=ALL_STATE_BANKS,
                        banks_confirmed=ALL_STATE_BANKS,
                        zone_manifest_id=None,
                        verified_clean=True,
                    ),
                    BankFlushReceipt(
                        slot_id=1,
                        banks_requested=ALL_STATE_BANKS,
                        banks_confirmed=ALL_STATE_BANKS,
                        zone_manifest_id=None,
                        verified_clean=True,
                    ),
                ),
            )

    adapter = WarpModeldLifecycle(FakeWarp())
    result = adapter.rollback("test")
    assert set(result.banks_flushed) == set(ALL_STATE_BANKS)
    assert result.slots_flushed == (0, 1)


# --- receipt log ------------------------------------------------------------


def test_receipt_log_is_hash_chained_and_tamper_evident(tmp_path):
    log = ReceiptLog(tmp_path / "log.jsonl")
    log.append("first", value=1)
    log.append("second", value=2)
    # An unsealed log is not a complete record, so verify() refuses it
    # even though the chain is intact.
    assert log.verify_chain()
    assert not log.verify()
    log.seal()
    assert log.verify()
    entries = log.read_all()
    assert [e["seq"] for e in entries] == [1, 2, 3]
    assert entries[1]["prev_sha256"] == entries[0]["entry_sha256"]
    assert entries[2]["event"] == "sealed"
    assert entries[2]["entry_count"] == 2
    lines = (tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["value"] = 99
    lines[0] = json.dumps(tampered, sort_keys=True)
    (tmp_path / "log.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not log.verify()


def test_receipt_log_detects_suffix_truncation(tmp_path):
    log = ReceiptLog(tmp_path / "log.jsonl")
    log.append("first", value=1)
    log.append("second", value=2)
    log.seal()
    assert log.verify()
    lines = (tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()
    # Deleting the seal leaves a valid shorter chain; verify() must
    # refuse it because the seal is gone.
    (tmp_path / "log.jsonl").write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    assert not log.verify()
    # The chain alone still holds: only the missing seal exposes this.
    assert log.verify_chain()
    # Deleting a middle entry breaks the chain and the seal count.
    (tmp_path / "log.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert log.verify()
    (tmp_path / "log.jsonl").write_text(
        "\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8"
    )
    assert not log.verify()


def test_receipt_log_refuses_append_after_seal(tmp_path):
    log = ReceiptLog(tmp_path / "log.jsonl")
    log.append("first", value=1)
    log.seal()
    with pytest.raises(ControllerError):
        log.append("second", value=2)


def test_evaluated_entry_carries_null_not_nan_for_pending_rollback(controller):
    import math

    candidate = controller.propose({"eta": 0.01, "lora_scale": 1.0})
    controller.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)
    measurements = controller.evaluate()
    assert measurements.rollback_max_logit_diff is None
    entries = controller.receipts.read_all()
    evaluated = [e for e in entries if e["event"] == "evaluated"][0]
    assert evaluated["measurements"]["rollback"]["max_logit_diff"] is None
    raw = (controller.receipts.path).read_text(encoding="utf-8")
    assert "NaN" not in raw
    assert "Infinity" not in raw
    # Strict JSON round-trips the whole log.
    import json as _json

    def _reject(name):
        raise ValueError(name)

    for line in raw.splitlines():
        _json.loads(line, parse_constant=_reject)


def test_receipt_log_refuses_non_finite_values(tmp_path):
    log = ReceiptLog(tmp_path / "log.jsonl")
    with pytest.raises(ValueError):
        log.append("bad", value=float("nan"))
    with pytest.raises(ValueError):
        log.append("bad", value=float("inf"))


def test_promote_refuses_measurements_without_rollback(controller):
    candidate = controller.propose({"eta": 0.01, "lora_scale": 1.0})
    controller.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)
    measurements = controller.evaluate()
    with pytest.raises(ControllerError):
        controller.promote_or_reject(candidate, measurements)


def test_repair_budget_enforced(controller):
    with pytest.raises(ControllerError):
        controller.run_experiment(
            {"eta": 0.01, "lora_scale": 1.0},
            actual_parent_sha256=PARENT_SHA,
            repair_round=4,
        )


# --- full fake run against the real contract --------------------------------


def test_full_run_accepts_passing_candidate(controller):
    verdict, receipt = controller.run_experiment(
        {"eta": 0.01, "lambda": 1, "lora_scale": 1.0, "quant": "bf16"},
        actual_parent_sha256=PARENT_SHA,
    )
    assert verdict.verdict == "ACCEPT"
    assert receipt["verdict"] == "ACCEPT"
    assert receipt["manifest_sha256"] == controller.contract.manifest_sha256
    assert receipt["suite_sha256"] == controller.contract.combined_suite_sha256
    assert receipt["candidate"]["hash_recorded_before_evaluation"] is True
    assert receipt["candidate"]["adapter_sha256"]
    assert receipt["measurements"]["task"]["top1"] == 0.58
    assert receipt["timings_ms"]["compile"] == 12.5
    assert receipt["repair_round"] == 0
    events = [e["event"] for e in controller.receipts.read_all()]
    assert events == [
        "candidate_proposed",
        "candidate_digest_recorded",
        "evaluated",
        "rollback_verified",
        "verdict",
        "receipt",
        "sealed",
    ]
    assert controller.receipts.verify()


def test_full_run_rejects_regressed_control(controller):
    regressed_suites = dict(PASSING_SUITES)
    regressed_suites["task"] = {
        "top1": 0.40,
        "contested_fix_fraction": 0.02,
        "break_fraction": 0.20,
    }
    controller.runtime.suites = regressed_suites
    candidate = controller.propose_control("regressed-control")
    controller.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)
    measurements = controller.evaluate()
    report = controller.rollback()
    assert report.verified
    complete = measurements.__class__(
        **{
            **measurements.__dict__,
            "rollback_exact_matches": report.baseline.exact_matches,
            "rollback_sequences": report.baseline.sequences,
            "rollback_max_logit_diff": report.baseline.max_logit_diff,
        }
    )
    verdict = controller.promote_or_reject(candidate, complete)
    assert verdict.verdict == "REJECT"


def test_receipt_matches_frozen_schema_shape(controller):
    verdict, receipt = controller.run_experiment(
        {"eta": 0.01, "lora_scale": 1.0},
        actual_parent_sha256=PARENT_SHA,
    )
    schema = controller.contract.receipt_schema
    required = set(schema["required"])
    assert required <= set(receipt)
    assert receipt["receipt_schema_version"] == "0.1.0"
    assert receipt["environment"]["llama_cpp_build"] == "b12549"
    assert receipt["environment"]["llama_cpp_commit"] == "8af68d486"
    assert receipt["measurements"]["margin"]["threshold"] == -0.37
    assert set(receipt["measurements"]) == {
        "task",
        "margin",
        "retention_iid",
        "retention_shifted",
        "safety",
        "rollback",
    }
    assert verdict.verdict == "ACCEPT"


# --- receipt schema version is read from the schema, fail closed ------------


def _receipt_with_schema_version_prop(contract, prop):
    import copy
    from dataclasses import replace

    from warp_modeld.experiment import Measurements

    schema = copy.deepcopy(contract.receipt_schema)
    if prop is None:
        schema["properties"].pop("receipt_schema_version", None)
    else:
        schema["properties"]["receipt_schema_version"] = prop
    mutated = replace(contract, receipt_schema=schema)
    candidate = propose_candidate({"eta": 0.01, "lora_scale": 1.0}, contract)
    compile_result = FakeCompiler().compile(candidate, PARENT_SHA)
    return build_receipt(
        contract=mutated,
        candidate=candidate,
        compile_result=compile_result,
        measurements=Measurements(**passing_measurements(contract)),
        verdict="ACCEPT",
        timings_ms={"compile": 12.5, "evaluate": 1.0, "deploy": 2.0},
        environment=ENVIRONMENT,
        repair_round=0,
    )


def test_build_receipt_reads_pinned_const_from_schema(contract):
    prop = contract.receipt_schema["properties"]["receipt_schema_version"]
    assert prop == {"const": "0.1.0"}
    receipt = _receipt_with_schema_version_prop(contract, prop)
    assert receipt["receipt_schema_version"] == "0.1.0"


def test_build_receipt_reads_const_object_version(contract):
    receipt = _receipt_with_schema_version_prop(contract, {"const": "0.2.0"})
    assert receipt["receipt_schema_version"] == "0.2.0"


def test_build_receipt_reads_bare_string_version(contract):
    receipt = _receipt_with_schema_version_prop(contract, "0.2.0")
    assert receipt["receipt_schema_version"] == "0.2.0"


def test_build_receipt_fails_closed_when_version_missing(contract):
    with pytest.raises(ControllerError):
        _receipt_with_schema_version_prop(contract, None)


def test_build_receipt_fails_closed_when_const_not_a_string(contract):
    with pytest.raises(ControllerError):
        _receipt_with_schema_version_prop(contract, {"const": 123})


def test_build_receipt_fails_closed_when_properties_missing(contract):
    from dataclasses import replace

    from warp_modeld.experiment import Measurements

    mutated = replace(contract, receipt_schema={"type": "object"})
    candidate = propose_candidate({"eta": 0.01, "lora_scale": 1.0}, contract)
    compile_result = FakeCompiler().compile(candidate, PARENT_SHA)
    with pytest.raises(ControllerError):
        build_receipt(
            contract=mutated,
            candidate=candidate,
            compile_result=compile_result,
            measurements=Measurements(**passing_measurements(contract)),
            verdict="ACCEPT",
            timings_ms={"compile": 12.5, "evaluate": 1.0, "deploy": 2.0},
            environment=ENVIRONMENT,
            repair_round=0,
        )


# --- regression tests for the orda re-review (2026-11-21) -------------------


def test_failed_mount_cannot_evaluate_without_digest_receipt(controller):
    class FailingMountRuntime(FakeRuntime):
        def mount_adapter(self, adapter_sha256, lora_scale):
            raise ControllerError("mock mount failed")

    controller.runtime = FailingMountRuntime()
    candidate = controller.propose({"eta": 0.01, "lora_scale": 1.0})
    with pytest.raises(ControllerError):
        controller.compile_and_bind(candidate, actual_parent_sha256=PARENT_SHA)
    events = [e["event"] for e in controller.receipts.read_all()]
    assert "candidate_digest_recorded" not in events
    with pytest.raises(ControllerError, match="no bound candidate"):
        controller.evaluate()


def test_scoring_failure_rolls_back_and_emits_no_success(controller):
    class FailingScoreRuntime(FakeRuntime):
        def score_suite(self, suite_name, cases):
            raise ControllerError("mock scoring failed")

    controller.runtime = FailingScoreRuntime()
    with pytest.raises(ControllerError, match="mock scoring failed"):
        controller.run_experiment(
            {"eta": 0.01, "lora_scale": 1.0},
            actual_parent_sha256=PARENT_SHA,
        )
    assert controller.lifecycle.calls == ["experiment_rollback"]
    events = [e["event"] for e in controller.receipts.read_all()]
    assert "verdict" not in events
    assert "receipt" not in events
    assert events[-1] == "sealed"
    assert controller.receipts.verify()


def test_empty_margin_evidence_cannot_pass_acceptance(contract):
    from warp_modeld.experiment import Measurements

    fields = passing_measurements(contract)
    fields.update(
        {
            "margins_adapter": (),
            "margins_baseline": (),
            "margin_adapter_requests": 0,
            "margin_baseline_requests": 0,
        }
    )
    verdict = apply_acceptance_policy(
        Measurements(**fields),
        contract.thresholds,
        expected_canaries=contract.suites["safety_canaries"]["n_canaries"],
    )
    assert verdict.verdict == "REJECT"
    assert "margin_adapter" in verdict.failed_gates
    assert "margin_baseline" in verdict.failed_gates


def test_zero_of_nine_canaries_cannot_pass_acceptance(contract):
    from warp_modeld.experiment import Measurements

    expected = contract.suites["safety_canaries"]["n_canaries"]
    assert expected == 9
    for run in (0, 5):
        fields = passing_measurements(contract)
        fields["safety_canaries_run"] = run
        verdict = apply_acceptance_policy(
            Measurements(**fields),
            contract.thresholds,
            expected_canaries=expected,
        )
        assert verdict.verdict == "REJECT"
        assert "safety_canaries" in verdict.failed_gates


def test_contract_drift_rejects_every_manifest_pinned_file(tmp_path):
    import shutil

    def mutate_audit(copied):
        audit_path = copied / "audit" / "split_leakage.json"
        data = json.loads(audit_path.read_text(encoding="utf-8"))
        data["held_out_states"] = -1
        audit_path.write_text(json.dumps(data), encoding="utf-8")

    def mutate_generator(copied):
        script_path = copied / "scripts" / "generate_suites.py"
        script_path.write_text(
            script_path.read_text(encoding="utf-8") + "\n# drift\n",
            encoding="utf-8",
        )

    for mutate in (mutate_audit, mutate_generator):
        copied = tmp_path / ("exp-" + mutate.__name__)
        shutil.copytree(EXP, copied)
        mutate(copied)
        with pytest.raises(ContractDriftError):
            load_contract(copied)


def test_rollback_requires_frozen_14_sequence_probe(controller):
    controller.runtime.baseline = BaselineCheck(
        max_logit_diff=0.0, exact_matches=1, sequences=1
    )
    with pytest.raises(StateFlushError):
        controller.rollback()
    from warp_modeld.experiment import Measurements

    fields = passing_measurements(controller.contract)
    fields.update(
        {
            "rollback_exact_matches": 1,
            "rollback_sequences": 1,
        }
    )
    verdict = apply_acceptance_policy(
        Measurements(**fields),
        controller.contract.thresholds,
        expected_canaries=CANARIES,
    )
    assert verdict.verdict == "REJECT"
    assert "rollback_sequences" in verdict.failed_gates


# --- regression tests for the orda and abu re-reviews (2026-11-22) ----------


def test_margin_counts_are_pinned_to_the_frozen_rule():
    from warp_modeld import experiment

    assert experiment.FROZEN_MARGIN_ADAPTER_REQUESTS == 84
    assert experiment.FROZEN_MARGIN_BASELINE_REQUESTS == 36


def test_one_request_per_side_cannot_pass_through_run_experiment(controller):
    controller.runtime.margins = {
        "threshold": -0.37,
        "adapter_requests": 1,
        "baseline_requests": 1,
        "margins_adapter": [0.18],
        "margins_baseline": [-1.0],
    }
    verdict, _ = controller.run_experiment(
        {"eta": 0.01, "lora_scale": 1.0}, actual_parent_sha256=PARENT_SHA
    )
    assert verdict.verdict == "REJECT"
    assert "margin_adapter" in verdict.failed_gates
    assert "margin_baseline" in verdict.failed_gates


@pytest.mark.parametrize(
    "change",
    [
        # Reported request count matches the frozen count, margins are short.
        {"margins_adapter": ADAPTER_MARGINS[:-1]},
        {"margins_baseline": BASELINE_MARGINS[:-1]},
        # Margins are the right length, reported request count is not.
        {"margin_adapter_requests": 83},
        {"margin_baseline_requests": 35},
        # Count and margins agree with each other but not with the rule.
        {"margins_adapter": ADAPTER_MARGINS[:-1], "margin_adapter_requests": 83},
        {
            "margins_baseline": BASELINE_MARGINS + (-1.0,),
            "margin_baseline_requests": 37,
        },
    ],
)
def test_margin_lengths_and_counts_must_equal_the_frozen_counts(contract, change):
    from warp_modeld.experiment import Measurements

    fields = passing_measurements(contract)
    fields.update(change)
    verdict = apply_acceptance_policy(
        Measurements(**fields), contract.thresholds, expected_canaries=CANARIES
    )
    assert verdict.verdict == "REJECT"
    gates = set(verdict.failed_gates)
    side = "margin_adapter" if "margins_adapter" in change or (
        "margin_adapter_requests" in change
    ) else "margin_baseline"
    assert side in gates


def test_expected_canaries_is_a_required_argument(contract):
    from warp_modeld.experiment import Measurements

    with pytest.raises(TypeError):
        apply_acceptance_policy(
            Measurements(**passing_measurements(contract)), contract.thresholds
        )


def test_five_of_nine_canaries_rejects_through_run_experiment(controller):
    suites = dict(PASSING_SUITES)
    suites["safety_canaries"] = {"canaries_run": 5, "failures": []}
    controller.runtime.suites = suites
    verdict, _ = controller.run_experiment(
        {"eta": 0.01, "lora_scale": 1.0}, actual_parent_sha256=PARENT_SHA
    )
    assert verdict.verdict == "REJECT"
    assert "safety_canaries" in verdict.failed_gates


def test_failing_rollback_leaves_a_rollback_failed_receipt(controller):
    class FailingScoreRuntime(FakeRuntime):
        def probe_margins(self):
            raise ControllerError("mock probe failed")

    class FailingLifecycle(FakeLifecycle):
        def rollback(self, reason):
            self.calls.append(reason)
            raise ControllerError("mock lifecycle rollback failed")

    controller.runtime = FailingScoreRuntime()
    controller.lifecycle = FailingLifecycle()
    with pytest.raises(ControllerError, match="mock probe failed"):
        controller.run_experiment(
            {"eta": 0.01, "lora_scale": 1.0},
            actual_parent_sha256=PARENT_SHA,
        )
    entries = controller.receipts.read_all()
    events = [e["event"] for e in entries]
    assert "rollback_failed" in events
    failed = entries[events.index("rollback_failed")]
    assert "mock lifecycle rollback failed" in failed["reason"]
    assert events[-1] == "sealed"
    assert controller.receipts.verify()


def test_rollback_reraises_a_lifecycle_failure_after_recording_it(controller):
    class FailingLifecycle(FakeLifecycle):
        def rollback(self, reason):
            raise ControllerError("mock lifecycle rollback failed")

    controller.lifecycle = FailingLifecycle()
    with pytest.raises(ControllerError, match="mock lifecycle rollback failed"):
        controller.rollback()
    events = [e["event"] for e in controller.receipts.read_all()]
    assert events == ["rollback_failed"]


# --- acceptance integrity, preregistered 2026-11-22 -------------------------


NON_FINITE_GATES = (
    "task_top1",
    "task_contested_fix_fraction",
    "task_break_fraction",
    "margin_threshold",
    "iid_mean_kl",
    "iid_top1_agreement",
    "shifted_mean_kl",
)


@pytest.mark.parametrize("gate", NON_FINITE_GATES)
@pytest.mark.parametrize("value", (float("nan"), float("inf"), -float("inf")))
def test_non_finite_scalar_gate_never_accepts(contract, gate, value):
    from warp_modeld.experiment import Measurements

    fields = passing_measurements(contract)
    fields[gate] = value
    with pytest.raises(ControllerError):
        apply_acceptance_policy(
            Measurements(**fields), contract.thresholds, expected_canaries=CANARIES
        )


@pytest.mark.parametrize("value", (float("nan"), float("inf")))
def test_non_finite_margin_never_accepts(contract, value):
    from warp_modeld.experiment import Measurements

    fields = passing_measurements(contract)
    fields["margins_adapter"] = (value, *ADAPTER_MARGINS[1:])
    with pytest.raises(ControllerError):
        apply_acceptance_policy(
            Measurements(**fields), contract.thresholds, expected_canaries=CANARIES
        )


def test_non_finite_rollback_diff_never_accepts(contract):
    from warp_modeld.experiment import Measurements

    fields = passing_measurements(contract)
    fields["rollback_max_logit_diff"] = float("nan")
    with pytest.raises(ControllerError):
        apply_acceptance_policy(
            Measurements(**fields), contract.thresholds, expected_canaries=CANARIES
        )


def test_acceptance_integrity_clean_control_still_accepts(contract):
    from warp_modeld.experiment import Measurements

    verdict = apply_acceptance_policy(
        Measurements(**passing_measurements(contract)),
        contract.thresholds,
        expected_canaries=CANARIES,
    )
    assert verdict.verdict == "ACCEPT"


def test_tampered_receipt_log_refuses_append(tmp_path):
    log = ReceiptLog(tmp_path / "receipts.jsonl")
    log.append("first", value=1)
    log.append("second", value=2)
    assert log.verify_chain()

    entries = log.read_all()
    entries[0]["value"] = 99
    with (tmp_path / "receipts.jsonl").open("w", encoding="utf-8") as f:
        for entry in entries:
            f.write(json.dumps(entry, sort_keys=True) + "\n")

    assert not log.verify_chain()
    with pytest.raises(ControllerError):
        log.append("third", value=3)
    assert len(log.read_all()) == 2


def test_clean_receipt_log_accepts_append(tmp_path):
    log = ReceiptLog(tmp_path / "receipts.jsonl")
    log.append("first", value=1)
    log.append("second", value=2)
    assert log.verify_chain()
    assert log.append("third", value=3)["seq"] == 3
    assert log.verify_chain()
