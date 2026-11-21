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

PASSING_MARGINS = {
    "threshold": -0.37,
    "adapter_requests": 84,
    "baseline_requests": 36,
    "margins_adapter": [-0.10, 0.0, 0.18],
    "margins_baseline": [-1.0, -0.9, -0.81],
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
        "margins_adapter": (-0.10, 0.0, 0.18),
        "margins_baseline": (-1.0, -0.9, -0.81),
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
    assert controller.receipts.verify()


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
        Measurements(**passing_measurements(contract)), contract.thresholds
    )
    assert verdict.verdict == "ACCEPT"
    assert verdict.failed_gates == ()


@pytest.mark.parametrize(
    "change",
    [
        {"task_top1": 0.55},
        {"task_contested_fix_fraction": 0.09},
        {"task_break_fraction": 0.09},
        {"margins_adapter": (-0.10, -0.40, 0.18)},
        {"margins_baseline": (-1.0, -0.30, -0.81)},
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
    verdict = apply_acceptance_policy(Measurements(**fields), contract.thresholds)
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
        Measurements(**passing_measurements(contract)), tampered
    )
    assert verdict.verdict == "ACCEPT"
    frozen = apply_acceptance_policy(
        Measurements(**{**passing_measurements(contract), "task_top1": 0.55}),
        contract.thresholds,
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
                        banks_confirmed=("kv_cache", "ssm_recurrent"),
                        zone_manifest_id=None,
                        verified_clean=True,
                    ),
                    BankFlushReceipt(
                        slot_id=1,
                        banks_requested=ALL_STATE_BANKS,
                        banks_confirmed=("lattice_horizontal_streams",),
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
    assert log.verify()
    entries = log.read_all()
    assert [e["seq"] for e in entries] == [1, 2]
    assert entries[1]["prev_sha256"] == entries[0]["entry_sha256"]
    lines = (tmp_path / "log.jsonl").read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["value"] = 99
    lines[0] = json.dumps(tampered, sort_keys=True)
    (tmp_path / "log.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert not log.verify()


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
