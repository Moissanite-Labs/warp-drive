#!/usr/bin/env python3
"""R5 refusal-site mutation & exact-invariant test suite for AUDIT-063 (Round 6 Arm R6-3).

Targets 100.0% AST mutation kill rate (`aletheia v1.3.0 mutate --add-cwd`) across BOTH
`experiment_contract.py` AND `bounded_controller.py`.

Pure Python 3 stdlib, zero bare asserts.
Safe under: python3 -I -B, python3 -I -O -B, python3 -I -B -W error, PYTHONHASHSEED=12345.
"""

from __future__ import annotations

from fractions import Fraction
import hashlib
import json
from pathlib import Path
import sys
from typing import Any, Mapping

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import bounded_controller as bc  # noqa: E402
import experiment_contract as ec  # noqa: E402
import verify_bounded_controller as vbc  # noqa: E402


def _require(cond: bool, msg: str) -> None:
    if not cond:
        raise RuntimeError(f"TEST_FAILURE: {msg}")


def _expect_err(exc_types, fn, msg: str, *, code: str | None = None) -> None:
    try:
        fn()
    except exc_types as exc:
        if code is not None and getattr(exc, "code", None) != code:
            raise RuntimeError(f"WRONG_CODE for {msg}: expected {code}, got {getattr(exc, 'code', None)}") from exc
        return
    raise RuntimeError(f"MUTATION_ESCAPE — expected error: {msg}")


def _sha(label: str) -> str:
    return hashlib.sha256(label.encode("utf-8")).hexdigest()


def _base_manifest() -> dict[str, Any]:
    train, clean, _ = vbc.build_reference_splits()
    return vbc.build_reference_manifest(train, clean)


def _valid_proposal(manifest: Mapping[str, Any], cid: str = "cand-1", **overrides: Any) -> dict[str, Any]:
    out: dict[str, Any] = {
        "candidate_id": cid,
        "contract_sha256": manifest["manifest_sha256"],
        "control_role": "candidate",
        "repair_round": 1,
        "target_layer": "blk.31",
        "rank": 8,
        "strength_num": 10,
        "strength_den": 10,
        "quantization": "f16",
        "seed": 7,
    }
    out.update(overrides)
    return out


def _base_metrics(**overrides: Any) -> dict[str, Any]:
    m: dict[str, Any] = {
        "task_exact_gain": [1, 20],       # exact boundary == min_task_exact_gain
        "logprob_margin_delta": [1, 2],   # exact boundary == min_logprob_margin_delta
        "iid_retention_drop": [1, 100],   # exact boundary == max_iid_retention_drop
        "shifted_retention_drop": [1, 50],# exact boundary == max_shifted_retention_drop
        "safety_canary_pass_rate": [1, 1],
        "residual_movement_before": [10, 1],
        "residual_movement_after": [10, 1],
        "unrelated_kl_before_milli": 50,
        "unrelated_kl_after_milli": 50,   # exact boundary == max_unrelated_kl_milli
        "text_plausible": True,
        "local_eval_ms": 10,
    }
    m.update(overrides)
    return m


def test_group1_contract_scalars_and_json() -> None:
    ec.verify_no_floats({"a": [1, "x", (True, None)]})
    _expect_err(ec.ExperimentContractError, lambda: ec.verify_no_floats({"a": [0.5]}), "float in list")
    _expect_err(ec.ExperimentContractError, lambda: ec.verify_no_floats((1, 2.0)), "float in tuple")

    parsed = ec.loads_strict_unique_json('{"a":1,"b":[2,3]}')
    _require(parsed == {"a": 1, "b": [2, 3]}, "strict json parse")
    _require(ec.loads_strict_unique_json('{"a":1.5}', forbid_floats=False) == {"a": 1.5}, "forbid_floats=False")
    _expect_err(ec.ExperimentContractError, lambda: ec.loads_strict_unique_json(123), "non-str json")  # type: ignore[arg-type]
    _expect_err(ec.ExperimentContractError, lambda: ec.loads_strict_unique_json("{bad"), "malformed json")
    _expect_err(ec.ExperimentContractError, lambda: ec.loads_strict_unique_json('{"a":1,"a":2}'), "dup json key", code="ERR_DUPLICATE_JSON_KEY")
    _expect_err(ec.ExperimentContractError, lambda: ec.loads_strict_unique_json('{"a":1.5}'), "float json", code="ERR_FLOAT_FORBIDDEN")

    # Exact int boundaries (exact min & exact max pass, 1 beyond fails)
    _require(ec.require_exact_int(1, "x", min_value=1, max_value=3) == 1, "min boundary pass")
    _require(ec.require_exact_int(3, "x", min_value=1, max_value=3) == 3, "max boundary pass")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_exact_int(True, "x"), "bool int")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_exact_int(0, "x", min_value=1), "below min")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_exact_int(4, "x", max_value=3), "above max")

    _expect_err(ec.ExperimentContractError, lambda: ec.require_non_empty_str("  ", "s"), "blank str")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_sha256("abc", "h"), "short sha")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_sha256(("a" * 64) + "\n", "h"), "trailing newline sha")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_commit40("abc", "c"), "short commit")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_commit40(("a" * 40) + "\n", "c"), "trailing newline commit")

    _require(ec.require_rational_pair([0, 1], "r", allow_zero_num=True) == Fraction(0), "zero rational")
    _require(ec.require_rational_pair([1, 1], "r", allow_zero_num=False) == Fraction(1), "pos rational")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_rational_pair([1], "r"), "len 1 pair")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_rational_pair([0, 1], "r", allow_zero_num=False), "zero num disallowed")
    _expect_err(ec.ExperimentContractError, lambda: ec.require_rational_pair([1, 0], "r"), "zero den")


def test_group2_split_leakage_audit() -> None:
    train, clean, leaky = vbc.build_reference_splits()
    ok = ec.audit_split_leakage(train, clean, max_pair_overlap_ratio=Fraction(0), raise_on_fail=True)
    _require(ok["passed"] and ok["pair_overlap_count"] == 0, "clean split passes")
    # Boundary max_pair_overlap_ratio == 1 allows leaky pair ratio 49/50 (families are already disjoint!)
    allow_all = ec.audit_split_leakage(train, leaky, max_pair_overlap_ratio=Fraction(1))
    _require(allow_all["passed"] and allow_all["pair_overlap_ratio_exact"] == "49/50", "boundary ratio 1 pass")
    exact_boundary = ec.audit_split_leakage(train, leaky, max_pair_overlap_ratio=Fraction(49, 50))
    _require(exact_boundary["passed"], "exact boundary 49/50 == max passes")
    _expect_err(
        ec.ExperimentContractError,
        lambda: ec.audit_split_leakage(train, leaky, max_pair_overlap_ratio=Fraction(0), raise_on_fail=True),
        "leaky raise_on_fail",
        code="ERR_SPLIT_LEAKAGE",
    )
    # Family-only overlap and prompt-only overlap tested independently (kills L230/L232 separately)
    fam_only = [dict(clean[0], family_id=train[0]["family_id"])]
    fam_res = ec.audit_split_leakage(train, fam_only)
    _require(not fam_res["passed"] and "family_overlap:1" in fam_res["reasons"], "fam-only overlap")
    prompt_only = [dict(clean[0], prompt=train[0]["prompt"])]
    prompt_res = ec.audit_split_leakage(train, prompt_only)
    _require(not prompt_res["passed"] and "prompt_overlap:1" in prompt_res["reasons"], "prompt-only overlap")

    # Input validation refusals
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage([], clean), "empty train")
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage(train, []), "empty heldout")
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage(train, clean, max_pair_overlap_ratio=Fraction(-1, 10)), "neg max ratio")
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage(train, clean, max_pair_overlap_ratio=Fraction(11, 10)), "gt 1 max ratio")
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage(["bad"], clean), "non-mapping case")  # type: ignore[list-item]
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage([dict(train[0], negative_tokens=[])], clean), "empty negs")
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage([train[0], train[0]], clean), "dup train id")
    _expect_err(ec.ExperimentContractError, lambda: ec.audit_split_leakage(train, [dict(clean[0], case_id=train[0]["case_id"])]), "dup cross id")


def test_group3_frozen_manifest_and_ring0() -> None:
    m = _base_manifest()
    _require(ec.validate_frozen_manifest(m, reader_version=1)["manifest_sha256"] == m["manifest_sha256"], "valid manifest")

    _expect_err(ec.ExperimentContractError, lambda: ec.validate_frozen_manifest("bad"), "non-map manifest", code="ERR_INVALID_MANIFEST")  # type: ignore[arg-type]
    missing = dict(m)
    missing.pop("target_layer")
    _expect_err(ec.ExperimentContractError, lambda: ec.validate_frozen_manifest(missing), "missing field")

    def _bad_mut(mutator_fn, msg: str) -> None:
        bad = json.loads(json.dumps(m))
        mutator_fn(bad)
        bad["manifest_sha256"] = ec.compute_manifest_sha256(bad)
        _expect_err(ec.ExperimentContractError, lambda: ec.validate_frozen_manifest(bad), msg)

    _bad_mut(lambda d: d.__setitem__("contract_schema", "wrong"), "bad schema")
    _bad_mut(lambda d: d.__setitem__("min_reader_version", 2), "reader too old")
    _bad_mut(lambda d: d.__setitem__("harness_label", "w-mcp"), "w-mcp rejected")
    _bad_mut(lambda d: d.__setitem__("receipt_schema", "wrong"), "bad receipt schema")
    _bad_mut(lambda d: d.__setitem__("compiler_repo", "Moissanite-Labs/weft"), "wrong weft repo")
    _bad_mut(lambda d: d.__setitem__("target_layer", "all_layers"), "bad target_layer")
    _bad_mut(lambda d: d.__setitem__("target_layer", "blk.31\n"), "trailing newline target_layer")
    _bad_mut(lambda d: d.__setitem__("max_repair_rounds", 4), "max_repair_rounds > 3")
    _bad_mut(lambda d: d.__setitem__("base_checkpoint", "bad"), "non-map ckpt")
    _bad_mut(lambda d: d.__setitem__("parent_lineage", "bad"), "non-map lineage")
    _bad_mut(lambda d: d["parent_lineage"].__setitem__("domain_commits", {}), "empty domain_commits")
    _bad_mut(lambda d: d["parent_lineage"].__setitem__("contested_heads", ["h1"]), "contested heads")
    _bad_mut(lambda d: d.__setitem__("allowed_knobs", "bad"), "non-map knobs")
    _bad_mut(lambda d: d["allowed_knobs"].__setitem__("ranks", []), "empty ranks")
    _bad_mut(lambda d: d["allowed_knobs"].__setitem__("quantizations", ["int2"]), "bad quant")
    _bad_mut(lambda d: d.__setitem__("frozen_thresholds", "bad"), "non-map thresh")
    _bad_mut(lambda d: d["frozen_thresholds"].__setitem__("safety_canary_pass_required", [9, 10]), "safety < 1")
    _bad_mut(lambda d: d["frozen_thresholds"].__setitem__("max_rollback_logit_diff_milli", 1), "rb diff != 0")
    _bad_mut(lambda d: d.__setitem__("suite_digests", "bad"), "non-map suites")
    _bad_mut(lambda d: d.__setitem__("preregistration", "bad"), "non-map prereg")
    _bad_mut(lambda d: d["preregistration"].__setitem__("split_leakage_audit_passed", False), "prereg leakage false")
    _bad_mut(
        lambda d: d["preregistration"].__setitem__("data_commit", d["preregistration"]["plan_commit"]),
        "same commit prereg",
    )

    tampered = dict(m)
    tampered["manifest_sha256"] = _sha("wrong-digest")
    _expect_err(ec.ExperimentContractError, lambda: ec.validate_frozen_manifest(tampered), "tampered sha", code="ERR_MANIFEST_TAMPERED")

    # Extension collision check
    _expect_err(
        ec.ExperimentContractError,
        lambda: ec.build_frozen_manifest(
            base_checkpoint=m["base_checkpoint"],
            runtime_flags_sha256=m["runtime_flags_sha256"],
            compiler_commit=m["compiler_commit"],
            parent_lineage=m["parent_lineage"],
            target_layer=m["target_layer"],
            allowed_knobs=m["allowed_knobs"],
            frozen_thresholds=m["frozen_thresholds"],
            max_repair_rounds=m["max_repair_rounds"],
            suite_digests=m["suite_digests"],
            preregistration=m["preregistration"],
            extensions={"target_layer": "blk.0"},
        ),
        "extension collision",
        code="ERR_EXTENSION_COLLISION",
    )

    # Ring-0 immutability checks (top-level, uppercase, nested dict & list!)
    ec.verify_ring0_immutability(m, {"candidate_id": "c1", "contract_sha256": m["manifest_sha256"], "notes": ["ok"]})
    _expect_err(ec.ExperimentContractError, lambda: ec.verify_ring0_immutability(m, "bad"), "non-map proposal")  # type: ignore[arg-type]
    _expect_err(ec.ExperimentContractError, lambda: ec.verify_ring0_immutability(m, {"lora": []}), "forbidden lora")
    _expect_err(ec.ExperimentContractError, lambda: ec.verify_ring0_immutability(m, {"LORA": []}), "uppercase LORA")
    _expect_err(ec.ExperimentContractError, lambda: ec.verify_ring0_immutability(m, {"nested": [{"thresholds_override": [0, 1]}]}), "nested list override")
    _expect_err(ec.ExperimentContractError, lambda: ec.verify_ring0_immutability(m, {"contract_sha256": _sha("x")}), "contract drift")


def test_group4_reconciler_clock_latch_and_ledger() -> None:
    lat = bc.certify_reconciler_lattice_385()
    _require(lat["total_transitions"] == 385 and lat["all_invariants_sound"] and lat["tombstone_resolutions"] == 32, "385 lattice")
    _expect_err(bc.ControllerError, lambda: bc.reconcile_controller_step("BadPhase", "Live", "Compiled"), "unknown phase")
    _expect_err(bc.ControllerError, lambda: bc.reconcile_controller_step("Proposing", "BadContact", "Compiled"), "unknown contact")
    _expect_err(bc.ControllerError, lambda: bc.reconcile_controller_step("Proposing", "Live", "BadObs"), "unknown obs")

    # Exact clock pair
    _require(bc.map_host_to_controller_exact(Fraction(10), Fraction(2), Fraction(7)) == Fraction(15), "clock affine")
    _expect_err(bc.ControllerError, lambda: bc.map_host_to_controller_exact(10, Fraction(2), Fraction(7)), "non-frac clock")  # type: ignore[arg-type]

    # Exact Goodhart Latch boundaries (exact == pass, 1 over -> LATCH_HALT)
    eq_pass = bc.evaluate_goodhart_latch(
        residual_before=Fraction(0),
        residual_after=Fraction(0),
        unrelated_kl_before_milli=50,
        unrelated_kl_after_milli=50,
        max_unrelated_kl_milli=50,
    )
    _require(not eq_pass["latch_halt"] and eq_pass["decision"] == "PASS", "exact latch boundary pass")
    cap_fail = bc.evaluate_goodhart_latch(
        residual_before=Fraction(10),
        residual_after=Fraction(10),
        unrelated_kl_before_milli=50,
        unrelated_kl_after_milli=51,
        max_unrelated_kl_milli=50,
    )
    _require(cap_fail["latch_halt"] and cap_fail["kl_over_cap"], "kl over cap halt")
    precond_trap = bc.evaluate_goodhart_latch(
        residual_before=Fraction(10),
        residual_after=Fraction(9),
        unrelated_kl_before_milli=10,
        unrelated_kl_after_milli=16,
        max_unrelated_kl_milli=50,
    )
    _require(precond_trap["latch_halt"] and precond_trap["proxy_shrank"] and precond_trap["kl_inflated"], "precond trap")
    _expect_err(bc.ControllerError, lambda: bc.evaluate_goodhart_latch(residual_before=Fraction(-1), residual_after=Fraction(0), unrelated_kl_before_milli=0, unrelated_kl_after_milli=0, max_unrelated_kl_milli=0), "neg res before")
    _expect_err(bc.ControllerError, lambda: bc.evaluate_goodhart_latch(residual_before=Fraction(0), residual_after=Fraction(-1), unrelated_kl_before_milli=0, unrelated_kl_after_milli=0, max_unrelated_kl_milli=0), "neg res after")

    # Ledger key length boundary (16 ok, 15 fail) & tamper detection
    key16 = b"0123456789abcdef"
    _expect_err(bc.ControllerError, lambda: bc.SignedExperimentLedger(b"short-key-15byt"), "15-byte key reject")
    led = bc.SignedExperimentLedger(key16)
    led.append("op1", candidate_id="c1", payload={"x": 1})
    led.append("op2", candidate_id="c1", payload={"x": 2})
    ver = bc.verify_receipt_chain_independent(led.records, secret_key=key16)
    _require(ver["valid"] and ver["count"] == 2 and ver["head_sha256"] == led.head_sha256, "valid ledger")

    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent([], secret_key=key16), "empty ledger")
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent(["bad"], secret_key=key16), "non-map rec")  # type: ignore[list-item]
    # Signed-record replay/truncation attacks (valid hash & HMAC, isolating seq and prev_hash guards!)
    import hmac as _hmac

    def _sign_forged(
        seq_val: int,
        prev_val: str,
        *,
        schema_val: str = ec.RECEIPT_SCHEMA,
        iface_val: str = bc.INTERFACE_CLASS,
    ) -> dict[str, Any]:
        body = {
            "receipt_schema": schema_val,
            "interface_class": iface_val,
            "seq": seq_val,
            "prev_receipt_sha256": prev_val,
            "operation": "forged",
            "candidate_id": "c1",
            "payload": {"x": 1},
        }
        rsha = ec.sha256_canonical(body)
        sig = _hmac.new(key16, f"{rsha}:hmac-sha256:warp-exp-hmac-v1".encode("ascii"), hashlib.sha256).hexdigest()
        return {**body, "receipt_sha256": rsha, "sig_alg": "hmac-sha256", "key_id": "warp-exp-hmac-v1", "signature": sig}

    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent([dict(led.records[0], forged_verdict="PROMOTED")], secret_key=key16), "extra unhashed top-level key")
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent([_sign_forged(1, bc.GENESIS_HASH, schema_val="wrong")], secret_key=key16), "signed wrong schema")
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent([_sign_forged(1, bc.GENESIS_HASH, iface_val="w-mcp")], secret_key=key16), "signed wrong interface")
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent([_sign_forged(2, bc.GENESIS_HASH)], secret_key=key16), "signed seq skip")
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent([_sign_forged(1, "1" * 64)], secret_key=key16), "signed broken prev")
    bad_sha = [dict(led.records[0], receipt_sha256="2" * 64)]
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent(bad_sha, secret_key=key16), "bad sha")
    bad_kid = [dict(led.records[0], key_id="other")]
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent(bad_kid, secret_key=key16), "bad key_id")
    bad_sig = [dict(led.records[0], signature="3" * 64)]
    _expect_err(bc.ControllerError, lambda: bc.verify_receipt_chain_independent(bad_sig, secret_key=key16), "bad sig")


def test_group5_controller_5ops_and_boundaries() -> None:
    m = _base_manifest()
    key = b"controller-test-key-32bytes-0001"
    led = bc.SignedExperimentLedger(key)
    ctrl = bc.BoundedExperimentController(m, led)
    comp = vbc._DeterministicMockCompiler()
    ckpt_dig = ctrl.base_checkpoint_digest
    flags_dig = m["runtime_flags_sha256"]

    _expect_err(bc.ControllerError, lambda: ctrl.candidate_state("missing"), "unknown state")

    # Propose boundary tests: min strength (1) at round 1, max strength (20) at round 3 ALL PASS!
    _require(ctrl.required_state_banks == ("kv_cache", "ssm_recurrent", "lattice_horizontal_streams"), "req banks from ckpt")
    ctrl.propose_candidate(_valid_proposal(m, "c-min", strength_num=1, repair_round=1))
    ctrl.propose_candidate(_valid_proposal(m, "c-max", strength_num=20, repair_round=3))
    _require(ctrl.candidate_state("c-max")["phase"] == "Proposing", "c-max proposing")

    # Propose refusals (including CTRL-BYPASS-1 duplicate round-1 replay & candidate round 0 & control round 1!)
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-unk", repair_round=2, extra_field=1)), "unknown key")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-min", repair_round=2)), "dup cid")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-role", repair_round=0, control_role="bad")), "bad role", code="ERR_INVALID_CONTROL_ROLE")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-r0", repair_round=0)), "candidate round 0")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-r4", repair_round=4)), "candidate round 4")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-dup-r1", repair_round=1)), "duplicate candidate round 1", code="ERR_REPAIR_BUDGET_EXCEEDED")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-ctrl-r1", control_role="regressed_control", repair_round=1)), "control round != 0", code="ERR_REPAIR_BUDGET_EXCEEDED")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-lay", repair_round=2, target_layer="blk.0")), "bad layer")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-q", repair_round=2, quantization="q4_0")), "bad quant")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-b0", control_role="unchanged_base", repair_round=0, rank=4, strength_num=0)), "base rank!=0")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-rk", repair_round=2, rank=32)), "bad rank")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-s0", repair_round=2, strength_num=0)), "strength < min")
    _expect_err(bc.ControllerError, lambda: ctrl.propose_candidate(_valid_proposal(m, "c-s21", repair_round=2, strength_num=21)), "strength > max")

    # compile_and_bind refusals + exact pass
    _expect_err(bc.ControllerError, lambda: ctrl.compile_and_bind("missing", compiler=comp, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig), "compile missing")
    _expect_err(bc.ControllerError, lambda: ctrl.compile_and_bind("c-min", compiler=comp, live_checkpoint_digest=_sha("bad"), live_runtime_flags_sha256=flags_dig), "ckpt drift")
    _expect_err(bc.ControllerError, lambda: ctrl.compile_and_bind("c-min", compiler=comp, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=_sha("bad")), "flags drift")

    class _BadCommitCompiler:
        is_mock = True
        def compile_candidate(self, *, manifest, proposal):
            return {"candidate_adapter_sha256": _sha("a"), "compile_ms": 1, "compiler_commit": "f" * 40}

    _expect_err(bc.ControllerError, lambda: ctrl.compile_and_bind("c-min", compiler=_BadCommitCompiler(), live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig), "compiler drift")
    b_min = ctrl.compile_and_bind("c-min", compiler=comp, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig)
    _expect_err(bc.ControllerError, lambda: ctrl.compile_and_bind("c-min", compiler=comp, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig), "double compile")

    # evaluate refusals + exact boundary promotion (including genuine negative task_exact_gain [-1, 20]!)
    rt = vbc._DeterministicMockRuntime(
        {
            "c-min": _base_metrics(),  # exact boundaries on every threshold -> MUST PROMOTE!
            "c-fail-safety": _base_metrics(safety_canary_pass_rate=[9, 10]),
            "c-fail-iid": _base_metrics(iid_retention_drop=[11, 1000]),
            "c-fail-shift": _base_metrics(shifted_retention_drop=[21, 1000]),
            "c-fail-gain": _base_metrics(task_exact_gain=[-1, 20]),  # signed negative -5pp regression!
            "c-fail-lp": _base_metrics(logprob_margin_delta=[49, 100]),
            "c-fail-latch": _base_metrics(unrelated_kl_after_milli=51),
            "c-ctrl-no-promote": _base_metrics(),
            "c-base-ok": _base_metrics(task_exact_gain=[0, 1], logprob_margin_delta=[0, 1]),
            "c-base-bad": _base_metrics(task_exact_gain=[0, 1], logprob_margin_delta=[1, 10]),
            "c-bad-lp-fmt": _base_metrics(logprob_margin_delta="bad"),
        }
    )
    _expect_err(bc.ControllerError, lambda: ctrl.evaluate("missing", runtime=rt, live_adapter_sha256=b_min["candidate_adapter_sha256"], live_checkpoint_digest=ckpt_dig), "eval missing")
    _expect_err(bc.ControllerError, lambda: ctrl.evaluate("c-max", runtime=rt, live_adapter_sha256=b_min["candidate_adapter_sha256"], live_checkpoint_digest=ckpt_dig), "eval before compile")
    _expect_err(bc.ControllerError, lambda: ctrl.evaluate("c-min", runtime=rt, live_adapter_sha256=b_min["candidate_adapter_sha256"], live_checkpoint_digest=_sha("bad")), "eval ckpt drift")
    _expect_err(bc.ControllerError, lambda: ctrl.evaluate("c-min", runtime=rt, live_adapter_sha256=_sha("bad"), live_checkpoint_digest=ckpt_dig), "eval adapter drift")
    _expect_err(bc.ControllerError, lambda: ctrl.promote_or_reject("missing"), "promote missing")
    _expect_err(bc.ControllerError, lambda: ctrl.promote_or_reject("c-min"), "promote before eval")

    ctrl.evaluate("c-min", runtime=rt, live_adapter_sha256=b_min["candidate_adapter_sha256"], live_checkpoint_digest=ckpt_dig)
    v_min = ctrl.promote_or_reject("c-min")
    _require(v_min["verdict"] == "PROMOTED" and v_min["failures"] == [], "exact boundary candidate promotes")
    _expect_err(bc.ControllerError, lambda: ctrl.promote_or_reject("c-min"), "double promote rejected")

    # Exercise every single rejection branch individually via regressed_control (kills every `failures.append(...)` mutant!)
    for cid, expected_reason in (
        ("c-fail-safety", "safety_canary_failed"),
        ("c-fail-iid", "iid_retention_drop_exceeded"),
        ("c-fail-shift", "shifted_retention_drop_exceeded"),
        ("c-fail-gain", "task_exact_gain_below_threshold"),
        ("c-fail-lp", "logprob_margin_below_threshold"),
        ("c-fail-latch", "goodhart_kl_latch_halted"),
        ("c-ctrl-no-promote", "control_role_cannot_promote"),
    ):
        ctrl.propose_candidate(_valid_proposal(m, cid, control_role="regressed_control", repair_round=0))
        b = ctrl.compile_and_bind(cid, compiler=comp, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig)
        ctrl.evaluate(cid, runtime=rt, live_adapter_sha256=b["candidate_adapter_sha256"], live_checkpoint_digest=ckpt_dig)
        v = ctrl.promote_or_reject(cid)
        _require(v["verdict"] == "REJECTED" and expected_reason in v["failures"], f"{cid} -> {expected_reason}")

    # Base control ok vs non-zero logprob shift reject
    for cid, exp_v in (("c-base-ok", "CONTROL_BASE_PASS"), ("c-base-bad", "REJECTED")):
        ctrl.propose_candidate(_valid_proposal(m, cid, control_role="unchanged_base", repair_round=0, rank=0, strength_num=0))
        b = ctrl.compile_and_bind(cid, compiler=comp, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig)
        ctrl.evaluate(cid, runtime=rt, live_adapter_sha256=b["candidate_adapter_sha256"], live_checkpoint_digest=ckpt_dig)
        v = ctrl.promote_or_reject(cid)
        _require(v["verdict"] == exp_v, f"{cid} -> {exp_v}")

    # Malformed logprob_margin_delta format rejected
    ctrl.propose_candidate(_valid_proposal(m, "c-bad-lp-fmt", repair_round=2))
    b_lp = ctrl.compile_and_bind("c-bad-lp-fmt", compiler=comp, live_checkpoint_digest=ckpt_dig, live_runtime_flags_sha256=flags_dig)
    _expect_err(bc.ControllerError, lambda: ctrl.evaluate("c-bad-lp-fmt", runtime=rt, live_adapter_sha256=b_lp["candidate_adapter_sha256"], live_checkpoint_digest=ckpt_dig), "bad lp pair")

    # Rollback refusals (including CTRL-BYPASS-2 kv-only omission on hybrid+lattice checkpoint!) & exact 0-diff pass
    _expect_err(bc.ControllerError, lambda: ctrl.rollback("missing", runtime=rt), "rb missing")
    _expect_err(bc.ControllerError, lambda: ctrl.rollback("c-min", runtime=rt, expected_state_banks=("kv_cache",)), "rb missing checkpoint banks", code="ERR_INVALID_STATE_BANKS")
    rt.fail_lattice_flush = True
    _expect_err(bc.ControllerError, lambda: ctrl.rollback("c-min", runtime=rt), "rb incomplete bank flush")
    rt.fail_lattice_flush = False
    rt.inject_logit_drift_milli = 1
    _expect_err(bc.ControllerError, lambda: ctrl.rollback("c-min", runtime=rt), "rb logit drift > 0")
    rt.inject_logit_drift_milli = 0
    rb_ok = ctrl.rollback("c-min", runtime=rt)
    _require(rb_ok["baseline_logits_restored"] is True, "rb exact 0 diff passes")


def test_group6_cerebras_advisory_boundary() -> None:
    m = _base_manifest()
    bc.sanitize_outbound_payload({"text": "ok", "items": [{"score": 1}]})
    _expect_err(bc.ControllerError, lambda: bc.sanitize_outbound_payload({"nested": [{"api_key": "sk"}]}), "nested forbidden key")

    tr = vbc._DeterministicMockCerebrasTransport(m["manifest_sha256"])
    cli = bc.CerebrasKimiAdvisoryClient(tr, expected_model="kimi-k3.1-pro", max_retries=1)

    p = cli.propose(frozen_manifest=m, history_summary=[])
    _require(p["parsed"]["candidate_id"] == "cand-r1-underfit", "propose ok")
    d = cli.diagnose(frozen_manifest=m, failure_report={"f": 1}, remaining_rounds=1)
    _require("repair_proposal" in d["parsed"], "diagnose ok")
    c = cli.compare(case_id="c1", baseline_text="a", adapted_text="b")
    _require(c["parsed"]["advisory_vote"] == "BETTER", "compare ok")

    # Custom transport for schema & non-dict refusal tests
    class _RawRespTransport:
        transport_mode = "mock_contract"
        live_credentials_used = False
        def __init__(self, body: str, *, served: str = "kimi-k3.1-pro") -> None:
            self._body = body
            self._served = served
        def call(self, request):
            return {
                "status": "ok",
                "served_model": self._served,
                "prompt_tokens": 10,
                "completion_tokens": 10,
                "latency_ms": 5,
                "content_json": self._body,
            }

    c_nondict = bc.CerebrasKimiAdvisoryClient(_RawRespTransport("[1,2]"))
    _expect_err(bc.ControllerError, lambda: c_nondict.compare(case_id="x", baseline_text="a", adapted_text="b"), "non-dict json")
    _require(c_nondict.receipts[-1]["status"] == "rejected" and c_nondict.receipts[-1]["error_code"] == "ERR_MALFORMED_ADVISORY_RESPONSE", "non-dict receipt recorded")

    c_badprop = bc.CerebrasKimiAdvisoryClient(_RawRespTransport("{}"))
    _expect_err(bc.ControllerError, lambda: c_badprop.propose(frozen_manifest=m, history_summary=[]), "propose missing fields")
    _require(c_badprop.receipts[-1]["status"] == "rejected" and c_badprop.receipts[-1]["error_code"] == "ERR_INVALID_PROPOSAL_SCHEMA", "bad propose receipt recorded")

    c_baddiag = bc.CerebrasKimiAdvisoryClient(_RawRespTransport("{}"))
    _expect_err(bc.ControllerError, lambda: c_baddiag.diagnose(frozen_manifest=m, failure_report={}, remaining_rounds=1), "diagnose missing fields")
    _require(c_baddiag.receipts[-1]["status"] == "rejected" and c_baddiag.receipts[-1]["error_code"] == "ERR_INVALID_DIAGNOSIS_SCHEMA", "bad diagnose receipt recorded")

    c_badcmp = bc.CerebrasKimiAdvisoryClient(_RawRespTransport('{"advisory_vote":"INVALID"}'))
    _expect_err(bc.ControllerError, lambda: c_badcmp.compare(case_id="x", baseline_text="a", adapted_text="b"), "invalid vote")
    _require(c_badcmp.receipts[-1]["status"] == "rejected" and c_badcmp.receipts[-1]["error_code"] == "ERR_INVALID_COMPARE_SCHEMA", "bad compare receipt recorded")

    _expect_err(bc.ControllerError, lambda: bc.CerebrasKimiAdvisoryClient(_RawRespTransport('{"advisory_vote":"BETTER"}', served="wrong-model")).compare(case_id="x", baseline_text="a", adapted_text="b"), "model substitution", code="ERR_MODEL_SUBSTITUTION")

    tr.mode = "malformed_json"
    _expect_err(bc.ControllerError, lambda: cli.compare(case_id="x", baseline_text="a", adapted_text="b"), "dup key json")
    _require(cli.receipts[-1]["status"] == "rejected" and cli.receipts[-1]["error_code"] == "ERR_MALFORMED_ADVISORY_RESPONSE", "dup key receipt recorded")
    tr.mode = "timeout"
    _expect_err(bc.ControllerError, lambda: cli.compare(case_id="x", baseline_text="a", adapted_text="b"), "transport error")
    _require(cli.receipts[-1]["status"] == "error" and cli.receipts[-1]["error_code"] == "ERR_TIMEOUT", "timeout receipt recorded")


def run_all_tests() -> int:
    test_group1_contract_scalars_and_json()
    test_group2_split_leakage_audit()
    test_group3_frozen_manifest_and_ring0()
    test_group4_reconciler_clock_latch_and_ledger()
    test_group5_controller_5ops_and_boundaries()
    test_group6_cerebras_advisory_boundary()
    return 6


if __name__ == "__main__":
    n = run_all_tests()
    print(f"AUDIT_063_R5_BOUNDED_CONTROLLER_SUITE PASS ({n}/6 groups)")
    sys.exit(0)
