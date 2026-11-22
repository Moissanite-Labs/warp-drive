#!/usr/bin/env python3
"""R1-R5 Verification, Invariance, Unseen-Instance & 100% Mutation-Kill Suite for AUDIT-064 (Arm R6-4).

Pure Python 3 stdlib; zero bare asserts; 100% guard coverage for `aletheia v1.3.0 mutate --add-cwd`.
"""

from __future__ import annotations

from fractions import Fraction
import json
from pathlib import Path
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import warp_weight_iteration_bridge as wb  # noqa: E402


def check(cond: bool, msg: str) -> None:
    if not cond:
        raise wb.WarpIterationAuditError("TEST_FAIL", msg)


def expect_code(code: str, fn) -> None:
    try:
        fn()
    except wb.WarpIterationAuditError as exc:
        check(exc.code == code, f"Expected [{code}], got [{exc.code}]: {exc.message}")
        return
    raise wb.WarpIterationAuditError("TEST_MISSED_ERR", f"Expected [{code}] but call succeeded")


def reject_any_float(obj: object, path: str = "root") -> None:
    check(not isinstance(obj, float), f"Float forbidden at {path}: {obj!r}")
    if isinstance(obj, dict):
        for k, v in obj.items():
            reject_any_float(v, f"{path}.{k}")
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            reject_any_float(v, f"{path}[{i}]")


def test_group_1_end_to_end_zero_float_certificate() -> None:
    res = wb.run_all(standalone=True)
    reject_any_float(res)
    check(res["verdict"] == "WARP_WEIGHT_ITERATION_BRIDGE_ALL_VERIFIED", f"Bad verdict: {res['verdict']}")
    raw = json.dumps(res, sort_keys=True, allow_nan=False)

    def _no_float(s: str) -> None:
        raise wb.WarpIterationAuditError("FLOAT_JSON", f"Float in JSON: {s!r}")

    parsed = json.loads(raw, parse_float=_no_float)
    p2 = parsed["pillar_2_blk31_causal_and_qwen35_4b_census"]["exact_causal_propagation"]
    p3 = parsed["pillar_3_preconditioning_kl_and_lattice_bridge"]
    p4 = parsed["pillar_4_issue3_governed_iteration_gate"]

    check(p2["WI1_terminal_layer_no_lattice"]["no_flush_rollback_logit_err_sq"] == "0/1", "WI-1 failed")
    check(p2["WI2_early_layer_cross_token_taint"]["full_kv_ssm_flush_rollback_err_sq"] == "0/1", "WI-2 flush failed")
    check(p2["WI3_terminal_layer_with_horizontal_lattice_arXiv2611_21608"]["proves_multibank_contract_non_relaxable"] is True, "WI-3 failed")
    check(p3["WI4_fisher_kl_preconditioning_inversion"]["kl_inflation_ratio_pre_over_raw"] == "401/225", "WI-4 ratio wrong")
    check(p3["WI4_fisher_kl_preconditioning_inversion"]["fisher_schur_unrelated_kl"] == "0/1", "WI-4 Schur KL nonzero")
    check(p3["WI5_siliquant_hessian_bloat_and_gdn_persistence"]["hessian_bloat_factor"] == "9/1", "WI-5 bloat wrong")
    check(p3["WI6_margin_vs_argmax_blindness"]["argmax_identical"] is True, "WI-6 argmax wrong")
    check(p4["verified"] is True, "Pillar 4 failed")


def test_group_2_exact_invariance_and_algebraic_identities() -> None:
    # 1. Exact permutation invariance of Fisher-KL curvature under simultaneous row/prob permutation
    probs = wb.qvec([Fraction(1, 2), Fraction(1, 4), Fraction(1, 4)])
    u = wb.qmat([[2, 0, 1], [-1, 7, 1], [-1, -7, 1]])
    f1 = wb.exact_fisher_matrix_in_residual_space(probs, u)
    probs_perm = wb.qvec([Fraction(1, 4), Fraction(1, 2), Fraction(1, 4)])
    u_perm = wb.qmat([[-1, 7, 1], [2, 0, 1], [-1, -7, 1]])
    f2 = wb.exact_fisher_matrix_in_residual_space(probs_perm, u_perm)
    check(f1 == f2, "Fisher-KL matrix not invariant under vocabulary permutation")

    # 2. Exact constant-logit shift invariance: adding c*(1,1,1)^T to any column of U leaves F_p identical!
    u_shift = wb.qmat([[5, 3, 1], [2, 10, 1], [2, -4, 1]])
    check(wb.exact_fisher_matrix_in_residual_space(probs, u_shift) == f1, "Fisher-KL not softmax shift invariant")

    # 3. Hyperbolic 2x2 Bunch-Kaufman pivot, diagonal swap, zero eigenvalue & empty Schur identity
    hyp = wb.qmat([[0, 3, 0], [3, 0, 0], [0, 0, 0]])
    check(wb.op_krein_inertia(hyp) == (1, 1, 1), "Hyperbolic inertia wrong")
    swap_m = wb.qmat([[0, 0, 0], [0, 2, 0], [0, 0, -5]])
    check(wb.op_krein_inertia(swap_m) == (1, 1, 1), "Swap-diag inertia wrong")
    hyp_far = wb.qmat([[0, 0, 2], [0, 0, 0], [2, 0, 0]])
    check(wb.op_krein_inertia(hyp_far) == (1, 1, 1), "Far hyperbolic pivot inertia wrong")
    check(wb.op_schur_complement(wb.qeye(2), ()) == wb.qeye(2), "Empty elim Schur wrong")


def test_group_3_unseen_instances_and_boundary_accepts() -> None:
    # 1. Unseen 4-token Fisher-KL inversion with nonuniform probabilities (1/2, 1/4, 1/8, 1/8)
    p4 = wb.qvec([Fraction(1, 2), Fraction(1, 4), Fraction(1, 8), Fraction(1, 8)])
    u4 = wb.qmat([[1, 0, 1], [-1, 0, 1], [0, 8, 1], [0, -8, 1]])
    f4 = wb.exact_fisher_matrix_in_residual_space(p4, u4)
    check(wb.op_krein_inertia(f4) == (2, 1, 0), "Unseen 4-token Fisher inertia wrong")
    check(wb.exact_quadratic_fisher_kl(wb.qvec([0, 0, 5]), f4) == 0, "Unseen gauge direction KL nonzero")

    # 2. Boundary valid values for hardened state banks (capability_tag=0, 255; slot_id=0; tokens=0)
    s0 = wb.HardenedStateBankStatus(bank=wb.STATE_BANK_KV, tainted=False, active_lora_ids=(), tokens_or_layers=0, capability_tag=0)
    s255 = wb.HardenedStateBankStatus(bank=wb.STATE_BANK_SSM, tainted=False, active_lora_ids=(0,), tokens_or_layers=0, capability_tag=255)
    check(s0.is_clean is True and s255.is_clean is False, "Boundary HardenedStateBankStatus wrong")
    wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=True, lattice_layers=1, lattice_width=1)
    wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=False, lattice_layers=0, lattice_width=0)

    # 3. Unverified receipt (verified_clean=False) allowed even with partial banks_confirmed
    rec_unclean = wb.HardenedBankFlushReceipt(
        slot_id=0, banks_requested=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), banks_confirmed=(wb.STATE_BANK_KV,),
        zone_manifest_id=None, verified_clean=False,
    )
    check(rec_unclean.verified_clean is False, "Unclean receipt wrong")

    # 4. Fixed-radix exact equality boundary (value * den == num * radix -> True; +1 -> False)
    check(wb.verify_fixed_radix_bound(0, 1, 0, 1) is True, "Zero fixed-radix boundary failed")
    check(wb.verify_fixed_radix_bound(65536, 65536, 1, 1) is True, "Exact equality fixed-radix failed")
    check(wb.verify_fixed_radix_bound(65537, 65536, 1, 1) is False, "Exceed fixed-radix failed")


def test_group_4_r5_adversarial_refusal_controls() -> None:
    # --- Core scalar / vector / matrix / Schur / Krein guards ---
    expect_code("BAD_SCALAR", lambda: wb.to_q(True))  # type: ignore[arg-type]
    expect_code("BAD_SCALAR", lambda: wb.to_q(1.5))  # type: ignore[arg-type]
    expect_code("EMPTY_VEC", lambda: wb.qvec([]))
    expect_code("EMPTY_MAT", lambda: wb.qmat([]))
    expect_code("EMPTY_COL", lambda: wb.qmat([[]]))
    expect_code("RAGGED_MAT", lambda: wb.qmat([[1, 2], [3]]))
    expect_code("BAD_DIM", lambda: wb.qeye(0))
    expect_code("BAD_DIM", lambda: wb.qeye(True))  # type: ignore[arg-type]
    expect_code("DOT_SHAPE", lambda: wb.qdot(wb.qvec([1]), wb.qvec([1, 2])))
    expect_code("MATVEC_SHAPE", lambda: wb.qmatvec(wb.qeye(2), wb.qvec([1])))
    expect_code("MUL_SHAPE", lambda: wb.qmul(wb.qeye(2), wb.qeye(3)))
    expect_code("ADD_SHAPE", lambda: wb.qadd(wb.qeye(2), wb.qeye(3)))
    expect_code("SUB_SHAPE", lambda: wb.qsub(wb.qeye(2), wb.qeye(3)))

    rect_top_sym = wb.qmat([[1, 2, 3], [2, 5, 6]])
    check(wb.is_symmetric(rect_top_sym) is False, "Top-sym rectangular matrix marked symmetric")
    asym = wb.qmat([[1, 2], [0, 1]])
    expect_code("NOT_SYM", lambda: wb.op_krein_inertia(asym))
    expect_code("SOLVE_SHAPE", lambda: wb.qsolve(rect_top_sym, wb.qeye(2)))
    expect_code("SINGULAR_MAT", lambda: wb.qsolve(wb.qmat([[1, 1], [1, 1]]), wb.qeye(2)))
    expect_code("SCHUR_NOT_SYM", lambda: wb.op_schur_complement(asym, (1,)))
    expect_code("SCHUR_DUP_IDX", lambda: wb.op_schur_complement(wb.qeye(2), (0, 0)))
    expect_code("SCHUR_BAD_IDX", lambda: wb.op_schur_complement(wb.qeye(2), (-1,)))
    expect_code("SCHUR_BAD_IDX", lambda: wb.op_schur_complement(wb.qeye(2), (2,)))
    expect_code("SCHUR_EMPTY_KEEP", lambda: wb.op_schur_complement(wb.qeye(2), (0, 1)))

    # --- Pillar 1 hardened multi-bank state-isolation guards (closing WD-SB-01..04) ---
    expect_code("BAD_BANK_NAME", lambda: wb.HardenedStateBankStatus(bank="bogus", tainted=False))
    expect_code("BAD_TAINT_TYPE", lambda: wb.HardenedStateBankStatus(bank=wb.STATE_BANK_KV, tainted=0))  # type: ignore[arg-type]
    expect_code("BAD_TOKENS_COUNT", lambda: wb.HardenedStateBankStatus(bank=wb.STATE_BANK_KV, tainted=False, tokens_or_layers=-1))
    expect_code("BAD_TOKENS_COUNT", lambda: wb.HardenedStateBankStatus(bank=wb.STATE_BANK_KV, tainted=False, tokens_or_layers=False))  # type: ignore[arg-type]
    expect_code("BAD_LORA_ID", lambda: wb.HardenedStateBankStatus(bank=wb.STATE_BANK_KV, tainted=False, active_lora_ids=(-1,)))
    expect_code("BAD_CAP_TAG", lambda: wb.HardenedStateBankStatus(bank=wb.STATE_BANK_KV, tainted=False, capability_tag=-1))
    expect_code("BAD_CAP_TAG", lambda: wb.HardenedStateBankStatus(bank=wb.STATE_BANK_KV, tainted=False, capability_tag=256))

    expect_code("BAD_SLOT_ID", lambda: wb.HardenedBankFlushReceipt(slot_id=-1, banks_requested=(wb.STATE_BANK_KV,), banks_confirmed=(wb.STATE_BANK_KV,), zone_manifest_id=None, verified_clean=True))
    expect_code("EMPTY_BANKS_REQ", lambda: wb.HardenedBankFlushReceipt(slot_id=0, banks_requested=(), banks_confirmed=(), zone_manifest_id=None, verified_clean=False))
    expect_code("BAD_REQ_BANK", lambda: wb.HardenedBankFlushReceipt(slot_id=0, banks_requested=("bogus",), banks_confirmed=(), zone_manifest_id=None, verified_clean=False))
    expect_code("BAD_CONF_BANK", lambda: wb.HardenedBankFlushReceipt(slot_id=0, banks_requested=(wb.STATE_BANK_KV,), banks_confirmed=("bogus",), zone_manifest_id=None, verified_clean=False))
    expect_code("BAD_CLEAN_FLAG", lambda: wb.HardenedBankFlushReceipt(slot_id=0, banks_requested=(wb.STATE_BANK_KV,), banks_confirmed=(wb.STATE_BANK_KV,), zone_manifest_id=None, verified_clean=1))  # type: ignore[arg-type]
    expect_code("CLEAN_WITHOUT_CONFIRMATION", lambda: wb.HardenedBankFlushReceipt(slot_id=0, banks_requested=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), banks_confirmed=(wb.STATE_BANK_KV,), zone_manifest_id=None, verified_clean=True))

    expect_code("BAD_LAT_FLAG", lambda: wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=1, lattice_layers=1, lattice_width=1))  # type: ignore[arg-type]
    expect_code("BAD_LAT_LAYERS", lambda: wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=True, lattice_layers=-1, lattice_width=1))
    expect_code("BAD_LAT_WIDTH", lambda: wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=True, lattice_layers=1, lattice_width=-1))
    expect_code("ZERO_LATTICE_DIM", lambda: wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=True, lattice_layers=24, lattice_width=0))
    expect_code("ZERO_LATTICE_DIM", lambda: wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=True, lattice_layers=0, lattice_width=256))
    expect_code("NONZERO_DISABLED_LATTICE", lambda: wb.validate_lattice_checkpoint_dims(has_horizontal_lattice=False, lattice_layers=1, lattice_width=0))

    # verify_multibank_flush_strict refusal controls
    good_post = [{"id": 0, "is_processing": False, "state_banks": {
        wb.STATE_BANK_KV: {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0},
        wb.STATE_BANK_SSM: {"tainted": False, "active_lora_ids": [], "tokens_or_layers": 0},
    }}]
    good_resp = {0: {"banks_flushed": [wb.STATE_BANK_KV, wb.STATE_BANK_SSM]}}
    expect_code("EMPTY_REQ_BANKS", lambda: wb.verify_multibank_flush_strict(required_banks=(), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=good_post))
    expect_code("BAD_REQ_BANK", lambda: wb.verify_multibank_flush_strict(required_banks=("bad",), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=good_post))
    expect_code("EMPTY_PRE_SLOTS", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV,), pre_slot_ids=(), erase_responses=good_resp, post_slots=good_post))
    expect_code("BAD_SLOT_ID", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV,), pre_slot_ids=(-1,), erase_responses=good_resp, post_slots=good_post))
    expect_code("MISSING_ERASE_RESP", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV,), pre_slot_ids=(0,), erase_responses={}, post_slots=good_post))
    expect_code("BAD_BANKS_FLUSHED", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV,), pre_slot_ids=(0,), erase_responses={0: {}}, post_slots=good_post))
    expect_code("MISSING_CONFIRMED_BANKS", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), pre_slot_ids=(0,), erase_responses={0: {"banks_flushed": [wb.STATE_BANK_KV]}}, post_slots=good_post))
    expect_code("BAD_POST_SLOT_ID", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=[{"id": -1}]))
    expect_code("POST_SLOT_MISSING", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=[]))
    expect_code("SLOT_STILL_PROCESSING", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=[{"id": 0, "is_processing": True, "state_banks": good_post[0]["state_banks"]}]))
    expect_code("MISSING_STATE_BANKS", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=[{"id": 0, "is_processing": False}]))
    expect_code("MISSING_BANK_STATUS", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=[{"id": 0, "is_processing": False, "state_banks": {wb.STATE_BANK_KV: {"tainted": False}}}]))
    expect_code("BAD_BANK_STATUS", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV,), pre_slot_ids=(0,), erase_responses={0: {"banks_flushed": [wb.STATE_BANK_KV]}}, post_slots=[{"id": 0, "is_processing": False, "state_banks": {wb.STATE_BANK_KV: "not_a_dict"}}]))
    expect_code("BANK_STILL_TAINTED", lambda: wb.verify_multibank_flush_strict(required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), pre_slot_ids=(0,), erase_responses=good_resp, post_slots=[{"id": 0, "is_processing": False, "state_banks": {wb.STATE_BANK_KV: {"tainted": False}, wb.STATE_BANK_SSM: {"tainted": True}}}]))

    # --- Pillar 2 & 3 simulator / Fisher / 2-bit quantizer guards ---
    dw2 = wb.qeye(2)
    expect_code("BAD_EDIT_LAYER", lambda: wb.simulate_hybrid_3layer_exact(edit_layer=1, delta_w=dw2, active_steps=(True,), has_horizontal_lattice=False))
    expect_code("BAD_DELTA_SHAPE", lambda: wb.simulate_hybrid_3layer_exact(edit_layer=2, delta_w=wb.qeye(3), active_steps=(True,), has_horizontal_lattice=False))
    expect_code("EMPTY_STEPS", lambda: wb.simulate_hybrid_3layer_exact(edit_layer=2, delta_w=dw2, active_steps=(), has_horizontal_lattice=False))

    expect_code("PROBS_SUM_NEQ_1", lambda: wb.exact_fisher_matrix_in_residual_space(wb.qvec([Fraction(1, 2), Fraction(1, 3)]), wb.qeye(2)))
    expect_code("NONPOS_PROB", lambda: wb.exact_fisher_matrix_in_residual_space(wb.qvec([Fraction(1), Fraction(0)]), wb.qeye(2)))
    expect_code("U_ROW_MISMATCH", lambda: wb.exact_fisher_matrix_in_residual_space(wb.qvec([Fraction(1, 2), Fraction(1, 2)]), wb.qeye(3)))
    expect_code("FISHER_NOT_SYM", lambda: wb.exact_quadratic_fisher_kl(wb.qvec([1, 0]), asym))
    expect_code("FISHER_VEC_SHAPE", lambda: wb.exact_quadratic_fisher_kl(wb.qvec([1]), wb.qeye(2)))

    expect_code("GROUP_SHAPE", lambda: wb.exact_2bit_weighted_group_mse(wb.qvec([1]), wb.qvec([1, 1]), scale_by_sqrt_h=False))
    expect_code("BAD_SQRT_H", lambda: wb.exact_2bit_weighted_group_mse(wb.qvec([1]), wb.qvec([0]), scale_by_sqrt_h=False))
    expect_code("ZERO_GROUP", lambda: wb.exact_2bit_weighted_group_mse(wb.qvec([0]), wb.qvec([1]), scale_by_sqrt_h=False))

    # --- Pillar 4 governed candidate & fixed-radix guards ---
    expect_code("CERT_BAD_VAL", lambda: wb.verify_fixed_radix_bound(-1, 1, 1, 1))
    expect_code("CERT_BAD_RADIX", lambda: wb.verify_fixed_radix_bound(0, 0, 1, 1))
    expect_code("CERT_BAD_LNUM", lambda: wb.verify_fixed_radix_bound(0, 1, -1, 1))
    expect_code("CERT_BAD_LDEN", lambda: wb.verify_fixed_radix_bound(0, 1, 1, 0))

    base_p = {"target_layer": "blk.31", "scale_num": 1, "scale_den": 1, "radix_scale": 65536, "frob_sq_scaled": 65536, "margin_delta": "1/1", "unrelated_fisher_kl": "0/1"}
    h_ok = wb.sha256_canonical(base_p)
    rec_ok = (wb.HardenedBankFlushReceipt(slot_id=0, banks_requested=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), banks_confirmed=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), zone_manifest_id=None, verified_clean=True),)
    rec_part = (wb.HardenedBankFlushReceipt(slot_id=0, banks_requested=(wb.STATE_BANK_KV,), banks_confirmed=(wb.STATE_BANK_KV,), zone_manifest_id=None, verified_clean=True),)

    expect_code("BAD_CAND_ID", lambda: wb.evaluate_governed_candidate(candidate_id=" ", committed_hash=h_ok, payload=base_p, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=rec_ok))
    expect_code("BAD_COMMIT_HASH", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash="short", payload=base_p, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=rec_ok))

    p_bad_sn = dict(base_p, scale_num=-1)
    expect_code("BAD_SCALE_NUM", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash=wb.sha256_canonical(p_bad_sn), payload=p_bad_sn, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=rec_ok))
    p_bad_sd = dict(base_p, scale_den=0)
    expect_code("BAD_SCALE_DEN", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash=wb.sha256_canonical(p_bad_sd), payload=p_bad_sd, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=rec_ok))
    p_big_frob = dict(base_p, frob_sq_scaled=200000)
    expect_code("ERR_CERT_FROB_EXCEEDED", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash=wb.sha256_canonical(p_big_frob), payload=p_big_frob, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=rec_ok))
    p_neg_kl = dict(base_p, unrelated_fisher_kl="-1/10")
    expect_code("BAD_KL", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash=wb.sha256_canonical(p_neg_kl), payload=p_neg_kl, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=rec_ok))
    p_base_drift = dict(base_p, scale_num=0, margin_delta="1/10")
    expect_code("ERR_BASE_CONTROL_DRIFT", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash=wb.sha256_canonical(p_base_drift), payload=p_base_drift, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=rec_ok))
    expect_code("ERR_MISSING_FLUSH_RECEIPT", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash=h_ok, payload=base_p, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV,), flush_receipts=()))
    expect_code("ERR_MULTIBANK_FLUSH_INCOMPLETE", lambda: wb.evaluate_governed_candidate(candidate_id="c", committed_hash=h_ok, payload=base_p, allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4), max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM), flush_receipts=rec_part))

    # Boundary equality on margin_delta == min_margin_gain AND unrelated_kl == max_unrelated_kl -> PROMOTE!
    p_eq = dict(base_p, margin_delta="1/4", unrelated_fisher_kl="1/2")
    res_eq = wb.evaluate_governed_candidate(
        candidate_id="c_eq", committed_hash=wb.sha256_canonical(p_eq), payload=p_eq,
        allowed_target_layer="blk.31", frob_limit=(2, 1), min_margin_gain=Fraction(1, 4),
        max_unrelated_kl=Fraction(1, 2), required_banks=(wb.STATE_BANK_KV, wb.STATE_BANK_SSM),
        flush_receipts=rec_ok,
    )
    check(res_eq["verdict"] == "PROMOTE", "Boundary equality candidate must promote")

    # Missing clone, wrong-SHA/dirty git repo, wrong-SHA HTML, & malformed HTML refusal controls
    miss = HERE / "_nonexistent_path_r5"
    check(wb.run_live_warp_drive_bug_reproducers(miss)["available"] is False, "Missing warp repo fallback failed")
    check(wb.parse_qwen35_4b_empirical_census(miss)["available"] is False, "Missing 4b.html fallback failed")

    import hashlib
    import subprocess
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        # 1. Temp git repo with non-matching SHA kills M070
        git_dir = tmp / "fake_repo"
        git_dir.mkdir()
        subprocess.check_call(["git", "-C", str(git_dir), "init", "-q"])
        subprocess.check_call(
            ["git", "-C", str(git_dir), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "--allow-empty", "-q", "-m", "init"]
        )
        r_sha = wb.run_live_warp_drive_bug_reproducers(git_dir)
        check(r_sha["available"] is False and r_sha["mode"] == "sha_or_dirty_mismatch", f"Bad git SHA guard failed: {r_sha}")

        # 2. Temp bogus HTML kills M076/M077 (wrong SHA) and M078 (matching SHA, missing const DATA)
        bad_html = tmp / "bad.html"
        bad_bytes = b"<html><body>no data here</body></html>"
        bad_html.write_bytes(bad_bytes)
        bad_sha = hashlib.sha256(bad_bytes).hexdigest()
        r_h_sha = wb.parse_qwen35_4b_empirical_census(bad_html)
        check(r_h_sha["available"] is False and r_h_sha["mode"] == "sha_mismatch", f"HTML SHA guard failed: {r_h_sha}")
        r_h_parse = wb.parse_qwen35_4b_empirical_census(bad_html, expected_sha=bad_sha)
        check(r_h_parse["available"] is False and r_h_parse["mode"] == "parse_failed", f"HTML parse guard failed: {r_h_parse}")


def main() -> int:
    groups = (
        test_group_1_end_to_end_zero_float_certificate,
        test_group_2_exact_invariance_and_algebraic_identities,
        test_group_3_unseen_instances_and_boundary_accepts,
        test_group_4_r5_adversarial_refusal_controls,
    )
    for fn in groups:
        fn()
    print(f"ROUND6_ARM4_WARP_WEIGHT_ITERATION_R5_OK: {len(groups)}/{len(groups)} test groups passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
