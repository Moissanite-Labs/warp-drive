"""Tests for the lane-7 independent verifier.

All fixtures here are synthetic and built by the tests themselves, except
the golden fixture test, which reads the generated receipt + receipt log
in tests/fixtures/ and the frozen contract from LANE7_EXP_DIR (skipped
when the variable is not set). Nothing in this package imports
warp_modeld: see test_no_controller_import.
"""

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from verify import (  # noqa: E402
    check_cerebras_bounds,
    check_config_digests,
    check_contract,
    check_leakage,
    check_margins,
    check_policy,
    check_receipt,
    check_receipt_log,
    sha256_canonical,
)

HERE = Path(__file__).resolve().parent
PKG = HERE.parent


def dump(path: Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n")


def sha_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def make_exp_dir(tmp: Path) -> Path:
    exp = tmp / "exp"
    suites = {
        "task": {"suite": "task", "n_cases": 2, "cases": [
            {"positive_tokens": [1], "negative_tokens": [2]},
            {"positive_tokens": [3], "negative_tokens": [4]}]},
        "retention_iid": {"suite": "retention_iid", "n_cases": 1, "cases": [{}]},
        "retention_shifted": {"suite": "retention_shifted", "n_cases": 1, "cases": [{}]},
        "safety_canaries": {"suite": "safety_canaries", "n_canaries": 1,
                            "canary_ids": ["c1"]},
    }
    for name, obj in suites.items():
        dump(exp / "suites" / ("%s.json" % name), obj)
    dump(exp / "thresholds.json", {
        "thresholds_version": "0.1.0", "repair_budget_max_rounds": 3,
        "adapter_application_margin": {"threshold": -0.37},
        "task": {"top1_min": 0.56, "contested_fix_min_fraction": 0.1,
                 "break_max_fraction": 0.08},
        "retention": {"iid_kl_max_mean": 0.25, "iid_top1_agreement_min": 0.95,
                      "shifted_kl_max_mean": 0.4},
        "safety": {"canary_fail_max": 0},
    })
    dump(exp / "controls.json", {
        "controls_version": "0.1.0",
        "unchanged_base": {"expected": {
            "task_top1": "within 0.02 of the published base value 0.518 on the 112 held-out states",
            "verdict": "PASS"}},
        "deliberately_regressed": {"expected": {
            "task_top1": "below the base value 0.518", "verdict": "REJECT"}},
    })
    dump(exp / "receipt.schema.json", {
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "required": ["receipt_schema_version", "manifest_sha256", "suite_sha256",
                     "candidate", "seeds", "environment", "timings_ms",
                     "measurements", "verdict"],
        "properties": {
            "receipt_schema_version": {"type": "string"},
            "manifest_sha256": {"type": "string"},
            "suite_sha256": {"type": "string"},
            "candidate": {"type": "object", "required": ["candidate_id", "config",
                         "adapter_sha256", "hash_recorded_before_evaluation"],
                "properties": {
                    "candidate_id": {"type": "string"},
                    "config": {"type": "object", "properties": {
                        "rank": {"const": 8}, "target_layer": {"const": 31},
                        "target_tensor": {"const": "ffn_up"},
                        "eta": {"type": "number"}, "lora_scale": {"type": "number"}},
                        "required": ["rank", "target_layer", "target_tensor",
                                     "eta", "lora_scale"]},
                    "adapter_sha256": {"type": "string"},
                    "hash_recorded_before_evaluation": {"const": True}}},
            "environment": {"type": "object", "properties": {
                "llama_cpp_build": {"const": "b12549"},
                "llama_cpp_commit": {"const": "8af68d486"}}},
            "verdict": {"enum": ["ACCEPT", "REJECT", "CONTROL_PASS"]},
            "repair_round": {"maximum": 3, "type": "integer"},
            "measurements": {"type": "object", "required": ["task", "margin",
                             "retention_iid", "retention_shifted", "safety", "rollback"],
                "properties": {
                    "task": {"type": "object"},
                    "margin": {"type": "object", "properties": {
                        "threshold": {"const": -0.37}}},
                    "retention_iid": {"type": "object"},
                    "retention_shifted": {"type": "object"},
                    "safety": {"type": "object"},
                    "rollback": {"type": "object"}}},
        },
    })
    dump(exp / "audit" / "split_leakage.json", {"held_out_states": 2, "training_states": 1,
                                                "reusing_train_pair": 1,
                                                "distinct_held_out_pairs": 2,
                                                "distinct_training_pairs": 1,
                                                "by_family": {"A": {"held_out_states": 2,
                                                                    "reusing_train_pair": 1}}})
    dump(exp / "scripts" / "generate_suites.py", "# fake\n")
    digests = {}
    for key, rel in [("task", "suites/task.json"), ("retention_iid", "suites/retention_iid.json"),
                     ("retention_shifted", "suites/retention_shifted.json"),
                     ("safety_canaries", "suites/safety_canaries.json"),
                     ("thresholds", "thresholds.json"), ("controls", "controls.json"),
                     ("receipt_schema", "receipt.schema.json"),
                     ("audit_split_leakage", "audit/split_leakage.json"),
                     ("generate_suites_script", "scripts/generate_suites.py")]:
        digests[key] = sha_bytes((exp / rel).read_bytes())
    digests["combined_suites"] = sha_bytes(b"".join(
        (exp / ("suites/%s.json" % n)).read_bytes()
        for n in ("task", "retention_iid", "retention_shifted", "safety_canaries")))
    dump(exp / "manifest.json", {
        "manifest_version": "0.1.0", "repair_budget_max_rounds": 3,
        "experiment": "demo-test",
        "allowed_candidate_knobs": {"rank": 8, "eta_range": [0.002, 0.02]},
        "last_layer_target": {"layer": 31},
        "suites": {"task": {"cases": 2}, "retention_iid": {"cases": 1},
                   "retention_shifted": {"cases": 1}, "safety_canaries": {"cases": 1}},
        "digests": digests,
    })
    return exp


def passing_measurements():
    return {"task": {"top1": 0.58, "contested_fix_fraction": 0.15, "break_fraction": 0.03},
            "margin": {"threshold": -0.37, "adapter_requests": 2, "baseline_requests": 2,
                       "margins_adapter": [-0.1, 0.0], "margins_baseline": [-1.0, -0.9]},
            "retention_iid": {"mean_kl": 0.10, "top1_agreement": 0.97},
            "retention_shifted": {"mean_kl": 0.20},
            "safety": {"canaries_run": 1, "failures": []},
            "rollback": {"exact_matches": 14, "sequences": 14, "max_logit_diff": 0.0}}


def passing_receipt(exp: Path):
    manifest_sha = sha_bytes((exp / "manifest.json").read_bytes())
    combined = sha_bytes(b"".join((exp / ("suites/%s.json" % n)).read_bytes()
                                  for n in ("task", "retention_iid",
                                            "retention_shifted", "safety_canaries")))
    return {"receipt_schema_version": "0.1.0", "manifest_sha256": manifest_sha,
            "suite_sha256": combined,
            "candidate": {"candidate_id": "cand-test",
                          "config": {"rank": 8, "target_layer": 31,
                                     "target_tensor": "ffn_up", "eta": 0.01,
                                     "lora_scale": 1.0},
                          "adapter_sha256": "a" * 64,
                          "hash_recorded_before_evaluation": True},
            "seeds": {"suite_generation": "deterministic",
                      "noise_sample": "sorted_first_64_no_rng"},
            "environment": {"gpu": "test", "llama_cpp_build": "b12549",
                            "llama_cpp_commit": "8af68d486", "os": "test",
                            "vram_mib": None},
            "timings_ms": {"compile": 1.0, "evaluate": 2.0, "deploy": 3.0},
            "measurements": passing_measurements(),
            "verdict": "ACCEPT", "repair_round": 0}


def write_log(path: Path, entries):
    prev = "0" * 64
    lines = []
    for i, fields in enumerate(entries, start=1):
        entry = {"seq": i, "ts_utc": "2026-11-21T00:00:00+00:00",
                 "event": fields.pop("event"), "prev_sha256": prev}
        entry.update(fields)
        entry["entry_sha256"] = sha256_canonical(entry)
        lines.append(json.dumps(entry, sort_keys=True))
        prev = entry["entry_sha256"]
    path.write_text("\n".join(lines) + "\n")
    return lines


# --- contract ---------------------------------------------------------------


def test_contract_verifies(tmp_path):
    exp = make_exp_dir(tmp_path)
    assert check_contract(exp)[0]["verdict"] == "VERIFIED"


def test_contract_falsifies_tampered_suite(tmp_path):
    exp = make_exp_dir(tmp_path)
    (exp / "suites" / "task.json").write_text('{"tampered": true}\n')
    out = check_contract(exp)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "task" in out["evidence"]


# --- leakage ----------------------------------------------------------------


def test_leakage_recomputes(tmp_path):
    exp = make_exp_dir(tmp_path)
    harvest = tmp_path / "harvest.json"
    mlm = tmp_path / "ml.json"
    dump(harvest, {"states": [
        {"id": "H1", "family": "A", "pos_toks": [1], "neg_toks": [2]},
        {"id": "H2", "family": "A", "pos_toks": [3], "neg_toks": [4]},
        {"id": "T1", "family": "A", "pos_toks": [1], "neg_toks": [2]}]})
    dump(mlm, {"held_out_ids": ["H1", "H2"]})
    out = check_leakage(exp, harvest, mlm)[0]
    assert out["verdict"] == "VERIFIED"
    assert "1/2" in out["evidence"]


def test_leakage_falsifies_wrong_audit(tmp_path):
    exp = make_exp_dir(tmp_path)
    (exp / "audit" / "split_leakage.json").write_text(
        json.dumps({"held_out_states": 2, "training_states": 1, "reusing_train_pair": 2,
                    "distinct_held_out_pairs": 2, "distinct_training_pairs": 1,
                    "by_family": {"A": {"held_out_states": 2, "reusing_train_pair": 2}}}) + "\n")
    harvest = tmp_path / "harvest.json"
    mlm = tmp_path / "ml.json"
    dump(harvest, {"states": [
        {"id": "H1", "family": "A", "pos_toks": [1], "neg_toks": [2]},
        {"id": "H2", "family": "A", "pos_toks": [3], "neg_toks": [4]},
        {"id": "T1", "family": "A", "pos_toks": [1], "neg_toks": [2]}]})
    dump(mlm, {"held_out_ids": ["H1", "H2"]})
    assert check_leakage(exp, harvest, mlm)[0]["verdict"] == "FALSIFIED"


# --- margins ----------------------------------------------------------------


def test_margins_recompute(tmp_path):
    pilot = tmp_path / "pilot.json"
    dump(pilot, {"decision_threshold_margin_midpoint": -0.37,
                 "rounds": [{"results": [
                     {"requested": "triple", "margin": -0.1},
                     {"requested": "triple", "margin": 0.1},
                     {"requested": "w0", "margin": -0.9},
                     {"requested": "w0", "margin": -0.8}]}],
                 "summary": {"triple_requests": 2, "w0_requests": 2,
                             "triple_margin_min": -0.1, "w0_margin_max": -0.8}})
    out = check_margins(pilot)[0]
    assert out["verdict"] == "VERIFIED"
    assert "2/2" in out["evidence"]


def test_margins_falsify_crossing_baseline(tmp_path):
    pilot = tmp_path / "pilot.json"
    dump(pilot, {"decision_threshold_margin_midpoint": -0.37,
                 "rounds": [{"results": [
                     {"requested": "triple", "margin": 0.1},
                     {"requested": "w0", "margin": -0.2}]}],
                 "summary": {"triple_requests": 1, "w0_requests": 1,
                             "triple_margin_min": 0.1, "w0_margin_max": -0.2}})
    assert check_margins(pilot)[0]["verdict"] == "FALSIFIED"


# --- receipt ----------------------------------------------------------------


def test_receipt_verifies(tmp_path):
    exp = make_exp_dir(tmp_path)
    receipt = tmp_path / "receipt.json"
    dump(receipt, passing_receipt(exp))
    assert check_receipt(receipt, exp)[0]["verdict"] == "VERIFIED"


def test_receipt_falsifies_wrong_build(tmp_path):
    exp = make_exp_dir(tmp_path)
    bad = passing_receipt(exp)
    bad["environment"]["llama_cpp_build"] = "b99999"
    receipt = tmp_path / "receipt.json"
    dump(receipt, bad)
    out = check_receipt(receipt, exp)[0]
    assert out["verdict"] == "FALSIFIED"


def test_receipt_falsifies_drifted_manifest_digest(tmp_path):
    exp = make_exp_dir(tmp_path)
    bad = passing_receipt(exp)
    bad["manifest_sha256"] = "0" * 64
    receipt = tmp_path / "receipt.json"
    dump(receipt, bad)
    assert check_receipt(receipt, exp)[0]["verdict"] == "FALSIFIED"


# --- receipt log -------------------------------------------------------------


def test_receipt_log_verifies_and_detects_tamper(tmp_path):
    log = tmp_path / "log.jsonl"
    write_log(log, [{"event": "candidate_proposed", "candidate_id": "c1"},
                    {"event": "verdict", "verdict": "ACCEPT"}])
    assert check_receipt_log(log)[0]["verdict"] == "VERIFIED"
    lines = log.read_text().splitlines()
    lines[1] = lines[1].replace("ACCEPT", "REJECT")
    log.write_text("\n".join(lines) + "\n")
    assert check_receipt_log(log)[0]["verdict"] == "FALSIFIED"


def test_receipt_log_rejects_nan(tmp_path):
    log = tmp_path / "log.jsonl"
    write_log(log, [{"event": "evaluated", "max_logit_diff": 0.0}])
    lines = log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["max_logit_diff"] = float("nan")
    body = {k: v for k, v in entry.items() if k != "entry_sha256"}
    entry["entry_sha256"] = sha256_canonical(body)
    log.write_text(json.dumps(entry, sort_keys=True) + "\n")
    out = check_receipt_log(log)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "strict JSON" in out["evidence"]


def test_receipt_log_empty_is_partial(tmp_path):
    log = tmp_path / "log.jsonl"
    log.write_text("")
    assert check_receipt_log(log)[0]["verdict"] == "PARTIAL"


def test_config_digests_recompute(tmp_path):
    log = tmp_path / "log.jsonl"
    config = {"rank": 8, "eta": 0.01, "quant": "bf16"}
    write_log(log, [{"event": "candidate_proposed", "candidate_id": "c1",
                     "config": config, "config_digest": sha256_canonical(config)}])
    assert check_config_digests(log)[0]["verdict"] == "VERIFIED"
    lines = log.read_text().splitlines()
    entry = json.loads(lines[0])
    entry["config"]["eta"] = 0.02
    log.write_text(json.dumps(entry, sort_keys=True) + "\n")
    assert check_config_digests(log)[0]["verdict"] == "FALSIFIED"


def test_config_digests_verify_binding_before_evaluation(tmp_path):
    log = tmp_path / "log.jsonl"
    config = {"rank": 8, "eta": 0.01, "quant": "bf16"}
    digest = sha256_canonical(config)
    write_log(log, [{"event": "candidate_proposed", "candidate_id": "c1",
                     "config": config, "config_digest": digest},
                    {"event": "candidate_digest_recorded", "candidate_id": "c1",
                     "config_digest": digest},
                    {"event": "evaluated", "candidate_id": "c1"}])
    out = check_config_digests(log)[0]
    assert out["verdict"] == "VERIFIED"
    assert "before its candidate was evaluated" in out["evidence"]


def test_config_digests_falsify_digest_recorded_after_evaluation(tmp_path):
    # Orda's witness: proposed -> evaluated -> digest recorded, with
    # sequence numbers, links, and hashes all recomputing.
    log = tmp_path / "log.jsonl"
    config = {"rank": 8, "eta": 0.01, "quant": "bf16"}
    digest = sha256_canonical(config)
    write_log(log, [{"event": "candidate_proposed", "candidate_id": "c1",
                     "config": config, "config_digest": digest},
                    {"event": "evaluated", "candidate_id": "c1"},
                    {"event": "candidate_digest_recorded", "candidate_id": "c1",
                     "config_digest": digest}])
    out = check_config_digests(log)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "after evaluation" in out["evidence"]


def test_config_digests_unverified_without_evaluated_event(tmp_path):
    log = tmp_path / "log.jsonl"
    config = {"rank": 8, "eta": 0.01, "quant": "bf16"}
    digest = sha256_canonical(config)
    write_log(log, [{"event": "candidate_proposed", "candidate_id": "c1",
                     "config": config, "config_digest": digest},
                    {"event": "candidate_digest_recorded", "candidate_id": "c1",
                     "config_digest": digest}])
    out = check_config_digests(log)[0]
    assert out["verdict"] == "UNVERIFIED"
    assert "before-evaluation binding is not established" in out["evidence"]


def _digest_log_entries(config, digest):
    return [{"event": "candidate_proposed", "candidate_id": "A",
             "config": config, "config_digest": digest},
            {"event": "candidate_digest_recorded", "candidate_id": "A",
             "config_digest": digest},
            {"event": "evaluated", "candidate_id": "A"}]


def test_config_digests_falsify_evaluated_candidate_with_no_recorded_digest(tmp_path):
    # Valid chain: proposed(A), recorded(A), evaluated(A), proposed(B), evaluated(B).
    # B is evaluated with no recorded digest and must not pass.
    log = tmp_path / "log.jsonl"
    config_a = {"rank": 8, "eta": 0.01}
    config_b = {"rank": 8, "eta": 0.02}
    entries = _digest_log_entries(config_a, sha256_canonical(config_a))
    write_log(log, [dict(e) for e in entries])
    assert check_config_digests(log)[0]["verdict"] == "VERIFIED"
    write_log(log, [dict(e) for e in entries]
              + [{"event": "candidate_proposed", "candidate_id": "B",
                  "config": config_b, "config_digest": sha256_canonical(config_b)},
                 {"event": "evaluated", "candidate_id": "B"}])
    out = check_config_digests(log)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "B" in out["evidence"] and "no recorded digest" in out["evidence"]


def test_config_digests_falsify_evaluated_candidate_never_proposed(tmp_path):
    log = tmp_path / "log.jsonl"
    config = {"rank": 8, "eta": 0.01}
    entries = _digest_log_entries(config, sha256_canonical(config))
    write_log(log, [dict(e) for e in entries] + [{"event": "evaluated", "candidate_id": "ghost"}])
    out = check_config_digests(log)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "ghost" in out["evidence"]


def test_config_digests_falsify_digest_that_differs_from_proposal(tmp_path):
    # Rechained so only the digest comparison can reject it.
    log = tmp_path / "log.jsonl"
    config = {"rank": 8, "eta": 0.01}
    write_log(log, [{"event": "candidate_proposed", "candidate_id": "A",
                     "config": config, "config_digest": sha256_canonical(config)},
                    {"event": "candidate_digest_recorded", "candidate_id": "A",
                     "config_digest": sha256_canonical({"rank": 16})},
                    {"event": "evaluated", "candidate_id": "A"}])
    assert check_receipt_log(log)[0]["verdict"] == "VERIFIED"
    out = check_config_digests(log)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "differs from the proposed digest" in out["evidence"]


def test_config_digests_reject_non_strict_json(tmp_path):
    log = tmp_path / "log.jsonl"
    config = {"rank": 8, "eta": 0.01}
    digest = sha256_canonical(config)
    lines = write_log(log, _digest_log_entries(config, digest))
    assert check_config_digests(log)[0]["verdict"] == "VERIFIED"
    # NaN placed in an unrelated field of the evaluated entry, then rechained.
    entry = json.loads(lines[2])
    entry["max_logit_diff"] = float("nan")
    body = {k: v for k, v in entry.items() if k != "entry_sha256"}
    entry["entry_sha256"] = sha256_canonical({k: (None if v != v else v)
                                              for k, v in body.items()})
    log.write_text("\n".join(lines[:2] + [json.dumps(entry, sort_keys=True)]) + "\n")
    out = check_config_digests(log)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "strict JSON" in out["evidence"]


# --- cerebras bounds ----------------------------------------------------------


def test_cerebras_bounds_match_and_mismatch(tmp_path):
    exp = make_exp_dir(tmp_path)
    good = tmp_path / "good.json"
    dump(good, {"properties": {"rank": {"enum": [8]},
                                "target_layer": {"const": 31},
                                "eta": {"type": "number"},
                                "lambda": {"type": ["number", "string"]},
                                "lora_scale": {"type": "number"},
                                "quantization": {"enum": ["bf16", "f16"]}}})
    assert check_cerebras_bounds(good, exp)[0]["verdict"] == "VERIFIED"
    bad = tmp_path / "bad.json"
    dump(bad, {"properties": {"rank": {"enum": [4, 8, 16, 32]},
                              "target_layer": {"const": "last"},
                              "strength": {"type": "number"},
                              "quantization": {"enum": ["q8_0", "q4_0", "bf16"]}}})
    out = check_cerebras_bounds(bad, exp)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "rank" in out["evidence"]


# --- policy ------------------------------------------------------------------


def test_policy_accepts_and_rejects(tmp_path):
    exp = make_exp_dir(tmp_path)
    m = tmp_path / "m.json"
    dump(m, passing_receipt(exp))
    out = check_policy(m, exp)[0]
    assert out["verdict"] == "VERIFIED"
    assert "ACCEPT" in out["evidence"]
    bad = passing_receipt(exp)
    bad["measurements"]["task"]["top1"] = 0.40
    bad["verdict"] = "ACCEPT"
    dump(m, bad)
    out = check_policy(m, exp)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "REJECT" in out["evidence"]


def test_policy_base_and_regressed_controls(tmp_path):
    exp = make_exp_dir(tmp_path)
    m = tmp_path / "m.json"
    base = passing_receipt(exp)
    base["candidate"]["candidate_id"] = "base-control"
    base["candidate"]["config"]["control_id"] = "base-control"
    base["measurements"]["task"]["top1"] = 0.518
    base["verdict"] = "CONTROL_PASS"
    dump(m, base)
    assert check_policy(m, exp)[0]["verdict"] == "VERIFIED"
    reg = passing_receipt(exp)
    reg["candidate"]["candidate_id"] = "regressed-control"
    reg["candidate"]["config"]["control_id"] = "regressed-control"
    reg["measurements"]["task"]["top1"] = 0.40
    reg["verdict"] = "REJECT"
    dump(m, reg)
    assert check_policy(m, exp)[0]["verdict"] == "VERIFIED"


def test_policy_fails_closed_on_empty_margin_lists(tmp_path):
    exp = make_exp_dir(tmp_path)
    m = tmp_path / "m.json"
    dump(m, passing_receipt(exp))
    assert check_policy(m, exp)[0]["verdict"] == "VERIFIED"
    for key, gate in (("margins_adapter", "margin_adapter"),
                      ("margins_baseline", "margin_baseline")):
        bad = passing_receipt(exp)
        bad["measurements"]["margin"][key] = []
        bad["verdict"] = "ACCEPT"
        dump(m, bad)
        out = check_policy(m, exp)[0]
        assert out["verdict"] == "FALSIFIED", key
        assert gate in out["evidence"], key


def test_policy_fails_closed_when_no_canaries_ran(tmp_path):
    exp = make_exp_dir(tmp_path)
    m = tmp_path / "m.json"
    bad = passing_receipt(exp)
    bad["measurements"]["safety"] = {"canaries_run": 0, "failures": []}
    bad["verdict"] = "ACCEPT"
    dump(m, bad)
    out = check_policy(m, exp)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "safety_canaries" in out["evidence"]


def test_policy_fails_closed_when_canaries_run_misses_the_frozen_count(tmp_path):
    exp = make_exp_dir(tmp_path)
    dump(exp / "suites" / "safety_canaries.json",
         {"suite": "safety_canaries", "n_canaries": 3, "canary_ids": ["c1", "c2", "c3"]})
    m = tmp_path / "m.json"
    short = passing_receipt(exp)
    short["measurements"]["safety"] = {"canaries_run": 2, "failures": []}
    dump(m, short)
    out = check_policy(m, exp)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "safety_canaries" in out["evidence"]
    full = passing_receipt(exp)
    full["measurements"]["safety"] = {"canaries_run": 3, "failures": []}
    dump(m, full)
    assert check_policy(m, exp)[0]["verdict"] == "VERIFIED"


def test_policy_is_unverified_without_the_frozen_canary_list(tmp_path):
    exp = make_exp_dir(tmp_path)
    (exp / "suites" / "safety_canaries.json").write_text('{"suite": "safety_canaries"}\n')
    m = tmp_path / "m.json"
    dump(m, passing_receipt(exp))
    assert check_policy(m, exp)[0]["verdict"] == "UNVERIFIED"


# --- independence ------------------------------------------------------------


def test_no_controller_import():
    import re
    pattern = re.compile(
        r"^\s*(from\s+warp_modeld|import\s+warp_modeld"
        r"|from\s+experiment\s+import|import\s+experiment)\b", re.MULTILINE)
    for path in sorted(PKG.rglob("*.py")):
        if "tests" in path.parts:
            continue
        text = path.read_text(encoding="utf-8")
        assert not pattern.search(text), path


def test_cli_runs_without_controller(tmp_path):
    exp = make_exp_dir(tmp_path)
    env = dict(os.environ)
    env["PYTHONPATH"] = ""
    proc = subprocess.run(
        [sys.executable, str(PKG / "verify.py"), "contract", "--exp-dir", str(exp)],
        capture_output=True, text=True, env=env, cwd=str(tmp_path))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["verdict"] == "VERIFIED"


# --- golden fixtures ----------------------------------------------------------


@pytest.mark.skipif("LANE7_EXP_DIR" not in os.environ,
                    reason="needs the frozen contract checkout at LANE7_EXP_DIR")
def test_golden_fixtures_against_frozen_contract():
    exp = Path(os.environ["LANE7_EXP_DIR"])
    receipt = HERE / "fixtures" / "receipt.json"
    log = HERE / "fixtures" / "receipts.jsonl"
    assert check_receipt(receipt, exp)[0]["verdict"] == "VERIFIED"
    assert check_policy(receipt, exp)[0]["verdict"] == "VERIFIED"
    assert check_config_digests(log)[0]["verdict"] == "VERIFIED"
    # The fixture log is known to carry a NaN rollback placeholder in its
    # evaluated entry: the verifier must flag exactly that.
    out = check_receipt_log(log)[0]
    assert out["verdict"] == "FALSIFIED"
    assert "strict JSON" in out["evidence"]
