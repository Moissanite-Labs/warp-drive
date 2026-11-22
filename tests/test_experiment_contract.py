"""Contract tests for the frozen demo experiment (issue #4).

Mock fixtures only: these tests check parsing, digests, counts, and
verdict control flow. They are not model evidence and never touch a
checkpoint, a GPU, or a live server.
"""

import hashlib
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXP = ROOT / "experiments" / "demo-2026-11-22"


def load(path):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def sha256_file(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_manifest_pins_present():
    manifest = load(EXP / "manifest.json")
    assert manifest["manifest_version"] == "0.1.0"
    assert manifest["base_checkpoint"]["file"] == "Qwen3.5-4B-Q8_0.gguf"
    assert manifest["base_checkpoint"]["sha256"] == (
        "10cc391b403021dd11c614679d2fd92f611c3681d29e29651b717316965d61e1"
    )
    assert manifest["runtime"]["build"] == "b12549"
    assert manifest["runtime"]["commit"] == "8af68d486"
    assert manifest["compiler"]["repo"] == "siliconcordat/weft"
    assert manifest["compiler"]["commit"] == (
        "5d7eac03696c2ff07ec70308b23b86a1d4088c1e"
    )
    assert manifest["last_layer_target"]["layer"] == 31
    assert manifest["reference_adapter"]["sha256"] == (
        "5bbc37371cd5791ac5ba9acdd0bd8b90abf967142726c019dd7284add9dd87e4"
    )
    assert manifest["repair_budget_max_rounds"] == 3


def test_manifest_digests_match_files():
    manifest = load(EXP / "manifest.json")
    digests = manifest["digests"]
    mapping = {
        "audit_split_leakage": EXP / "audit" / "split_leakage.json",
        "task": EXP / "suites" / "task.json",
        "retention_iid": EXP / "suites" / "retention_iid.json",
        "retention_shifted": EXP / "suites" / "retention_shifted.json",
        "safety_canaries": EXP / "suites" / "safety_canaries.json",
        "thresholds": EXP / "thresholds.json",
        "controls": EXP / "controls.json",
        "receipt_schema": EXP / "receipt.schema.json",
        "generate_suites_script": EXP / "scripts" / "generate_suites.py",
    }
    for key, path in mapping.items():
        assert digests[key] == sha256_file(path), key
    combined = hashlib.sha256(
        b"".join(
            (EXP / "suites" / name).read_bytes()
            for name in (
                "task.json",
                "retention_iid.json",
                "retention_shifted.json",
                "safety_canaries.json",
            )
        )
    ).hexdigest()
    assert digests["combined_suites"] == combined


def test_task_suite_counts_and_families():
    task = load(EXP / "suites" / "task.json")
    assert task["n_cases"] == 112
    assert len(task["cases"]) == 112
    assert task["families"] == {"A": 32, "B": 16, "C": 32, "D": 32}
    ids = [c["case_id"] for c in task["cases"]]
    assert len(set(ids)) == 112
    for case in task["cases"]:
        assert case["positive_tokens"]
        assert case["negative_tokens"]
        assert case["scoring"] == (
            "exact_top1_positive_token_at_decision_position"
        )


def test_retention_suite_counts():
    iid = load(EXP / "suites" / "retention_iid.json")
    assert iid["n_cases"] == 24
    assert len(iid["cases"]) == 24
    shifted = load(EXP / "suites" / "retention_shifted.json")
    assert shifted["n_cases"] == 80
    assert len(shifted["cases"]) == 80
    noise = [c for c in shifted["cases"] if "noise_id" in c]
    assert len(noise) == 64
    assert [c["noise_id"] for c in noise] == sorted(c["noise_id"] for c in noise)


def test_safety_canary_ids():
    canaries = load(EXP / "suites" / "safety_canaries.json")
    assert canaries["n_canaries"] == 9
    assert len(canaries["canary_ids"]) == 9
    assert len(set(canaries["canary_ids"])) == 9
    assert canaries["source"].startswith("schemas/verifier-canaries.json")


def test_audit_arithmetic_is_consistent():
    audit = load(EXP / "audit" / "split_leakage.json")
    assert audit["held_out_states"] == 112
    assert audit["reusing_train_pair"] == 110
    assert audit["reuse_fraction"] == round(110 / 112, 4)
    fam_total = sum(v["held_out_states"] for v in audit["by_family"].values())
    fam_reuse = sum(v["reusing_train_pair"] for v in audit["by_family"].values())
    assert fam_total == 112
    assert fam_reuse == 110
    assert audit["verdict"].startswith("LEAKED_SPLIT")


def test_thresholds_frozen_and_gates_agree():
    thresholds = load(EXP / "thresholds.json")
    assert thresholds["thresholds_version"] == "0.1.0"
    assert thresholds["adapter_application_margin"]["threshold"] == -0.37
    assert thresholds["repair_budget_max_rounds"] == 3
    assert thresholds["safety"]["canary_fail_max"] == 0
    assert thresholds["task"]["top1_min"] == 0.56
    schema = load(EXP / "receipt.schema.json")
    assert (
        schema["properties"]["measurements"]["properties"]["margin"]
        ["properties"]["threshold"]["const"]
        == -0.37
    )


def margin_gate_passes(margins, threshold=-0.37):
    return all(m > threshold for m in margins)


def test_margin_gate_on_synthetic_margins():
    # Pilot clusters: adapter -0.116 to +0.186, baseline -1.009 to -0.806.
    assert margin_gate_passes([-0.116, 0.0, 0.186])
    assert not margin_gate_passes([-0.116, -0.45, 0.186])
    assert not margin_gate_passes([-1.009, -0.806])


def test_control_verdicts_on_synthetic_measurements():
    thresholds = load(EXP / "thresholds.json")
    controls = load(EXP / "controls.json")
    base = controls["unchanged_base"]["expected"]
    assert base["verdict"] == "PASS"
    # Cross-check the two pinned files: the published base top1 in
    # thresholds.json must be the same value the base control in
    # controls.json is expected to reproduce within 0.02. No measured
    # base top1 exists in the tree yet (the base control runs live),
    # so this asserts the pinned expectation, not a measured value.
    published = float(
        re.search(r"Base measured ([0-9.]+)", thresholds["task"]["top1_basis"]).group(1)
    )
    assert published == 0.518
    assert f"{published:.3f}" in base["task_top1"] and "0.02" in base["task_top1"]
    regressed = controls["deliberately_regressed"]["expected"]
    assert regressed["verdict"] == "REJECT"
    assert regressed["task_top1"] == "below the base value 0.518"
    assert thresholds["task"]["top1_min"] > 0.518


def test_receipt_schema_shape():
    schema = load(EXP / "receipt.schema.json")
    required = set(schema["required"])
    assert {
        "receipt_schema_version",
        "manifest_sha256",
        "suite_sha256",
        "candidate",
        "seeds",
        "environment",
        "timings_ms",
        "measurements",
        "verdict",
    } <= required
    assert schema["properties"]["verdict"]["enum"] == [
        "ACCEPT",
        "REJECT",
        "CONTROL_PASS",
    ]
    assert schema["properties"]["repair_round"]["maximum"] == 3
    mock_receipt = {
        "receipt_schema_version": "0.1.0",
        "manifest_sha256": "0" * 64,
        "suite_sha256": "0" * 64,
        "candidate": {
            "candidate_id": "mock",
            "config": {
                "rank": 8,
                "target_layer": 31,
                "target_tensor": "ffn_up",
                "eta": 0.01,
                "lora_scale": 1.0,
            },
            "adapter_sha256": "1" * 64,
            "hash_recorded_before_evaluation": True,
        },
        "seeds": {"suite_generation": "deterministic"},
        "environment": {
            "gpu": "mock",
            "llama_cpp_build": "b12549",
            "llama_cpp_commit": "8af68d486",
        },
        "timings_ms": {"compile": 1, "evaluate": 1, "deploy": 1},
        "measurements": {},
        "verdict": "REJECT",
    }
    assert set(mock_receipt) >= required


def test_manifest_records_unresolved_measurements():
    manifest = load(EXP / "manifest.json")
    assert manifest["unresolved"]
    assert manifest["tokenizer"]["status"] == "UNVERIFIED"
    assert manifest["tokenizer"]["tokenizer_sha256"] is None
    assert manifest["verification_status"]["thresholds"].startswith(
        "PREREGISTERED"
    )
