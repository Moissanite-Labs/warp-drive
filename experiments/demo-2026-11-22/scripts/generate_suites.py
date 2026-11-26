#!/usr/bin/env python3
"""Generate the frozen demo suites and the split-leakage audit from published receipts.

Inputs are the two published ml-os receipt files on branch
geminus/2026-11-19-m1-runtime-findings (fetch commands in the experiment README).
No model, GPU, or checkpoint is needed: this script only rearranges published
state ids and token ids into frozen suite files, and recomputes the overlap
between the held-out split and the training split.

Deterministic: outputs are sorted, seeds are fixed, and no wall-clock or
randomness enters any file. Re-running with the same inputs must produce
byte-identical files; the digests in the manifest are checked against that.
"""

import argparse
import hashlib
import json

SUITE_VERSION = "0.1.0"
NOISE_SAMPLE_N = 64


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def dump(obj) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()


def case_from_state(state: dict) -> dict:
    return {
        "case_id": "state-%03d-%s" % (state["state"], state["id"]),
        "state_index": state["state"],
        "prompt_id": state["id"],
        "family": state["family"],
        "group": state["group"],
        "decision_position": state["pos"],
        "n_tokens": state["n_tokens"],
        "positive_tokens": state["pos_toks"],
        "negative_tokens": state["neg_toks"],
        "scoring": "exact_top1_positive_token_at_decision_position",
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--harvest-meta", required=True)
    ap.add_argument("--ml-manifest", required=True)
    ap.add_argument("--out-dir", required=True)
    args = ap.parse_args()

    with open(args.harvest_meta, encoding="utf-8") as f:
        meta = json.load(f)
    with open(args.ml_manifest, encoding="utf-8") as f:
        ml_manifest = json.load(f)

    held_ids = set(ml_manifest["held_out_ids"])
    states = meta["states"]
    held_states = [s for s in states if s["id"] in held_ids]
    train_states = [s for s in states if s["id"] not in held_ids]
    assert len(held_states) == 112, len(held_states)
    assert len(train_states) == 260, len(train_states)

    # Split-leakage audit: a held-out state leaks when its exact
    # (positive tokens, negative tokens) pair also occurs in training.
    train_pairs = {
        (tuple(s["pos_toks"]), tuple(s["neg_toks"])) for s in train_states
    }
    leaked = [
        s
        for s in held_states
        if (tuple(s["pos_toks"]), tuple(s["neg_toks"])) in train_pairs
    ]
    by_family = {}
    for family in sorted({s["family"] for s in held_states}):
        fam = [s for s in held_states if s["family"] == family]
        fam_leak = [
            s
            for s in fam
            if (tuple(s["pos_toks"]), tuple(s["neg_toks"])) in train_pairs
        ]
        by_family[family] = {
            "held_out_states": len(fam),
            "reusing_train_pair": len(fam_leak),
            "reuse_fraction": round(len(fam_leak) / len(fam), 4),
        }
    audit = {
        "audit_version": SUITE_VERSION,
        "method": (
            "A held-out state leaks when its exact "
            "(positive_tokens, negative_tokens) pair occurs in any "
            "training state. Computed from the published harvest states, "
            "not from prompt text, which is not published."
        ),
        "source_harvest_meta": "harvest_v1.meta.json",
        "source_held_out_ids": "manifest.json held_out_ids",
        "held_out_states": len(held_states),
        "training_states": len(train_states),
        "distinct_held_out_pairs": len(
            {(tuple(s["pos_toks"]), tuple(s["neg_toks"])) for s in held_states}
        ),
        "distinct_training_pairs": len(train_pairs),
        "reusing_train_pair": len(leaked),
        "reuse_fraction": round(len(leaked) / len(held_states), 4),
        "by_family": by_family,
        "verdict": (
            "LEAKED_SPLIT: the held-out split is weak. Task scores on it "
            "measure fit to seen token pairs, not generalisation. "
            "Report the audit fraction with every task score."
        ),
    }

    # Task suite: the 112 held-out states, family-separated.
    task_cases = [case_from_state(s) for s in sorted(held_states, key=lambda s: s["state"])]
    task = {
        "suite": "task",
        "suite_version": SUITE_VERSION,
        "n_cases": len(task_cases),
        "families": {
            fam: sum(1 for c in task_cases if c["family"] == fam)
            for fam in sorted({c["family"] for c in task_cases})
        },
        "scoring": "exact_top1_positive_token_at_decision_position",
        "note": (
            "Cases are token-level references to published harvest states. "
            "Prompt text is not published; execution needs the ml-os dataset "
            "and the pinned checkpoint. Do not invent prompt text."
        ),
        "cases": task_cases,
    }

    # IID retention: the 24 anchor states (same distribution as training
    # anchors, disjoint from the task states). Scored by KL vs base and
    # top-1 agreement with base, not by task accuracy.
    anchor_states = [s for s in train_states if s["group"] == "anchor"]
    assert len(anchor_states) == 24, len(anchor_states)
    retention_iid = {
        "suite": "retention_iid",
        "suite_version": SUITE_VERSION,
        "n_cases": len(anchor_states),
        "scoring": "kl_vs_base_and_top1_agreement_with_base",
        "cases": [case_from_state(s) for s in sorted(anchor_states, key=lambda s: s["state"])],
    }

    # Shifted retention: corpus and eido states (different distributions
    # from the formal-verification task) plus a fixed sample of K0 noise keys.
    shifted_states = [
        s for s in train_states if s["group"] in ("corpus", "eido")
    ]
    assert len(shifted_states) == 16, len(shifted_states)
    noise_ids = sorted(meta["noise_ids"])[:NOISE_SAMPLE_N]
    shifted_cases = [case_from_state(s) for s in sorted(shifted_states, key=lambda s: s["state"])]
    shifted_cases += [
        {
            "case_id": "noise-%s" % noise_id,
            "noise_id": noise_id,
            "scoring": "kl_vs_base",
        }
        for noise_id in noise_ids
    ]
    retention_shifted = {
        "suite": "retention_shifted",
        "suite_version": SUITE_VERSION,
        "n_cases": len(shifted_cases),
        "scoring": "kl_vs_base",
        "noise_sample": {
            "n_sampled": NOISE_SAMPLE_N,
            "n_total_noise_keys": len(meta["noise_ids"]),
            "rule": "first 64 noise ids in sorted order; no RNG",
        },
        "cases": shifted_cases,
    }

    out = {
        "audit/split_leakage.json": audit,
        "suites/task.json": task,
        "suites/retention_iid.json": retention_iid,
        "suites/retention_shifted.json": retention_shifted,
    }
    for rel, obj in out.items():
        data = dump(obj)
        with open("%s/%s" % (args.out_dir, rel), "wb") as f:
            f.write(data)
        print("%s sha256=%s" % (rel, sha256_bytes(data)))


if __name__ == "__main__":
    main()
