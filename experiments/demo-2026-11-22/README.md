# Demo experiment, 2026-11-22: frozen contract

One pinned checkpoint, one last-layer LoRA recipe, frozen suites, frozen
thresholds. Parent hub: issue #3. This lane: issue #4.

## What is frozen

| File | Content | Digest (sha256) |
| --- | --- | --- |
| `manifest.json` | Pinned base, runtime, compiler, lineage, knobs | see PR body |
| `suites/task.json` | 112 held-out states, families A 32, B 16, C 32, D 32 | `18f12069c1717b7bbe1d6cae37512a5c1e338a4a42836428b04665628fae7509` |
| `suites/retention_iid.json` | 24 anchor states | `0fc73d13c14a9673f20337b621dcef0dfbd625501329a190c9500e5fe74fc034` |
| `suites/retention_shifted.json` | 16 corpus/eido states + 64 K0 noise keys | `4bff6104d768ac922e3f6539856456f208f0fa882320886145a54c6c0b1c1249` |
| `suites/safety_canaries.json` | 9 canaries by id (prompts live in `schemas/verifier-canaries.json`) | `031d9e32247bbaa2a3c93ac5600c2441bdf97318c8c40c2e841a18f97197ef31` |
| `thresholds.json` | Preregistered gates, repair budget 3 | `eb2c654ed39823308d768ee38c49211fc7bba9dab063ca828727bdbf72e76dcc` |
| `controls.json` | Base control (expect PASS), sign-flipped control (expect REJECT) | `99277bfb989d7e4c0a6625f94d4dbadb033006434e2b450bd5875645e4abee77` |
| `receipt.schema.json` | Receipt schema: seeds, hashes, env, timings, verdicts | `009a148ed22cd58f23a988ea10f588ae84ebdd0c0d32c9b100fc58bf60af9b19` |
| `audit/split_leakage.json` | Split-leakage audit | `f6381b6a076f9f9bd15128e53ad1b6165bb19e418feb1fada7d63594c672ca0c` |

Combined suite digest: `abc72b6a63bb6e1deb16ff052a6a4ba37a2545d3196c2653b0d742f0e21e74f9`
(sha256 over the four suite files concatenated in task, IID, shifted,
canary order).

## Split-leakage audit (recomputed, not repeated)

110 of 112 held-out states (98.2 percent) reuse an exact
(positive-token, negative-token) pair seen in training. By family: A 32/32,
B 14/16, C 32/32, D 32/32. Only 20 distinct pairs cover the 112 held-out
states. The held-out split is weak: task scores on it measure fit to seen
token pairs, not generalisation. Report the audit fraction with every task
score. Method and counts are in `audit/split_leakage.json`.

## Verification state

- VERIFIED: base GGUF digest, runtime build and flags, compiler commit,
  reference adapter digest, margin threshold, split-leakage audit, suite
  determinism. Each is traced to its published receipt in `manifest.json`.
- PREREGISTERED: thresholds. They are decisions frozen from pilot values,
  not measurements. UNVERIFIED against a live run until lane 5 measures
  the reference adapter against them.
- UNVERIFIED: tokenizer name and digest (no published value found);
  live checkpoint verification; live runtime check; suite executability
  (prompt text is not published, so the suites run only with the ml-os
  dataset and the pinned checkpoint).

## Observed hardware limits on this machine

- No GPU: `nvidia-smi` is not installed, no CUDA device present.
- No local GGUF checkpoint on disk (searched the workspace and filesystem).
- No Cerebras credentials. Live checkpoint verification is a blocker,
  recorded in the manifest, not filled in by hand.

## Reproduction commands

Fetch the grounding receipts (ml-os branch, default-branch path 404s):

```sh
gh api repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/FRONTIER.md?ref=geminus/2026-11-19-m1-runtime-findings --jq '.content' | base64 -d > FRONTIER.md
gh api repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/results/harvest_v1.meta.json?ref=geminus/2026-11-19-m1-runtime-findings --jq '.content' | base64 -d > harvest_v1.meta.json
gh api repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/results/manifest.json?ref=geminus/2026-11-19-m1-runtime-findings --jq '.content' | base64 -d > ml-manifest.json
gh api repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/results/server_logit_check_v2.json?ref=geminus/2026-11-19-m1-runtime-findings --jq '.content' | base64 -d > server_logit_check_v2.json
```

Regenerate the suites and audit (must be byte-identical to the committed files):

```sh
python3 experiments/demo-2026-11-22/scripts/generate_suites.py \
  --harvest-meta harvest_v1.meta.json \
  --ml-manifest ml-manifest.json \
  --out-dir experiments/demo-2026-11-22
sha256sum experiments/demo-2026-11-22/audit/split_leakage.json \
  experiments/demo-2026-11-22/suites/task.json \
  experiments/demo-2026-11-22/suites/retention_iid.json \
  experiments/demo-2026-11-22/suites/retention_shifted.json
```

`suites/safety_canaries.json` is hand-pinned by id and is not produced by
the generator, so it is not part of this checksum step.

Run the contract tests (mock fixtures only: parsing and control flow, never
model evidence):

```sh
python3 -m pytest tests/test_experiment_contract.py -v
```

Live run (NOT run here; needs the RTX 3080 host, the pinned checkpoint,
and the ml-os dataset). Server flags are pinned in `manifest.json`:

```sh
llama-server -m Qwen3.5-4B-Q8_0.gguf --host 127.0.0.1 --port 63301 \
  -c 65536 -ngl 99 -np 8 -ctk f16 -ctv f16 --slots \
  --no-cache-idle-slots --lora-scaled <adapters> --lora-init-without-apply
```

## Rules

- Candidates cannot modify the manifest, suites, thresholds, or receipt
  schema. Candidate hashes are recorded before behavioral evaluation.
- Repair budget: at most 3 rounds.
- A threshold changes only by a versioned manifest bump with a stated
  reason, never by silent edit.
- Mock fixtures test parsing and control flow only, never model evidence.

## Controller (issue #5)

`src/warp_modeld/experiment.py` is the bounded experiment controller.
It is a project-specific weight experiment harness, not an interoperable
W-MCP standard. It consumes this frozen contract: `load_contract`
recomputes every pinned digest before anything else runs, and any
mismatch refuses the contract.

Operations, in fixed order: `propose_candidate`, `compile_and_bind`
(Weft compiler through the `Compiler` protocol, parent checkpoint bound,
candidate digest written to the append-only receipt log before any
scoring), `evaluate` (the four frozen suites plus probe margins, all
results retained), `rollback` (Warp lifecycle rollback across every
state bank, then baseline logit restoration verified at exactly 0.0),
`promote_or_reject` (only the frozen acceptance policy; no caller can
pass in thresholds). `run_experiment` runs the sequence end to end and
returns the verdict plus a receipt matching `receipt.schema.json`.

Run the controller tests (fake compiler and runtime adapters; logic
checks only, never model evidence):

```sh
PYTHONPATH=src python3 -m pytest tests/test_experiment_controller.py -v
```

Live wiring (not run here; needs the demo host, the pinned checkpoint,
and the ml-os dataset): a real `Compiler` drives
`weft.compiler.BetaEditNullspaceProjector` at the pinned commit, a real
`Runtime` mounts through `WarpModeld.mount_stack` and scores through
the pinned llama-server flags, and rollback goes through
`WarpModeldLifecycle` over `WarpModeld.rollback`.
