# Lane 7 audit log: independent verification of deployment, rejection, and rollback

Issue #7, parent #3. Demo deadline 2026-11-22 10:00 AM PT.
Audit date 2026-11-21. Agent sparky-118.

## Heads verified (live, read with gh before acting)

| Ref | SHA |
| --- | --- |
| main | `38a7072f8d23fe865b4d48d1da285a6db4fc14d1` |
| PR #8, `lane/4-freeze-contract` | `f9c9acce18434262bded9dd6263f46b80f6b89b1` |
| PR #10, `lane/5-controller` | `c526b8d3d73d018bb159312a9cf63adfc80e324d` |
| PR #9, `lane/6-cerebras-kimi` | `bf8de4b0e3f0451a496a76d87a537003b3377931` |

Checks on all three PR heads: CodeQL success, Analyze (python) success.
Each PR reports mergeable against main (blocked only on review).

## Environment

- VM: 4 CPUs, 7.7 GiB RAM. Python 3.12.3, pytest 9.1.1.
- No GPU: `nvidia-smi` is not installed. No `llama-server` binary.
- No local GGUF checkpoint on disk. The Hugging Face cache holds only
  partial blobs (largest entry 8.7 MB). The pinned checkpoint
  `Qwen3.5-4B-Q8_0.gguf` is not present.
- No Cerebras credential in the environment.
- Consequence: every empirical verdict on the real checkpoint, the real
  runtime, and the live provider is UNVERIFIED here. Mocked runs prove
  schema and routing only, never model evidence. Nothing in this log
  presents a mocked result as model evidence.

## Grounding receipts fetched (ml-os branch geminus/2026-11-19-m1-runtime-findings)

| File | sha256 |
| --- | --- |
| `results/harvest_v1.meta.json` | `83dc39609df5f955d2b1317ffc32b1ba2d1ac1c1731e28661fc765e5d0617a58` |
| `results/manifest.json` | `7faee9c12914ba91ff9c049db9e8ad705eaa79fa333add6a45f4d10c859a6285` |
| `results/server_logit_check_v2.json` | `2f994365af09eeaaece26154a48f3002d0a1d909f8999fbcccc1179f36c41152` |
| `results/rollback_probe_v2.json` | fetched, see rollback section |

## Reproduction commands

Fetch the grounding receipts:

```sh
gh api "repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/results/harvest_v1.meta.json?ref=geminus/2026-11-19-m1-runtime-findings" --jq '.content' | tr -d '\n' | base64 -d > harvest_v1.meta.json
gh api "repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/results/manifest.json?ref=geminus/2026-11-19-m1-runtime-findings" --jq '.content' | tr -d '\n' | base64 -d > ml-manifest.json
gh api "repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/results/server_logit_check_v2.json?ref=geminus/2026-11-19-m1-runtime-findings" --jq '.content' | tr -d '\n' | base64 -d > server_logit_check_v2.json
gh api "repos/Moissanite-Labs/ml-os/contents/receipts/geminus-2026-11-19/results/rollback_probe_v2.json?ref=geminus/2026-11-19-m1-runtime-findings" --jq '.content' | tr -d '\n' | base64 -d > rollback_probe_v2.json
```

Fresh clones (the shared checkout was not used):

```sh
git clone https://github.com/Moissanite-Labs/warp-drive.git warp-drive-lane7
git -C warp-drive-lane7 fetch origin pull/8/head:lane/4-freeze-contract pull/9/head:lane/6-cerebras-kimi pull/10/head:lane/5-controller
```

Suite regeneration (must be byte-identical to the committed files):

```sh
python3 experiments/demo-2026-11-22/scripts/generate_suites.py \
  --harvest-meta harvest_v1.meta.json --ml-manifest ml-manifest.json \
  --out-dir /tmp/lane7-regen
diff -r /tmp/lane7-regen experiments/demo-2026-11-22
```

Test suites (each lane worktree):

```sh
python3 -m pytest tests/test_experiment_contract.py -q            # lane 4 tree
PYTHONPATH=src python3 -m pytest tests/ -q                        # lane 5 tree
PYTHONPATH=src python3 -m pytest tests/ -q                        # lane 6 tree
```

Independent verifier (this PR):

```sh
python3 tools/lane7_verify/verify.py all \
  --exp-dir <path to experiments/demo-2026-11-22> \
  --harvest-meta harvest_v1.meta.json --ml-manifest ml-manifest.json \
  --pilot server_logit_check_v2.json \
  --receipt tools/lane7_verify/tests/fixtures/receipt.json \
  --log tools/lane7_verify/tests/fixtures/receipts.jsonl \
  --schema <path to schemas/cerebras-candidate.schema.json>
python3 -m pytest tools/lane7_verify/tests/test_lane7_verify.py -q
LANE7_EXP_DIR=<path to experiments/demo-2026-11-22> python3 -m pytest tools/lane7_verify/tests/test_lane7_verify.py -q
```

Black-box controller probe (audit scratch, not part of the verifier. It
drives the controller through its public API with the lane's own fakes):

```sh
PYTHONPATH=<lane5>/src:<lane5>/tests python3 warp-lane7-probe.py
```

## Verifier run (2026-11-21, against the heads above)

| Check | Verdict | Evidence |
| --- | --- | --- |
| contract | VERIFIED | Exact: 10 file digests plus the combined suite digest match the manifest. Versions and suite counts agree. Manifest sha256 `846124e325813920ce4bf98732b7c9ba76172f8c0a466a87fb51e827e2728571`. |
| split_leakage | VERIFIED | Exact: 110/112 held-out states (98.2 percent) reuse a training pair. By family A 32/32, B 14/16, C 32/32, D 32/32. 20 distinct held-out pairs, 46 distinct training pairs. |
| margins | VERIFIED | Exact, recomputed from 120 raw round results: adapter 84/84 above -0.3699 (range -0.1161 to 0.1860). Baseline 36/36 at or below (range -1.0092 to -0.8060). Gap 0.6899. |
| receipt | VERIFIED | Exact: the golden receipt matches the frozen schema consts. Manifest and combined suite digests recompute. Candidate config matches the frozen knobs (rank 8, layer 31, eta 0.01, scale 1.0). Verdict ACCEPT. |
| policy | VERIFIED | Independent policy from thresholds.json: ACCEPT, no failed gates. Agrees with the controller receipt. |
| receipt_log | FALSIFIED | Line 3 is not strict JSON: non-strict JSON constant NaN. See A3. |
| config_digests | VERIFIED | Exact: 2 logged config digests recompute. The digest recorded before evaluation matches the proposed digest. |
| cerebras_bounds | FALSIFIED | Rank enum [4, 8, 16, 32] vs frozen rank 8. Target_layer const 'last' vs frozen layer 31. Schema carries strength, not the frozen eta knob. No lambda knob. Strength, not the frozen lora_scale knob. See A8. |

Verifier exit code 1 (two FALSIFIED checks, both real anomalies, both
returned to their owning lanes).

## Verification matrix (issue #7)

### Reject base-checkpoint drift: PARTIAL

The controller rejects a reported digest mismatch before the compiler
runs (probe P5: `CheckpointMismatchError`, zero compiler calls). It
never hashes the checkpoint file itself: `compile_and_bind` takes the
digest as a caller-supplied string. Real byte-level drift rejection
lives in Warp Stage 1 (`verify_stage1`, called by `mount_stack` on
main), which the controller's `Runtime.mount_adapter` seam is not yet
wired to. The controller docstring says so. End-to-end drift rejection
is UNVERIFIED live (no checkpoint, no runtime). See A4.

### Reject adapter-hash drift: PARTIAL

Same shape. The controller checks the compiler repo and commit and the
digest format, and accepts any well-formed digest: a compiler returning
`aaaa...` (64 hex chars) for an adapter it never built is accepted
(probe P6). No artifact re-hash exists in the controller. See A4.

### Reject caller-supplied raw LoRA overrides: VERIFIED

Probe P3: all 10 override keys (`lora`, `lora_path`, `lora_scaled`,
`adapter`, `adapter_path`, `adapter_sha256`, `adapter_file`,
`raw_lora`, `weights`, `gguf`) raise `UnverifiedLoraOverrideError`.
The lane's own tests cover the same keys.

### Reject malformed candidate manifests: VERIFIED

Probe P4: 17 malformed shapes rejected (eta below/above range, bool,
NaN, string; rank 4; layer 30; tensor `ffn_down`; quant `q8_0`;
unknown key, missing eta, missing scale, scale 0.5, scale -1.0 without
the control flag; lambda 7; lambda `median`; bad candidate id).
Quant `f16` is accepted, correct per the pinned Weft
`SUPPORTED_QUANT_DTYPES`.

### Unchanged-base control accepted only in its intended control path: VERIFIED

Probe P9a: the base control via `propose_control` returns
CONTROL_PASS. Probe P10: an ordinary candidate at scale 0.0, whose
margins look like the base, is REJECTED by the `margin_adapter` gate.
The control path (`check_control`) is separate from the candidate
policy, and only the two preregistered control ids can enter it.

### Deliberately regressed candidate rejected even if its text appears plausible: PARTIAL

Probe P9b: the regressed control is REJECTED with the `task_top1` gate
on fake measurements (top1 0.40, below the base 0.518). The control
construction (sign-flipped scale -1.0) is defined in `controls.json`,
not measured, and the file says so. Whether the real sign-flipped
adapter fails on the live checkpoint is UNVERIFIED (no checkpoint, no
runtime), as is any claim about its output text.

### Shadow mounting, canaries, activation, immediate rollback, signed receipts: PARTIAL

Code paths exist on main and their unit tests pass: `mount_stack`
Stages 1 to 4, Stage 3 canaries, rollback with multi-bank flush,
HMAC-SHA256 `SignedLedger`. No live exercise is possible here (no
llama-server, no checkpoint), so the live demonstration is
UNVERIFIED. Controller-level gaps: the `Runtime.mount_adapter` seam is
not wired to `mount_stack`, so shadow mounting and activation are not
exercised through the controller at all; the controller's `ReceiptLog`
is hash-chained only, not signed (signing lives in Warp's ledger, and
the controller's rollback path reaches it only through the unwired
lifecycle seam). The controller's rollback bank requirement is
incompatible with the pinned checkpoint's bank set (A2). The
`evaluated` receipt entry is not strict JSON (A3).

### Baseline log-probabilities restored after rollback under the full state-flush contract: UNVERIFIED live

Published pilot evidence, recomputed from the raw probe file: blk31
rolls back exactly, 14/14 sequences at k = 1, 4, and 16, max logit
difference 0.0, exact-match fraction 1.0. Blk28/29/30 do not roll back
exactly (max differences up to 0.51), which supports the last-layer-only
design. But the probe script is titled "Rollback without a cache
flush" and is library-level only, so the published exactness does not
prove restoration under Warp's full state-flush contract. The contract
keeps the full-flush requirement anyway (thresholds.json says so), and
the narrow no-flush result must not replace it. Full-flush restoration
on the live runtime is UNVERIFIED, and A2 blocks even a mocked
end-to-end rollback through the real lifecycle.

### Split leakage: VERIFIED

Regenerated the suites from the published inputs: all four generated
files byte-identical to the committed files, and their sha256 values
match the manifest digests. Independent pair-overlap recomputation
from the harvest states and held-out ids agrees with the audit:
110/112, by family as above. The split is weak and the audit says so.
task scores on it measure fit to seen token pairs, not
generalisation. Report the audit fraction with every task score.

### Candidate lineage: VERIFIED

- Base checkpoint sha256 in the manifest equals `model_sha256` in
  `harvest_v1.meta.json` (`10cc391b...61e1`, file
  `Qwen3.5-4B-Q8_0.gguf`).
- Reference adapter sha256 in the manifest equals the ml-os
  `plain_blk31` sha256 (`5bbc3737...87e4`). The ml-os file is named
  `plain_blk31.gguf`; the manifest names it `c31_plain.gguf`. Same
  digest, renamed file.
- Compiler commit `5d7eac03696c2ff07ec70308b23b86a1d4088c1e` read live
  from `siliconcordat/weft`: 2026-11-20T04:52:25Z, "Merge pull request
  #8 ... weft: SwiGLU/RMSNorm tangent projection ...", matching the
  manifest.
- Runtime build `b12549-8af68d486` matches the `build_info` field in
  `server_logit_check_v2.json`.
- Manifest lineage points at ml-os PR #6 ("Geminus/2026 11 19 m1
  runtime findings", open, unmerged) and branch
  `geminus/2026-11-19-m1-runtime-findings`, and warp base 38a7072,
  which is the main head verified here. Evidence lives on an unmerged
  branch, not a merged commit.
- Safety canaries: all 9 ids in `suites/safety_canaries.json` are
  present in main's `schemas/verifier-canaries.json`, exact set match.

### Hash ordering: VERIFIED

Combined suite digest recomputed over the concatenated suite bytes in
manifest order (task, IID, shifted, canaries) matches
`abc72b6a63bb6e1deb16ff052a6a4ba37a2545d3196c2653b0d742f0e21e74f9`.
Every manifest digest recomputes, including `audit_split_leakage` and
`generate_suites_script`. Candidate config digests recompute from the
logged configs (canonical JSON, sorted keys), and the digest recorded
before evaluation matches the proposed digest.

### Missing receipts: PARTIAL

- The receipt log detects edits and deletions (probe P14b/P14c: both
  fail `verify()`), and the order digest-before-evaluation holds
  (P8b).
- But `verify()` returns True on an empty or missing log (P14d), so
  absence of receipts is undetectable from the log alone.
- Compiler or runtime exceptions leave no receipt entry: an evaluate
  failure leaves the adapter mounted with no rollback and no failure
  receipt (P11). See A5.
- `load_contract` does not check the manifest's
  `audit_split_leakage` or `generate_suites_script` digests, though
  the manifest pins them. See A6.

### Unsupported claim wording: FALSIFIED in thresholds.json

Two sentences in the frozen `thresholds.json`
`adapter_application_margin.rule` are wrong against the pilot data:

1. "Every probe request margin must exceed the threshold." Baseline
   margins must NOT exceed it; the gate is two-sided.
2. "One W0-side margin fails the gate." No W0-side margin fails: all
   36 baseline margins pass (max -0.806, well below -0.37).

The margin gate itself is CONFIRMED, not struck: the pilot clusters
support the two-sided gate (adapter min -0.116, baseline max -0.806,
gap 0.69), the midpoint -0.3699007034301758 matches `threshold_exact`
exactly, and `controls.json` states the baseline-side expectation for
the base control ("all probe margins on the W0 side of -0.37"). Only
the two sentences are wrong. See A1.

## Cross-checks

- Margin threshold: pilot `decision_threshold_margin_midpoint`
  -0.3699007034301758 equals thresholds.json `threshold_exact`.
  Pilot clusters in the claim comment (-1.01 to -0.81 baseline, -0.12
  to +0.19 adapter) match the recomputed ranges.
- Rollback rule: thresholds.json says 14/14 sequences at k = 1, 4,
  16, max logit difference 0.0. Recomputed from `rollback_probe_v2.json`
  raw rows: blk31 max 0.0 and exact-match fraction 1.0 at all three k.
- Test suites rerun in fresh worktrees at the verified heads:
  - Lane 4 tree: 68 passed, 1 skipped (30 subtests).
  - Lane 5 tree: 122 passed, 1 skipped (30 subtests). Contract-only
    11 passed. Controller-only 54 passed. The claim comment on issue
    #5 said 119 passed for the full suite. This rerun gives 122. The
    3-count difference is unexplained, reported as a minor note, not
    an anomaly. The 1 skip is the opt-in live GGUF test, correctly
    skipped without a checkpoint.
  - Lane 6 tree: 90 passed, 2 skipped (61 subtests). The skips are
    the live Cerebras smoke tests without a credential. The README's
    documented `python3 -m unittest tests/test_cerebras_client.py`
    command also passes (33 tests).
- Black-box controller probe: 31 checks, 1 FAIL (P13, the NaN entry).
  The probe script is audit scratch at
  `~/workspace/sparky-118/warp-lane7-probe.py`; the golden fixtures in
  this PR reproduce its receipt artifacts.
- Verifier tests: 19 passed (including the golden-fixture test against
  the real frozen contract).
- Golden fixtures: `receipt.json` sha256
  `84d68500638cce27f5a8799eafd4fb4f3f89ce28d359c33fb97d87e7338d140f`;
  `receipts.jsonl` sha256
  `7b894463488313b160bfebbb49d6142aa98e38eed78b5352f2b3d2d6646f0b92`.
  Generating run verdict ACCEPT, candidate `cand-e08705d50d27`,
  adapter sha256 prefix `7740e3f43f0ca54e`.

## Anomaly register (returned to the owning lane)

A1 belongs to lane 4. A2 through A7 belong to lane 5. A8 and A9 belong to lane 6. A10 is a merge-order note for the hub.

### A1: thresholds.json margin wording is wrong

The two sentences quoted above contradict the pilot data. The gate is
confirmed. The wording must be fixed by a versioned manifest bump, not
a silent edit. Returned to lane 4.

### A2: controller rollback demands banks the pinned checkpoint does not have

`ExperimentController.rollback` requires all three banks in
`ALL_STATE_BANKS` (KV, SSM, horizontal lattice). Warp's
`CheckpointFingerprint.required_state_banks()` returns only the banks
the checkpoint has. Qwen3.5-4B is a plain transformer, so the real
`WarpModeld` returns only `kv_cache`. Probe P12: a lifecycle
reporting only `kv_cache` makes the controller raise
`StateFlushError` ("rollback state flush missed banks: ssm_recurrent,
lattice_horizontal_streams"). The controller's own tests use a fake
lifecycle that always reports all three banks, so the suite passes
while real integration would fail every rollback. The fix needs the
contract to pin the required bank set (or the lifecycle to report it)
instead of an unconditional all-three requirement. Returned to lane 5.

### A3: "evaluated" receipt entry is not strict JSON

`evaluate()` fills rollback placeholders (`max_logit_diff` NaN,
exact_matches -1) and logs them. `json.dumps` with default settings
writes the bare token `NaN`, which strict JSON parsers reject. The
placeholder never reaches a final receipt (`promote_or_reject`
refuses it), but the append-only log itself contains a non-strict
line. Probe P13 demonstrates it; the verifier's `receipt-log` check
flags it. Returned to lane 5.

### A4: drift checks compare caller-supplied strings only

`compile_and_bind` takes `actual_parent_sha256` as a string and never
hashes the checkpoint file. The compiled adapter digest is taken from
the compiler's return value and never re-hashed against an artifact
(probe P6). A caller that reports the pinned digest while mounting
different bytes is not detected by the controller. The byte-level
check exists in Warp Stage 1 but is not wired to the controller's
runtime seam. Either wire the seam or state the trust boundary: the
controller rejects reported drift, and byte-level drift rejection
belongs to Warp Stage 1 at mount. Returned to lane 5.

### A5: evaluate failure leaves the adapter mounted with no rollback

`run_experiment` has no rollback-on-error path. Probe P11: when
scoring raises, the run stops with the adapter still mounted, no
rollback attempted, and no failure receipt. A failed evaluation must
still roll back (or the mounted state must be recorded as
not-baseline). Returned to lane 5.

### A6: two pinned digests are never checked by the loader. Empty log verifies

`load_contract` verifies seven file digests but not
`audit_split_leakage` or `generate_suites_script`, though the manifest
pins both. Separately, `ReceiptLog.verify()` returns True for an empty
or missing log (probe P14d), so a missing receipt log passes
verification vacuously. Returned to lane 5.

### A7: receipt environment is caller-asserted

`build_receipt` checks the environment's llama.cpp build and commit
against the manifest, but the environment dict is supplied by the
caller. A fake run receipts build `b12549` and commit `8af68d486`
(probe P15b) though no llama-server ran. Receipts attest the caller's
claims about the environment, not a measured environment. Record the
limit. Measure the environment where the demo runs it live. Returned
to lane 5.

### A8: Cerebras candidate bounds are stale against the frozen contract

The schema and client still carry the provisional bounds from before
the freeze: rank enum [4, 8, 16, 32] vs frozen rank 8. Quantization
[q8_0, q4_0, bf16] vs the Weft set (bf16, f16, f32, int8, int4).
`target_layer` const "last" vs frozen layer 31; `strength` instead of
the frozen `eta` and `lora_scale` knobs; no `lambda` knob. The schema
itself says the bounds are provisional until lane 4 freezes the
contract. Lane 4 is now frozen, so the bounds must be updated to it.
Returned to lane 6.

### A9: default Kimi model id is not directly callable live

Confirmed against Cerebras's own docs (Inference docs, change log
2026-11-17): the shared-inference catalog lists only `gpt-oss-120b`
and `qwen-3.8-27b`. Kimi K3.1 Pro is in the Dedicated model catalog;
a live call uses the org-assigned endpoint id as the `model` value,
not `kimi-k3.1-pro`. The client already documents the
`CEREBRAS_MODEL_ID` override for a dedicated endpoint id, and the
lane's README already states the live status as UNVERIFIED, so this
confirms the lane's own disclosure rather than contradicting it. The
default will fail on a live call. The demo needs a dedicated endpoint
id. Returned to lane 6.

### A10: lane 6 does not merge cleanly onto lane 5 (merge order)

Test merge of `lane/6-cerebras-kimi` into `lane/5-controller`
conflicts in `src/warp_modeld/__init__.py` and
`src/warp_modeld/errors.py` (both lanes append to the same import and
error-class lists). The test merge was aborted and the scratch
worktree removed. Merge order stands: the controller PR merges after
the contract PR, then the Cerebras PR with a mechanical conflict
resolution in those two files. Noted here for the hub. No code change
in this PR.

## Open items (not done, not claimed)

- Live checkpoint verification, live runtime check, tokenizer digest,
  and suite executability: UNVERIFIED. Blocked on the RTX 3080 host,
  the pinned checkpoint, and the ml-os dataset.
- Live Cerebras call: UNVERIFIED. Blocked on a credential and a
  dedicated endpoint id.
- Live shadow mounting, canaries, activation, immediate rollback, and
  signed rollback receipts: UNVERIFIED. Blocked on a live llama-server.
- Review of the final integration PR as a non-author reviewer: open.
  No integration PR exists yet; the lanes are unmerged.
- The three repair rounds, the accepted improvement candidate, and the
  demo timings are future work, not verified here.
