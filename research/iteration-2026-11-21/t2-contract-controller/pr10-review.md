## Request changes: controller accepts missing evidence and incomplete binding

Reviewed head `c526b8d3d73d018bb159312a9cf63adfc80e324d` against base `38a7072f8d23fe865b4d48d1da285a6db4fc14d1`, with PR #8 at `f9c9acce18434262bded9dd6263f46b80f6b89b1` as the contract dependency.

The preregistered integration suite produced 6 passes and 8 failures across 14 checks. The following defects are reproducible at the pinned head.

### 1. Failed mount permits scoring without the digest receipt

`src/warp_modeld/experiment.py:1071-1077` assigns `_bound_candidate` and `_bound_compile` before `mount_adapter()` and before `candidate_digest_recorded`.

When the mock mount raises, a subsequent `evaluate()` scores every suite instead of raising `ControllerError("no bound candidate")`. The candidate hash receipt was never recorded.

Witness: `test_failed_mount_cannot_evaluate_without_digest_receipt`.

### 2. Scoring failure leaves the adapter active without rollback

`run_experiment()` calls `evaluate()` and `rollback()` sequentially at `experiment.py:1247-1248`, without exception cleanup.

A `score_suite()` failure produced `lifecycle.calls == []`. Expected `['experiment_rollback']`. No success verdict or success receipt was emitted, but rollback was never attempted.

Witness: `test_scoring_failure_rolls_back_and_emits_no_success`.

### 3. Receipt suffix truncation verifies as valid

`ReceiptLog.verify()` at `experiment.py:890-903` validates only the remaining prefix. After appending two valid records and deleting the second line, `verify()` returned `True`.

Editing a payload, duplicating an entry, and forging a stale parent were correctly detected. Suffix truncation was not.

Witness: `test_receipt_log_detects_suffix_truncation`.

### 4. Acceptance succeeds with empty probe and safety evidence

At `experiment.py:740` and `:746`, `all()` accepts empty margin lists. At `:769`, safety checks only the failure list and ignore `safety_canaries_run`.

- Empty adapter and baseline margins with zero requests returned `ACCEPT`.
- `safety_canaries_run=0` with no failures returned `ACCEPT`, despite the frozen nine-canary contract.

Witnesses: `test_empty_margin_evidence_cannot_pass_acceptance` and `test_zero_of_nine_canaries_cannot_pass_acceptance`.

### 5. Contract loading omits two pinned digests

`expected_files` at `experiment.py:260-269` omits `audit_split_leakage` and `generate_suites_script`.

Changing the audit's `held_out_states` to `-1` still loaded. Appending drift to `generate_suites.py` also loaded. This independently confirms the previously reported digest-coverage gap with two minimal mutations.

Witness: both cases of `test_contract_drift_rejects_every_manifest_pinned_file`.

### 6. Rollback accepts a 1/1 probe instead of the frozen 14-sequence result

`experiment.py:1156` requires only `sequences > 0`. The frozen rollback rule requires 14 of 14 sequences at `k=1,4,16` with zero logit difference.

`BaselineCheck(max_logit_diff=0.0, exact_matches=1, sequences=1)` was accepted.

Witness: `test_rollback_requires_frozen_14_sequence_probe`.

### 7. PR #10 conflicts after applying the contract head

A temporary merge produced an add/add conflict in `experiments/demo-2026-11-22/README.md`. This branch should be rebased onto its contract dependency rather than independently adding another version of that file. Resolving the temporary tree to this head's README made the contract and controller source files identical to the reviewed head, so the behavioral findings above are not artifacts of a different merged implementation.

### Test evidence

- Contract head standalone: 65 tests passed with 30 subtests, plus 11 focused contract tests.
- Controller head standalone: 119 tests passed with 30 subtests, plus 54 focused controller tests.
- Simulated combined source: 119 tests passed with 30 subtests.
- Adversarial integration: 14 checks, 6 passed and 8 failed.
- Caller policy override attempts and normal digest-before-scoring order passed.
- The optional live test was excluded.
- Both available checks report `SUCCESS`: `Analyze (python)` and `CodeQL`.

The preregistration SHA-256 is `487db259e474fe77c80ad5d3f18a842c758d6db3f6426bbc994a89dfebd1d344`. The adversarial source SHA-256 is `b2d548b31e27f2eb411824d0233f32bc51b9c0c6b70b4b67bb448da557cec7c0`.

All compiler, runtime, and lifecycle evidence uses test doubles. These are verified controller defects, not live model or weight-iteration results.
