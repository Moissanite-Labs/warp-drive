# Independent non-author executable review: warp-drive PR #20

Date: 2026-11-22  
Pull request number: 20  
Reviewed head: `516431afa21d53b98265aa8735f8a871707aad98`  
Tree: `acb3fc65d3c19c234abac04ba6eb24845298c197`  
Recorded base: `38a7072f8d23fe865b4d48d1da285a6db4fc14d1`

## Verdict

**Bounded verification complete. No new executable or evidence-integrity defect found in the required scope. One non-blocking current-status documentation finding is recorded below.**

This is an independent non-author review report, not an approval, merge-readiness claim, live-model result, or reproduction of the preserved scientific trials. The recovery reused `/tmp/warp-pr20-rereview` and `/tmp/warp-pr20-rereview-evidence`. It did not recreate the clone/worktree, relatch the head/tree, rerun valid manifest verification, or repeat the completed unit suite or N0 trials.

The required pinned-head, public-hygiene, manifest, unit-test, tokenpage, claim-scope, and PR15-staleness checks are complete. Only the raw-QA recomputation and static staleness analysis were newly executed after auditing preserved logs and return codes.

## Finding: PR15 ledger section is stale only as current-status documentation

`research/iteration-2026-11-21/LEDGER.md` lines 132–144 preserve a change request against PR15 head `e6ad0967c2386eb3e3bdc7d81ff3a47808d53a1e`. That remains accurate historical evidence and should not be rewritten. It does not record that PR15 later merged at `2026-11-22T11:15:31Z`, with merge commit `ef08c95f68d9e78e6317031fbdac32a9fc2b842b` and reviewed merge-target source `1117bbdcd0160bed91d2916161e86698137e12cb` (tree `2a56e59e1496147222059ceeb54479ea47955e8e`).

Static source comparison shows that both specific review items are superseded at the merge-target source:

- The sandbox no longer calls non-portable `realpath -e`. It uses `cd -P`/`pwd -P` plus explicit path normalization. This is source evidence only, not a sandbox execution result.
- The runtime report no longer says the pinned baseline already had `O_EXCL` + `fsync`. It now explicitly says baseline `e3899d3` used `write_bytes`/`write_text` without those operations and scopes the hardening to `WD-LEDGER-01`.

A future editorial update should append this later state and the no-retest boundary while preserving the original review and witnesses. The current ledger expressly pins findings to listed heads and says later fixes require fresh non-author execution, so this omission does not falsify its historical claims. No PR15 code or tests were executed, and this review does not claim that the target fixes work.

Evidence: `pr15.json`, `pr15-merge-target-commit.json`, `pr15-staleness.json`. Static-audit return code `logs/pr15-staleness.rc` = 0.

## Required checks and results

### 1. Pinned head and clean preserved worktree

- `head-commit.txt` identifies exactly `516431afa21d53b98265aa8735f8a871707aad98`.
- `head-tree.txt` and a read-only inspection identify tree `acb3fc65d3c19c234abac04ba6eb24845298c197`.
- `pr20.json` records the same `headRefOid`, PR state `OPEN`, and base `38a7072f8d23fe865b4d48d1da285a6db4fc14d1`.
- `worktree-status.txt` is empty. The recovery wrote only to the separate evidence directory.
- The PR delta adds 133 files under `research/iteration-2026-11-21/`: the manifest plus its 132 covered files. It does not modify shipped runtime code or add an Actions workflow.

Preserved setup/log return codes: `clone.rc` = 0, `worktree-add.rc` = 0, `pr-view.rc` = 0, `repo-api.rc` = 0. Earlier command output is retained beside those files.

### 2. Public hygiene

The exact suite's `test_public_repo_hygiene_no_local_paths_or_coauthored_trailers` passed in the preserved execution. No new hygiene failure was found in this bounded review. A supplemental static indicator search found only three intentional canary/test strings containing `BEGIN PRIVATE KEY` in `schemas/verifier-canaries.json`, `tests/mock_llama_server.py`, and `tests/test_live_llama_smoke.py`. These are rejection fixtures, not credentials. That search was not a substitute for the passing hygiene test or a general secret-scanning guarantee.

### 3. Manifest coverage and hashes

Preserved valid command, rerun not performed:

```sh
python3 /tmp/warp-pr20-rereview-evidence/verify_manifest.py /tmp/warp-pr20-rereview
```

Return code: `logs/manifest-verification.rc` = 0. `manifest-verification.json` reports:

- root `research/iteration-2026-11-21`.
- 132 manifest entries, declared count 132, tracked files excluding the manifest 132.
- 132 files checked.
- no missing files, uncovered files, duplicate-path error, length mismatch, or hash mismatch.
- `ok: true`.

Manifest SHA-256: `c3bf68d0f3171d48b17eff57a386de996835cf10e8c807f7d0470f540c5b6757`.  
Machine-readable verification SHA-256: `33c7dbe1a8c98f3b0261ddedba9906a8f29411de3c83bcd2d80cccbab30fc118`.

### 4. Exact PR unit-test command

Preserved valid command, rerun not performed:

```sh
PYTHONPATH=src:. python3 -m unittest discover -s tests -v
```

Working directory: `/tmp/warp-pr20-rereview`.  
Return code: `logs/unit-tests.rc` = 0.  
Result: 58 tests run, 57 passed, one optional live-GGUF test skipped. `OK (skipped=1)`. Recorded duration 16.977 seconds.

The skip is `test_live_full_stage1_to_stage4_real_llama_server_and_weft_lora`, requiring opt-in live GGUF inputs. No live test was enabled. The separate `test_opt_in_live_llama_server_probe` and nonexistent-binary fail-closed test passed without live weights.

Evidence: `unit-tests.stdout` (empty, SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`) and `unit-tests.stderr` (SHA-256 `9d778429040247257e2934b53a15277fa1e70793ee805e0afc106d21fd43be95`). The PR's earlier preserved invocation had duration 16.286 seconds. Duration is not treated as a stable witness.

### 5. Independent tokenpage no-legend recomputation

The original contradictory prose was not edited. Its preserved `AUDIT_LOG.md` SHA-256 remains `85bd519d784380a684bf033d3c879f1938277f1b38df065f41db19ae8916184c`.

The pinned public raw QA was fetched read-only from:

```text
https://raw.githubusercontent.com/Moissanite-Labs/tokenpage/a694232ecd2dca2b568e7c6dda8d38e3515dcf78/studies/expedition-proper-kl-audit/data/tokenpage_pr5/raw_qa_qwen1.5b.jsonl
```

Command shape:

```sh
curl --fail --location --silent --show-error <pinned-url> --output /tmp/warp-pr20-rereview-evidence/tokenpage-raw-qa.jsonl
```

Return code: `logs/tokenpage-fetch.rc` = 0. Raw QA: 240,010 bytes, 952 total rows, SHA-256 `8cc8f1ce33be37a2d2ece4b5dab0722db5772460478551bb2007d319b0508334`, exactly matching the pinned hash in the PR.

The independent zero-dependency script `recompute_tokenpage_no_legend.py` selected 240 G1 rows: 120 without legend and 120 with legend, with 24 rows for each of title, priority, scope, criteria, and dependency. It recomputed empirical entropy minus mean negative log2 gold probability and summed the five fields.

Valid command:

```sh
python3 -I -B /tmp/warp-pr20-rereview-evidence/recompute_tokenpage_no_legend.py
```

Return code: `logs/tokenpage-recompute.valid.rc` = 0.

- No-legend empirical KL: **`-6.651510759217704` bits**.
- With-legend empirical KL: **`-4.8844556181300325` bits**.
- Rounded published delta: **`1.767` bits**.
- The machine receipt's no-legend value is reproduced.
- The prose figure `-6.651419738969508` is not reproduced. Prose minus recomputation is approximately `9.102024819540588e-05` bits.
- The ledger correctly treats the prose figure as an unreproduced transcription while retaining the original contradiction.

Receipt: `tokenpage-recompute.json`, SHA-256 `f9f14b90b9236de05a861518f21f5c187e386a59f34198aa16433a8b35cee580`. Script SHA-256: `6f264d20f23a5e52940398ece2cc2ab1d80906502f36684232815fd620812092`.

A first-pass script returned 1 before arithmetic because it incorrectly expected 240 total raw rows rather than 240 selected G1 rows. That failure, its source, and its logs are preserved as `.attempt1` artifacts. The corrected validation expects 952 total rows. Neither raw input nor PR prose changed. See `logs/inspection-failures.md`.

### 6. Claim scope and live-model boundary

The ledger and machine-readable summary consistently scope claims to recorded executions:

- test doubles establish control flow only.
- compiler/runtime/lifecycle and transport trials used doubles or mocks.
- live provider behavior remains `UNVERIFIED`.
- live GGUF, CUDA, physical GPU checkpoints, paid-provider behavior, and real model quality remain unverified.
- N0 labels denote completed negative evidence, not universal theorems or scientific novelty.
- later fixes require new non-author execution.

The PR body explicitly says not to treat it as merge approval or live-model evidence. The unit suite's one live test was skipped. This review found no claim that improperly converts mocked or static evidence into live-model evidence. This is a bounded claim-language audit, not a semantic proof of every preserved document.

## Commands, return codes, and incidental failures

All preserved return-code files are under `logs/`. Successful required checks have return code 0: clone, worktree add, PR/repository metadata reads, manifest verification, unit tests, PR15 metadata/target reads, raw-QA fetch, corrected recomputation, and static PR15 staleness analysis.

Two incidental inspection failures do not alter the verdict:

1. The first raw-QA validator returned 1 for the total-row assumption described above. `.attempt1` evidence is preserved.
2. An auxiliary static `git show` used a nonexistent PR15 path, `studies/expedition-trust-boundary-verifier/warp_drive_runtime_r5.py`, and returned 1. The required sandbox/report blobs were successfully read and hashed separately. This was not a test or source defect. Details are in `logs/inspection-failures.md`.

No failed unit test, manifest mismatch, raw-input hash mismatch, or numerical check failure remains unresolved. No rate-limit retry was repeated during recovery.

## Limitations and no-findings boundary

- No preserved trial other than the bounded raw-QA arithmetic was rerun. In particular, no N0 spectral/LDL trial, tokenpage harness mutation, external study, mutation-kill campaign, publication readback, or PR15 test was repeated.
- Existing recorded failures in other PRs remain findings against their pinned sources. They are not new PR20 regressions and were not independently re-established here.
- No paid providers, credentials, model downloads, live GGUF/CUDA/GPU execution, external writes, GitHub writes, or new mocks were used. The only mocks are those already present in the preserved unit-test run.
- Static PR15 supersession is not executable fix verification.
- No security audit, universal theorem proof, scientific-novelty determination, approval, or merge-readiness conclusion is made.

Within those boundaries, the pinned head/tree, evidence manifest, hygiene test, exact unit command, raw-QA value, and recorded-execution claim scoping support the PR's preservation claims. The sole finding is the non-blocking PR15 current-status staleness described above.

## Evidence index

Evidence root: `/tmp/warp-pr20-rereview-evidence`

- `REPORT.md`: this report.
- `SHA256SUMS`: hashes for the evidence package, excluding itself.
- `head-commit.txt`, `head-tree.txt`, `worktree-status.txt`, `pr20.json`, `repository.json`: pin and repository metadata.
- `manifest-verification.json`, `verify_manifest.py`, `key-file-sha256.txt`: integrity witnesses.
- `unit-tests.stdout`, `unit-tests.stderr`, `logs/unit-tests.rc`: exact-suite witnesses.
- `tokenpage-raw-qa.jsonl`, `recompute_tokenpage_no_legend.py`, `tokenpage-recompute.json`, `tokenpage-recompute.valid.stdout`: valid independent recomputation witnesses.
- `recompute_tokenpage_no_legend.attempt1.py`, `tokenpage-recompute.attempt1.stdout`, `logs/tokenpage-recompute.attempt1.stderr`, `logs/tokenpage-recompute.attempt1.rc`: preserved failed first pass.
- `pr15.json`, `pr15-merge-target-commit.json`, `pr15-staleness.json`: merged-state and static-source witnesses.
- `logs/`: setup, metadata, verification, fetch, and execution return codes/logs.
- `repo.git/`: preserved bare source object store used for the existing worktree and static source reads.
