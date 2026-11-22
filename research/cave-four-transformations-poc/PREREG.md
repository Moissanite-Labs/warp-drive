# Cave four-transformations POC preregistration

## Question

Can warp-drive replay the untouched Cave four-transformations known-answer suite under a locked research plan, preserve expected failures, and produce receipts that another checker can verify without trusting a summary?

This is a tooling and reference-replay result. It is not a new scientific claim about time arrows, models, or real instruments. Novelty remains `N0`.

## Fixed inputs

- Cave target: Foundation-0/cave-expedition pull request 8, commit `a714ef7981421266bea78e8357d61f3586f0eda0`.
- Cave plan: the target's `PREREG.md`, Amendments 1 and 2, and `AMENDMENTS_NEEDED.md` at that commit.
- Research method: Foundation-0/aletheia pull request 1, commit `7227bcc5dadb0f1b275a4ae9e7695b4323384f06`.
- Environment: Python 3.14.6 and numpy 2.5.4. The target uses only the standard library and numpy.
- Input data: synthetic data from the target's frozen seed rules. No real data file may be opened. No network access is needed.
- Target state: the target worktree must be clean and at the pinned commit before and after the run.

`cases.json` fixes scripts, arguments, modes, timeouts, expected process outcomes, and oracle classes before this POC run. `LOCK.json` fixes the hashes of the runner, protocol, preregistration, and case file. A target change, dirty worktree, or harness hash change halts the run.

## Coverage and budget

The full set is 18 case-mode runs. Unit checks, review witnesses, K1, K5, and K6 run in all three isolated Python modes. K2, K3, and K4 run only in plain mode because their recorded smoke costs are much higher. No run is a full-size scientific result. All K tests use the target's `smoke` argument. K4 and K5 have ten seeds even in smoke mode under the target's own rule.

Each case has a hard timeout in `cases.json`. Runs execute sequentially. There is no retry, adaptive threshold, extra seed, candidate optimization, model call, or paid compute. Expected failures are not rerun until they pass.

## Expected process outcomes

These expectations come from Cave's recorded outputs. They test reproduction, not nature.

| Case | Expected outcome | Oracle class |
|---|---|---|
| Unit checks | pass in all three modes | exact and sampled components |
| Review witnesses | pass in all three modes | exact executable witnesses |
| K1 | pass in all three modes | exact identities and mutation controls |
| K2 | fail in plain mode | sampled smoke outcome. Its must-fail control was not flagged at smoke size |
| K3 | fail in plain mode | sampled smoke outcome. Logistic `sub2` is below the gating criterion |
| K4 | pass in plain mode | sampled smoke outcome, not a full result |
| K5 | operational failure in all three modes | sampled test that stops before a verdict |
| K6 | pass in all three modes | exact refusal controls |

A script crash, timeout, missing summary, mismatched return code, or unexpected outcome is preserved. A reproduced expected failure counts as a matching replay. It never counts as a scientific pass.

## Decision rule

The POC produces `REFERENCE_REPLAY_COMPLETE` only when every expected case-mode outcome matches, the hash chain verifies, all output files match their recorded hashes, and the target remains unchanged. Otherwise it produces `REPRODUCTION_MISMATCH` or `OPERATIONAL_FAILURE`.

Real-data readiness remains `BLOCKED` regardless of replay success. Cave already records unresolved plan choices, K2 and K3 failures, the K5 overflow, incomplete mutation triage, and unbuilt checks. This POC cannot clear those gates.

## Aletheia application

- Law 2 and Law 2b: preserve the blocker and test the strongest reading of the existing plan. Do not declare the underlying method false from a smoke failure. Do not repair the plan after seeing its output.
- Law 3: use the untouched target as a reference replay, fixed seeds and controls, three Python modes where pinned, and an independent reviewer.
- Law 4: label every result `N0`. Full-text prior-art search is not triggered because no `N1` or `N2` claim is made.
- Law 5: connect the repositories through executable commits, hashes, commands, and receipts rather than shared terminology.
- Gate 8: lock the plan before execution and retain all failures.
- Gates 9 and 10: no novelty upgrade is sought. An independent advocate reviews any narrowed or negative tooling finding.
- R3/R6/R7: strictly parse JSON, take rules only from the locked case file, and recompute verdicts and counts from stored bytes.
- R4: compare the three pinned Python modes for the selected cases. No bare Python `assert` is allowed in the POC trust path.
- R5: test false acceptance, crashes, digest tampering, target changes, missing markers, and outcome changes against the POC harness.
- CS-08: fixed case count and timeouts; no adaptive compute.

## Independent review

A reviewer who did not author the runner must inspect the locked files, rerun its controls in all three modes, verify every receipt and output hash, and attempt to overturn the tooling conclusion. The reviewer may rerun selected target cases within the same fixed budget. Their findings are added without editing the original run receipts.

## Publication boundary

Only research records in Moissanite-Labs/warp-drive are published. Cave and Aletheia remain read-only references. Public files contain no local paths, credentials, real data, or live-model claims.
