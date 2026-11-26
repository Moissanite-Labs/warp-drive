# Cave four-transformations replay result

## Verdict

`REFERENCE_REPLAY_COMPLETE` at novelty `N0`, evidence class `reference_replay`.

All 18 locked case-mode outcomes matched Cave's recorded expectations at commit `a714ef7981421266bea78e8357d61f3586f0eda0`. This verifies warp-drive's ability to replay an external frozen suite under a locked budget and preserve independently checkable evidence. It does not validate Cave's scientific method or establish real-data performance.

## Fixed evidence

- POC lock: `9f1c5cd103696d342b2b152de8058cde278e371d980526b5db6e3e08946f6466`.
- Case file: `d8616d8708ea98c5b4704964ecdcde0d3e3bc11e17e66d6741fc6d29d5ba66d0`.
- Aletheia reference: Foundation-0/aletheia pull request 1 at `7227bcc5dadb0f1b275a4ae9e7695b4323384f06`.
- Run directory: `runs/run-001`.
- Receipt log SHA-256: `f98227b4c1b8ad5e102a078950ed88a74733a964762b27150e570d889fe80573`.
- Summary SHA-256: `6f0c9358e2ad257c2161d21a350f4b00b5d4b2af1f0ec51eff41d07bd74ca019`.
- Terminal receipt: `a613eafb93c4fc44867f20102a1dda393c596835a4455e3142023b155ee2c1d7`.
- The Cave worktree was clean at the pinned commit before and after the run. Its source was not modified.

## Outcomes

| Case | Locked coverage | Reproduced outcome |
|---|---:|---|
| U01 unit checks | 3 modes | `pass` in all three; each output reports 336 checks and zero failures |
| R01 review witnesses | 3 modes | `pass` in all three; each output ends with `UNGUARDED: none` |
| K1 exact identities and controls | 3 modes | `pass` in all three; each reports 7,614 main checks, zero failures, and all must-fail controls flagged |
| K2 sampled smoke | plain | expected `fail`; the must-fail control was not fully flagged at smoke size |
| K3 sampled smoke | plain | expected `fail`; one gating cell was below the criterion and the control was flagged |
| K4 sampled smoke | plain | `pass`; A>B in 9 of 10 and A>C in 10 of 10 sampled comparisons, with both blind-spot controls at zero |
| K5 sampled smoke | 3 modes | expected `operational_failure` in all three; no scientific verdict was produced |
| K6 refusal controls | 3 modes | `pass` in all three; all six refusal codes and seven deletion mutants were caught |

The 18 receipts contain 13 `pass`, two expected `fail`, and three expected `operational_failure` outcomes. No case was rerun to change its outcome. Expected failures count as reproductions, not scientific passes.

Sanitized stdout and outcome were identical across plain, optimized, and warnings-as-errors modes for U01, R01, K1, K5, and K6. This parity applies only to the locked modes, not to K2, K3, or K4, which ran once under the fixed budget.

## Verification

The separate receipt checker returned `chain_valid:true`, 18 receipts, the same outcome counts, and `REFERENCE_REPLAY_COMPLETE`. It recomputed outcomes from stored output bytes, checked all output and receipt hashes, enforced the public file manifest, verified source and lock bindings, and recomputed the summary and parity groups.

All 19 adversarial harness controls passed in each of plain, optimized, and warnings-as-errors Python modes: 57 passing control executions. Development parser failures and the two cancelled development runs remain documented separately. Neither cancelled run is presented as the authoritative replay.

## Limits and open gates

- All K cases used Cave's `smoke` mode. K4's passing smoke result does not establish full-seed or real-data performance.
- K2 and K3 failures are preserved without post-hoc threshold changes.
- K5 remains an operational failure, consistent with the pinned Cave overflow blocker.
- Real-data readiness remains `BLOCKED` by Cave's unresolved plan, mutation-triage, and unbuilt-check gates.
- The POC makes no model-quality, live-model, paid-run, novelty, or cross-repository runtime-interoperability claim beyond this pinned replay.

## Review

Prior independent reviews covered the harness design, adversarial controls, parser corrections, and recorded-output compatibility. The final non-author evidence review returned `APPROVE` for the narrow tooling conclusion and independently recomputed all locked hashes, receipts, output hashes, counts, and parity groups. Its complete commands and findings are in `review/final-evidence-review.md`.

The final review recorded one nonblocking hardening gap: `SOURCE.json.recorded_utc` is format-checked but not bound by the receipt chain or summary digest. The repository, commits, suite root, lock digest, commands, and outcomes remain bound. A future protocol version can bind the complete source hash; this run was not modified after review.
