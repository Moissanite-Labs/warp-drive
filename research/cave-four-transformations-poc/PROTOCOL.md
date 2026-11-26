# Replay and receipt protocol

## Inputs

`run.py` accepts a Cave checkout and a new output directory. It reads no case selection, threshold, expected verdict, timeout, or mode from the command line. Those rules come only from the locked `cases.json`.

The runner checks the exact Cave commit, clean target worktree, Python and numpy versions, and every hash in `LOCK.json`. It refuses to write into an existing run directory.

## Execution

Cases execute sequentially in their locked order. Each case runs from the Cave target root with an environment that removes credentials and user Python paths. Output is captured as UTF-8 with replacement for invalid bytes. Local checkout, run, home, and Python installation paths are replaced by placeholders before output is stored. The number of replacements is recorded.

A process outcome is classified as follows:

- `pass`: return code zero and the locked pass condition is present. A K test must end with its own unique `SUMMARY <id> SMOKE PASS` line. R01 ends with one exact, unique locked marker line. U01 ends with its unique count marker followed by the separate exact line `PASS`, matching its target source.
- `fail`: return code one and the K test ends with its own `SUMMARY <id> SMOKE FAIL` line.
- `operational_failure`: nonzero return code without a valid summary, a timeout, or an inconsistent return code and summary.
- `protocol_error`: invalid runner setup, target state, or receipt data.

The observed outcome is compared with the locked expectation. Both values are stored. A failure expected from the recorded Cave smoke run is a matching replay, not a pass.

## Receipts

Each case-mode run appends one canonical JSON object to `receipts.jsonl`. Receipts contain only strict JSON types. Floating-point numbers and duplicate object keys are rejected. Every receipt contains:

- sequence number and previous receipt digest.
- case, mode, locked command, timeout, and oracle class.
- return code, elapsed integer milliseconds, and observed and expected outcomes.
- SHA-256 digests of sanitized standard output and standard error.
- Cave target commit and POC lock digest;
- redaction count and its own digest.

`SUMMARY.json` binds the final receipt digest, measured outcome counts, parity groups, and overall replay status. `SOURCE.json` binds public source URLs and commits. No summary field substitutes for the stored output bytes.

## Verification

`check_receipts.py` reloads strict JSON, verifies the POC lock, target commits, command and rule bindings, sequential hash chain, file hashes, and summary terminal digest. It reparses each stored output to recompute the outcome and compares it with the receipt. It also recomputes counts and checks the 18 locked case-mode entries. A missing, extra, reordered, changed, or mislabeled record fails verification.

The verifier requires the exact public run-file manifest. An unlisted file, nested directory, symbolic link, or extra `SOURCE.json` field fails verification. Every public file is scanned for local-path and attribution patterns. This scan supplements runner redaction. It does not prove that arbitrary prose is safe to publish, so final evidence still requires a separate hygiene review.

Parity means identical sanitized standard output and identical observed outcome across the modes locked for that case. Standard error may differ when warnings mode changes the error path. The K5 error remains an operational failure in each mode.

## Harness controls

`test_harness.py` checks strict JSON, false acceptance, missing summaries, return-code mismatches, timeouts, target lock failures, digest tampering, extra receipts, redaction, and the no-bare-assert rule. Controls run under plain, optimized, and warnings-as-errors Python modes. A passing scientific case is not required for these tooling controls.

## Scope

The POC uses reference replay. It does not establish that Cave's statistical method is correct, that a known-answer smoke pass generalizes to full seeds or real data, or that warp-drive improves model research. It demonstrates that warp-drive can bind an external frozen research suite to fixed compute and verifiable evidence while preserving negative results.
