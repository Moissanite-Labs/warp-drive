# Preserved incidental inspection failures

## Tokenpage first-pass input-cardinality validation

Command:

```sh
python3 -I -B /tmp/warp-pr20-rereview-evidence/recompute_tokenpage_no_legend.py
```

Return code: 1. The first-pass source is preserved as `recompute_tokenpage_no_legend.attempt1.py`; its stdout, stderr, and return code use the `.attempt1` suffix. The script incorrectly required 952-line raw input to contain exactly 240 total rows before selecting the intended 240 G1 rows. No KL arithmetic ran. The corrected independent script validates 952 total rows and 120 selected rows in each legend cell, then returned 0.

Exact terminal diagnostic:

```text
RuntimeError: expected 240 QA rows, got 952
```

## Static PR15 source-path probe

One compound read-only source-inspection command ended with return code 1 when it attempted:

```sh
git show 1117bbdcd0160bed91d2916161e86698137e12cb:studies/expedition-trust-boundary-verifier/warp_drive_runtime_r5.py
```

Diagnostic: `fatal: path 'studies/expedition-trust-boundary-verifier/warp_drive_runtime_r5.py' does not exist in '1117bbdcd0160bed91d2916161e86698137e12cb'`.

This was an incorrect auxiliary inspection path, not a PR15 test or source failure. The required sandbox and report blobs were read successfully in the same inspection and are hashed in `pr15-staleness.json`. No PR15 code was executed.
