# Cave four-transformations POC

This directory binds warp-drive's receipt discipline and Aletheia v2's research rules to Cave Expedition's four-transformations known-answer suite. It replays the untouched Cave code at one pinned commit. It does not modify Cave, open real data, call a model, or repair a failing test.

## Deliverables

- `PREREG.md`: fixed question, inputs, budget, expected outcomes, and decision rule.
- `cases.json`: locked 18-case-mode matrix.
- `LOCK.json`: source hashes and target binding.
- `evaluation/`: runner, receipt checker, lock writer, and adversarial controls.
- `runs/run-001/`: sanitized outputs, hash-chained receipts, and measured summary.
- `RESULTS.md`: results and limits, written after verification.
- `review/`: independent review and advocate ruling.

## Reproduce the controls

From this directory, with Python 3.14.6 and numpy 2.5.4:

```bash
python3 -I -B evaluation/test_harness.py
python3 -I -O -B evaluation/test_harness.py
python3 -I -B -W error evaluation/test_harness.py
```

Do not regenerate `LOCK.json` when checking the recorded run. The lock writer exists for a new protocol version, not for making changed sources match old receipts.

## Verify the recorded run

Use a clean Cave checkout at `a714ef7981421266bea78e8357d61f3586f0eda0`:

```bash
python3 -I -B evaluation/check_receipts.py \
  --target /path/to/cave-expedition \
  --run runs/run-001
```

Verification reads the saved bytes and receipts. It does not rerun Cave's expensive tests or trust the saved summary.

## Execute a new replay

A new replay requires a new empty output directory. It runs 18 case-mode pairs sequentially and may take tens of minutes. K4 alone has a locked 40-minute timeout. Expected failures count as reproductions only when their exact process outcome matches the locked expectation.

```bash
python3 -I -B evaluation/run.py \
  --target /path/to/cave-expedition \
  --output runs/run-002
```

The target worktree must stay clean. The runner refuses a different Cave commit, a changed locked file, a different Python or numpy version, or an existing output directory.

## Evidence boundary

The result is `N0`, with evidence class `reference_replay`. Smoke tests are not full scientific results. Reproducing K2 and K3 failures and the K5 operational failure does not falsify the broader research direction. Passing K4 does not establish real-data performance. Real-data readiness remains blocked by Cave's own unresolved gates.
