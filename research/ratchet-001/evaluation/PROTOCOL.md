# Evaluation protocol v1

The evaluator is independent of the verifier under test. It records integer outcomes only. Clean inputs must pass. Every invalid input must be rejected with a nonzero exit or an explicit machine-readable rejection. A script that returns success without checking the requested input is a false accept, not a passing test.

Run validation paths under `python3 -I -B`, `python3 -I -O -B`, and `python3 -I -B -W error`. LF-only source and canonical JSON receipts are required. No bare Python `assert` is accepted as a validation gate. Hash the locked tree before baseline and again before candidate scoring. Receipts are chained in execution order by SHA-256.
