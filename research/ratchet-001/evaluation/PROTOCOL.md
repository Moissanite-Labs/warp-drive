# Evaluation protocol v1

The evaluator is independent of the verifier under test. It records integer outcomes only. Clean inputs must pass. Every invalid input must be rejected with a nonzero exit or an explicit machine-readable rejection. A script that returns success without checking the requested input is a false accept, not a passing test.

Run validation paths under `python3 -I -B`, `python3 -I -O -B`, and `python3 -I -B -W error`. LF-only source and canonical JSON receipts are required. No bare Python `assert` is accepted as a validation gate. Hash the locked tree before baseline and again before candidate scoring. Receipts are chained in execution order by SHA-256.

The fixed corpus contains 44 cases: 26 governance cases, 15 clustered-gate cases, and three exact-gradient cases. Every case runs once in each R4 mode, for 132 executions per arm. Mode counts and case-parity divergences remain in the summary. A crash on an expected-reject case is an operational failure, not a kill.

Each request is materialized before execution. The adapter decodes only canonical exact-rational objects and invokes the target's exported functions. The independent scorer recomputes clustered-gate and gradient expectations without calling the candidate. Governance expected reasons are locked in `corpus.build.json`. Raw observations are retained separately from the hash-chained receipts.

`FRAMEWORK_PIN.json` binds the Aletheia commit and module digest. `LOCK.json` binds every evaluator, protocol, pin, corpus generator, and audit file. `SOURCE.json` in each run binds the candidate repository and commit. Baseline and candidate arms share a 900000 ms execution cap and a 30-second per-case timeout.

Baseline results must be committed before candidate adaptation. The Goodhart latch then requires a blind raw-source review that does not receive baseline scores or candidate hypotheses. No improvement, novelty above N0, production readiness, or model-quality claim follows from this local exact-arithmetic corpus alone.
