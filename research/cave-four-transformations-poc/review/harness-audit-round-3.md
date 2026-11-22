# Independent delta review: actual-output regression

An independent reviewer who did not author the replay runner reviewed lock `9f1c5cd103696d342b2b152de8058cde278e371d980526b5db6e3e08946f6466`. The review approved an N0 replay in a new empty output directory. This ruling covers tooling only and makes no scientific claim.

## Verification performed

- All seven locked source hashes matched.
- `cases.json` hashed to `d8616d8708ea98c5b4704964ecdcde0d3e3bc11e17e66d6741fc6d29d5ba66d0`.
- `evaluation/run.py` hashed to `539c99d0cada9d8de84da79232f40ef725a5acfc9d8bd99bce78aa92767b64c8`.
- `evaluation/test_harness.py` hashed to `fc6fad7e6b24cd62463a20b4a149108187e76b6c054d149a8148b46e2bfb6b5b`.
- The pinned Cave worktree was clean at `a714ef7981421266bea78e8357d61f3586f0eda0`.
- All 19 controls passed in each of three modes: plain, optimized, and warnings-as-errors. There were 57 passing control executions.

## Actual U01 regression

The saved output from the second cancelled development run, with return code zero, now classifies as `pass`. Its terminal lines are the unit count marker followed by `PASS`. The marker occurs exactly once. Its stdout SHA-256 is `d7d821ec42397cb937fa1978ba3901691076c5fd56c3ad930011dd449851ad04`. Empty stderr has the standard empty SHA-256. The historical receipt digest recomputes correctly.

That receipt remains evidence of the false reject under the old parser and old lock. It is not a complete replay under the new lock. Pinned Cave source confirms the separate `PASS` print for U01 and the terminal `UNGUARDED: none` success marker for R01.

## Adversarial probes

Ten probes passed in each of the three modes, for 30 passing probe executions. The probe payload SHA-256 was identical across modes: `a374ab7e91e61c9ad09df0624e73944c0981df7e4586fc929dc71487e274122a`.

The review confirmed:

- U01 and R01 trailing failures and duplicate markers reject.
- A synthetic baseline verifies with 18 receipts: 13 `pass`, two `fail`, and three `operational_failure`.
- Its three U01 outputs have the exact marker-plus-`PASS` terminal shape.
- A rebuilt-chain attack across nine mutated outputs rejects on recomputed outcome.
- Python installation paths redact to `<python-home>`. Framework-library paths are rejected by the public-boundary scan.
- Unlisted public files and extra `SOURCE.json` fields still reject.

No Cave target case ran during this review. No model or paid run occurred. The reviewer made no GitHub write and changed no POC or Cave file.
