# Ratchet 001 evaluation audit log

## Pre-lock construction checks

No baseline or candidate corpus execution occurred during harness construction.

1. The first shell invocation used scalar flag expansion and failed at the Python interpreter with `Unknown option: -` (exit 2). It was replaced by explicit argv commands; this was not a verifier result.
2. The generated corpus contained 44 cases. The harness expectation was corrected from 43 to 44.
3. The first substantive self-test found governance mutants without a default `expect` label, an incorrect package root for Aletheia relative imports, and two incorrect harness expectations. The arithmetic expectation was corrected to the reduced rational `-2/25`. NFC normalization merges the confusable pair, so its net-zero cluster is not a loss. The corpus generator, loader, and self-test expectations were repaired before lock.
4. After those repairs, the pinned-package root was still one directory too high. It was corrected to the directory containing `aletheia/__init__.py`.
5. Ten self-tests passed under each of `python3 -I -B`, `python3 -I -O -B`, and `python3 -I -B -W error`. These tests validate harness controls, not the candidate.
6. Corpus generation was deterministic. Corpus SHA-256: `c82b509f4c2f91e5f672353f483a7641c19440cb9fe4bbdb8863fe40e77a3f7d`.
7. Aletheia's pinned module is execute-time checked against SHA-256 `233d8e4a6e57624407f991446c2d80876677905e558fe0815084c44deb6004b7`, from PR 1 head `1513e0f3322cf0c9899b92732f656e14a87e9b41`.

## Pre-baseline lock repair

Locked tree `f25c85e65da1585fc590dc1b6cf393ebd5b66fdccf6815d9a42b077cbc621961` never executed a candidate case. The first invocation used a relative run path and stopped at the runner's path precondition. The second, absolute-path invocation stopped while loading the corpus because receipt-only float rejection was incorrectly applied to deliberate wrong-type input attacks. No requests, observations, receipts, or candidate summary were created.

The harness was repaired before baseline execution to distinguish duplicate-safe request JSON from float-free receipt JSON. The corpus, candidate, expected labels, scoring rules, and compute caps were not changed. The v1 lock remains in Git history and under the baseline's setup-failure records. This is a harness repair, not a candidate adaptation or a measured result.
