# Ratchet 001 result

Status: `N0`; no promotion and no verifier-improvement claim.

## Frozen inputs and evidence

Note (2026-11-26): `python3 evaluation/run.py verify --run-dir runs/001-baseline` cannot run on this copy (FileNotFoundError for the missing `runs/001-baseline/receipts.jsonl`). The receipt-chain values below are recorded at run time; `runs/001-baseline/receipts.jsonl` is not in this public copy, so they cannot be re-verified here (see `research/PUBLICATION_GAPS.md`).

- Pull request: 21.
- Candidate head: `8031effa7ebcdbec5307dc2809212e1d55601639`.
- Candidate source SHA-256: `4d04687cb70b86a4b91e4661f16d6292b81c4760f60931f9bbf8228ca9dfb15d`.
- Candidate AST SHA-256: `sha256:405746ad9197a70c870cd265653232499f76865d50500bd663a3625cfdf91e81`.
- Final pre-baseline lock commit: `3fea1ed165afd65ffe958388fdc24239c4b4b670`.
- Evaluation tree SHA-256: `95f8f2a374e2ef5253be3b3e3b3c489b0238d0451ddd190f935bc235671b00bf`.
- Baseline evidence commit: `dc4c5f9d07e61cd60e60cd8f2c6d41b4fa8cf677`.
- Summary SHA-256: `6e11daf4f2d64063b21259cc73b5923607f2bb2d93061e07333dae099d816fce`.
- Receipt log SHA-256: `e33481b234e8ddf706cb477c77dd54c79e7dbeb829b4ae104d603228a3e46dcb` — recorded at run time; `runs/001-baseline/receipts.jsonl` is not in this public copy, so this cannot be re-verified here (see `research/PUBLICATION_GAPS.md`).
- Terminal receipt SHA-256: `4f046fbfc2f9a1855c15226d762a09e831e4ab86ea758e2cd0b6a5871078391f` — recorded at run time; `runs/001-baseline/receipts.jsonl` is not in this public copy, so this cannot be re-verified here (see `research/PUBLICATION_GAPS.md`).
- Cases: 44.
- Executions: 132.
- Elapsed: 8,232 ms.
- Cap: 900,000 ms.
- Receipt verification: `{"chain_valid":true}` — recorded at run time; `runs/001-baseline/receipts.jsonl` is not in this public copy, so this cannot be re-verified here (see `research/PUBLICATION_GAPS.md`).

## Counts

- False accepts: 0.
- False rejects: 3.
- Killed invalid inputs: 93.
- Passes: 21.
- Operational failures: 12.
- Independent-reference mismatches: 3.
- Exact mismatches, malformed receipts, timeouts, parity divergences, and wrong-reason outcomes: 0 each.

Every expected-reject case was rejected or failed operationally. There was no surviving expected-reject case for the preregistered H2 improvement route. Adding the blind review’s new bearer attacks to this version would violate the locked-corpus rule.

## Preserved anomalies

- `C03`: all three modes report `reference_mismatch`. The candidate distinguishes canonically equivalent Unicode conversation IDs, while the independent reference applies NFC before clustering. The candidate reports four conversations, three wins, one loss, and lead ratio `13/10`. The reference reports three conversations, two wins, zero losses, and lead ratio `7/3`.
- `C08` and `C09`: all three modes report `operational_failure`. Direct post-blind replay confirms `ValueError` rather than a structured `INVALID_INPUT` rejection.
- `G22`: all three modes report `false_reject`, with `KeyError: 'fused_outputs_rejudged'` on direct replay.
- `G23` and `G24`: all three modes report `operational_failure`, respectively with `KeyError: 'control_requires_bearer_token'` and `KeyError: 'hindsight_fence_escaped'` on direct replay.

`G22` has `fused_serving_artifact=true` but omits `fused_outputs_rejudged`, while its corpus expectation is `admit`. That conflicts with the fail-closed requirement that fused artifacts be rejudged. It is recorded as a v1 corpus-design defect. The baseline is not relabelled, and no candidate should be adapted to admit it.

Direct-replay commands, return codes, stdout, and stderr are preserved in `POST_BLIND_REPRODUCTIONS.json`, with local filesystem prefixes replaced by `<workspace>` for public hygiene. The original artifact digest and redaction boundary are recorded in `PUBLICATION_REDACTIONS.md`.

## Hypothesis disposition

- H1 fails: clean replay includes false rejects and an independent-reference mismatch.
- H2 fails: the fixed corpus has no surviving expected-reject case. No improvement claim is allowed on this version.
- H3 fails for `C03`: candidate output disagrees with the independent NFC-aware reference. This does not invalidate unrelated passing arithmetic checks.
- H4 holds for harness discrimination: the deliberate invalid control is rejected by construction tests, and the baseline records zero false accepts. This is not a candidate-quality claim.
- H5 is untested: there is no adapted candidate.

## Next portal

The post-baseline blind review found lowercase and short bearer-credential admission bypasses outside the locked corpus. Those findings, structured handling of omitted fields, the NFC reference mismatch, and the corrected missing-attestation semantics require a separately preregistered ratchet 002 evaluation. No v1 file is modified to fit those findings.
