## Request changes: digest ordering check fails open

At head `8ae84b7`, `check_config_digests` tracks proposal and digest values but never records the position of an `evaluated` event (`tools/lane7_verify/verify.py:380-419`). It can therefore report before-evaluation binding for a log that evaluated first.

I constructed a three-entry receipt log with this exact event order:

```text
candidate_proposed -> evaluated -> candidate_digest_recorded
```

The candidate config digest, sequence numbers, previous-entry links, and entry hashes all recompute. I generated those hashes independently with `hashlib.sha256`, not with the verifier's helper.

Observed on the pinned head:

```json
{
  "receipt_log": "VERIFIED",
  "config_digests": "VERIFIED",
  "config_evidence": "The digest recorded before evaluation matches the proposed digest"
}
```

Four isolated replay modes produced byte-identical output with SHA-256 `2972970c7f45a331e914a513f6f9ca6caaa7a9b47d078c34681a6cdd51d32dd8`.

### Required repair

Track evaluation order per candidate. Reject a digest first recorded after evaluation. If no evaluated event exists, do not claim before-evaluation binding. Add this out-of-order log as a must-fail regression test and retain the existing tamper controls.

### Other verification

The declared pytest suite collected 19 tests: 18 passed and 1 contract-dependent test skipped. The repository baseline ran 58 tests: 57 passed and 1 optional live-GGUF test skipped. `git diff --check` passes. Those suites did not cover this witness.

This is a verified local verifier defect, not evidence about a live model or runtime.
