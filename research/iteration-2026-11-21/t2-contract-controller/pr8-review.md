## Executable trial evidence, comment only

Reviewed head `f9c9acce18434262bded9dd6263f46b80f6b89b1` against base `38a7072f8d23fe865b4d48d1da285a6db4fc14d1` in a fresh detached checkout.

The independent executable review returned `APPROVE` within its standalone contract scope:

- 11 focused contract tests passed.
- 65 repository tests passed with 30 subtests. The optional live test was excluded.
- Deterministic suite regeneration reproduced all four committed files byte-for-byte.
- Generated SHA-256 values were `f6381b6a076f9f9bd15128e53ad1b6165bb19e418feb1fada7d63594c672ca0c` for the split-leakage audit, `18f12069c1717b7bbe1d6cae37512a5c1e338a4a42836428b04665628fae7509` for the task suite, `0fc73d13c14a9673f20337b621dcef0dfbd625501329a190c9500e5fe74fc034` for IID retention, and `4bff6104d768ac922e3f6539856456f208f0fa882320886145a54c6c0b1c1249` for shifted retention.

This comment does not supersede the earlier margin-rule wording anomaly. That contract prose remains a merge concern even though the executable gate and regeneration checks pass. I am therefore recording test evidence without adding an approval.

These are deterministic contract and mock-boundary results. They are not live model or weight-iteration evidence.
