# Preregistered adversarial integration tests

Scope: PR #8 head f9c9acce18434262bded9dd6263f46b80f6b89b1 as the contract dependency of PR #10 head c526b8d3d73d018bb159312a9cf63adfc80e324d. Tests will be run only against fresh detached /tmp checkouts/worktrees, including a synthetic combined tree. No implementation has yet been inspected.

For each test, record PASS, FAIL (minimal reproduction and exact location), or BLOCKED (missing capability/test seam). Existing tests do not satisfy these tests unless they explicitly exercise the named adversarial condition.

1. Contract drift (`contract_drift`):
   - Compare every PR10 contract call/import/fixture against PR8's exact exported signatures, field names/types, defaults, errors, and receipt schema.
   - Execute a PR10 controller/scoring path in the combined tree; fail on unresolved imports, keyword/positional signature mismatch, schema mismatch, or reliance on unchanged legacy behavior.
2. Candidate hash before scoring (`candidate_hash_before_scoring`):
   - Instrument or wrap candidate preparation/scoring with ordered events and a different candidate payload.
   - Assert canonical candidate bytes/hash are fixed before any model/scoring call and that the hash/scored candidate match; mutation after hashing or scoring before commitment fails.
3. Caller acceptance-policy override attempts (`caller_acceptance_policy_override`):
   - For every caller-controlled acceptance/config/policy argument, request rejection while attempting permissive caller policy/threshold overrides, including direct keyword and nested dict/object variants where supported.
   - Assert the callee's authoritative acceptance policy cannot be weakened; fail if caller values bypass required acceptance checks.
4. Rollback semantics (`rollback_semantics`):
   - Force failure at/after the critical state transition and inspect all prior writes/state.
   - Assert failure restores the pre-call committed state (or the explicitly documented transactional state), emits no success receipt, and leaves no partial candidate/acceptance artifacts; silent best-effort deletion or swallowed rollback errors fail if they permit false success or divergent state.
5. Receipt append-only/hash-chain failure (`receipt_append_only_hash_chain`):
   - Append valid receipts and verify hash linkage.
   - Attempt in-place mutation, deletion/truncation, duplicate/conflicting append, stale-parent append, and tampered receipt payload where the API/filesystem seam permits.
   - Assert each invalid operation is rejected or detected and no invalid receipt is accepted as committed; fail on overwrite, silent chain reset, hash omission, unchecked tail assumption, or verification of only the latest record.

Verdict rule: APPROVE only if no concrete correctness/security defect is found in the pinned diff and required tests pass. REQUEST_CHANGES for at least one reproducible defect, with the narrowest failing input and file/line reference. A test-harness limitation alone is not attributed to the PR.
