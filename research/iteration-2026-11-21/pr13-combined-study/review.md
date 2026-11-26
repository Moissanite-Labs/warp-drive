## Request changes: adversarial callbacks break hash, policy, and egress boundaries

Reviewed head `1ffda956d76745e61c53aff0e727036069fb13ec` in a clean detached checkout. All published verification commands passed, but four of seven independent adversarial probes failed. The first three contradict core trust-boundary claims.

### 1. Runtime can replace the adapter hash after pre-evaluation validation

At `studies/expedition-bounded-controller/bounded_controller.py:591`, `:623-626`, and `:657-659`, `evaluate()` checks the supplied live hash, then gives the runtime the mutable internal candidate record. The runtime can replace `candidate_adapter_sha256` before the evaluation receipt is signed.

Witness: `AdversarialReview.test_01_pre_evaluation_hash_survives_runtime_callback`.

Observed:

- Bound SHA: `7dc4d8166cec58672c733e167e0b729be3d0c9ee2c1da5a6d44cf65fdb78830e`.
- Runtime-substituted SHA: `ec4e65b6674e9d74b267d6844125358de8caebe28ac7e7ea68a7a9fe41db8bef`.
- Verdict: `PROMOTED`.
- Signed chain verification: `valid=True`, 4 records.

The chain signs the substituted value correctly. It does not preserve the original binding.

### 2. Compiler can mutate frozen thresholds and promote an under-threshold candidate

At `experiment_contract.py:376` and `bounded_controller.py:580`, `:644`, `:695`, and `:705`, manifest handling is shallow and the compiler receives the live nested manifest without an immutable snapshot or post-callback digest check.

The adversarial compiler changed `min_task_exact_gain` from `[1,20]` to `[-100,1]`. A candidate with `task_exact_gain=[0,1]` then returned `PROMOTED`. The stored manifest SHA remained `18281c6db1641b3361a7d4e116331bc3cd616b6049705b2ebb9e864f1e273740`, while recomputation after the callback gave `e00de7156d6cf568bbd83be5e0dde2cdbfe9aa32d3b1a91eb2a65620258f6a1f`.

Witness: `AdversarialReview.test_02_compiler_cannot_change_frozen_acceptance_policy`.

### 3. Provider egress denylist permits raw adapter bytes under an alias

At `bounded_controller.py:100-116`, `:815-824`, and `:1051-1064`, the sanitizer blocks selected key names but does not constrain `failure_report` to fixed measurements.

A mocked failure report containing `adapter: [0,1,2,255]` reached transport unchanged instead of raising `ERR_EGRESS_POLICY_VIOLATION`. No provider was contacted. This disproves the sanitizer's fixed-text-and-metrics boundary for arbitrary report keys.

Witness: `AdversarialReview.test_03_provider_egress_rejects_raw_adapter_alias`.

### 4. Malformed provider metadata escapes without a rejection receipt

At `bounded_controller.py:947-950`, `prompt_tokens="not-an-integer"` raises `ExperimentContractError` before receipt creation. The mock client recorded zero receipts, contradicting the README claim that failures receive rejected or error receipts.

Witness: `AdversarialReview.test_04_malformed_provider_metadata_records_rejected_receipt`.

### Verification evidence

- Four isolated study modes produced byte-identical output SHA-256 `2245d5bb9ebbab07afc54c7b11c40317ac789634de4018991e35cc927c590499`.
- R5 passed 6 of 6 groups in all four isolated modes.
- Repository baseline ran 58 tests with 57 passes and 1 optional live-GGUF skip.
- Aletheia `audit-check` passed with 7 files scanned, zero bare asserts, zero syntax or JSON errors, and both R4 scripts passing.
- The committed and standalone certificate canonical digests both recompute correctly. The standalone certificate omits the compatibility section, so its different canonical value is expected.
- Adversarial suite: 7 tests, 3 passed and 4 failed. Passing controls rejected nested duplicate JSON keys, caller adapter mismatch before runtime, and a missing rollback flush.
- Witness source SHA-256: `051fe6b375851437651e21761b0d00dc113f867fa51b82b5bac28b66d0be7cfd`.
- Both available checks report `SUCCESS`: `Analyze (python)` and `CodeQL`.

These tests establish defects in fake-runtime and mock-transport control flow. They are not evidence about live model quality, a physical GPU checkpoint, or a real provider.
