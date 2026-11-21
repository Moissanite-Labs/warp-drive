# Iteration 1: preregistered empirical trials

Date: 2026-11-21
Base: `38a7072f8d23fe865b4d48d1da285a6db4fc14d1`
Method: Foundation-0/aletheia PR 1, head `58207b422ca31c29bb498bc7aebb2ebc4f1fe41c`

## Purpose

Use the project rather than extend its theory. Test the open weight-iteration lanes and search for reproducible findings in other organizations. Do not call a run successful because the methodology or a mock harness passes.

## Decision rules

- A tooling check verifies only the named tool at the pinned commit.
- A research finding needs a predefined falsifier, execution against real repository code or data, an independent replay, and a reproducible receipt.
- Mock compilers, runtimes, and providers establish control flow only. They are not weight-programming evidence.
- `VERIFIED` means verified within the stated test scope. It does not imply scientific novelty, merge approval, or live deployment.
- Classify novelty as `N0`, `N1`, or `N2` only after checking the target repository and relevant prior work. Default to `N0` when that comparison is incomplete.
- Retain failed trials, environmental blockers, and contradictions. Do not delete them from the final ledger.

## Trials

### T1: Aletheia executable baseline

Claim: Aletheia v1.3 runs on this host, not merely describes a protocol.

Falsifier: any of the four isolated Python modes fails, gives different canonical results, or leaves a mutation-test survivor.

Scope: Framework PR head `58207b4`, Python 3.14.6. This establishes `N0` tooling reproducibility, not a research result.

### T2: Frozen contract and bounded controller integration

Sources: warp-drive PR 8 at `f9c9acce18434262bded9dd6263f46b80f6b89b1` and PR 10 at `c526b8d3d73d018bb159312a9cf63adfc80e324d`.

Falsifiers:

1. A drifted contract or checkpoint is accepted.
2. Scoring can occur before the candidate digest is recorded.
3. Caller-supplied thresholds or raw LoRA overrides bypass frozen policy.
4. Rollback reports success without the required full state flush or baseline restoration.
5. Receipt omission or mutation goes undetected.
6. The simulated merged heads fail their combined test suite.

A non-author reviewer independently executes the tests and adversarial cases. Any resulting review concerns behavior at these heads. It does not prove live weight iteration.

### T3: Cerebras client boundary tests

Source: warp-drive PR 9 at `bf8de4b0e3f0451a496a76d87a537003b3377931`.

Falsifiers:

1. An invalid proposal, comparison, or diagnostic escapes schema validation.
2. Retry or timeout behavior exceeds its declared bound.
3. Provider receipts expose prompts, credentials, or private content.
4. Served-model substitution passes unnoticed.
5. Existing repository tests regress.

No paid request or new credential is authorized by this trial. No stored `CEREBRAS_API_KEY` or environment key existed at preregistration. If no authorized key appears during the run, record the live path as `UNVERIFIED` and stop at mock boundary tests.

### T4: Tokenizer empirical trial

Target: Moissanite-Labs/tokenpage, at a source commit recorded by the executor.

Protocol: inspect the existing code, data, and open proposals. Select one active executable claim and preregister its exact local falsifier before measuring. Execute the real repository input, then independently replay any candidate finding.

Falsifier: the selected claim does not reproduce, or a new claimed boundary disappears under an untouched-input replay or matched control.

No writes to tokenpage are authorized in this iteration. A useful outcome is a verified local advance with a minimal witness. A negative result remains a trial result but is not a successful research finding.

### T5: Exact spectral cross-oracle trial

Target: Foundation-0/spectral-inertia, at source commits recorded by the executor.

Protocol: choose an unresolved executable seam. Run exact integer or `Fraction` inputs through the target implementation and compare any candidate result against an independent arithmetic path. Include negative controls and optimizer-isolated replay.

Falsifier: the candidate counterexample or bound does not survive independent exact evaluation, or the same result already exists in the inspected target revision.

The merged Bareiss study may serve as a second arithmetic implementation. Shared validation or formulas limit oracle independence and must be disclosed.

### T6: Residual merged-study follow-up

Source: the merged Bareiss study at base `38a7072`.

Observed lead, not yet a finding: the approval review questioned the naive LDL diagnostic on a zero pivot.

Falsifier of the suspected defect: calling the naive diagnostic on a valid singular PSD matrix returns a well-defined comparison result without silently treating the factorization as complete.

If reproduced, classify the defect narrowly. A diagnostic failure is not evidence that the primary Bareiss certificate accepts an invalid matrix. Any repair must preserve the pinned study measurements or record and explain a changed digest.

### Evidence already collected before this latch

Aletheia's four self-test modes each passed 13 tests and killed 13 of 13 tested mutants with byte-identical output. This was tool validation before target selection, not outcome data for T2–T6.

The host reports an Apple M1 Max GPU. No CUDA device, pinned GGUF checkout, or usable Cerebras repository credential has been established. Claims that require those inputs remain open.
