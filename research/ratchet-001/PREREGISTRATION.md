# Ratchet 001 preregistration

Date: 2026-11-22. Goal: `50ecb3c8-72be-4790-99c7-0b24a6c90900`.

## Real task and fixed inputs

Pilot warp-drive on pull request 21, head `8031effa7ebcdbec5307dc2809212e1d55601639`, base `38a7072f8d23fe865b4d48d1da285a6db4fc14d1`. Current main at preregistration is `10b54c8020aec294917ee7c118cc33da0c071691`; it is recorded separately and is not silently substituted for the pull-request base.

The task is to audit the Latent Lattice and Songe governance studies against their actual source, certificates, tests, reports, and pinned upstream references. PR titles and CI are not evidence of correctness.

## Steelmanned hypotheses

- H1: the clean studies and certificates replay under isolated normal, optimized, and warnings-as-errors modes.
- H2: at least one independently authored invalid input or omitted certificate field survives the baseline verifier. A candidate should close that gap without rejecting the clean input.
- H3: exact mathematical claims can be checked with integer or rational arithmetic and at least one independent oracle. Failure to fetch an upstream reference limits the affected claim; it does not invalidate unrelated local checks.
- H4: a fixed adversarial corpus can rank verifiers with integer counts, without training on the verifier or changing the evaluation harness.
- H5: a repair should generalize to an input class, not recognize a particular certificate hash or fixture value.

Novelty starts at `N0`. Neither a draft pull request nor an unreviewed script is a merged tool capability.

## Locked evaluation design

After this plan commit, an independent harness and adversarial corpus will be committed before the baseline run. Its tree SHA-256 will be recorded. Candidate branches may add verifier code and reports but may not edit `evaluation/` or delete adverse receipts.

The harness will include clean inputs, must-fail mutations, omitted fields, wrong types, and independently recomputed exact values. The corpus is fixed before comparing arms. Any later new case starts a new evaluation version and cannot be used to claim improvement on this version.

Per-arm cap: 15 minutes of verifier execution on the same host. The cap includes clean and adversarial cases. Development and human review time are reported separately and are not scored.

Integer metrics, compared in this order:

1. false accepts of invalid inputs: must be zero for promotion;
2. false rejects of clean inputs: must be zero for promotion;
3. killed invalid inputs: candidate must exceed baseline on the same fixed corpus;
4. elapsed whole milliseconds: tie-break only within the same cap.

Timeouts, crashes, malformed receipts, and omitted output count against the verifier. There is no averaged score that can hide a false accept.

## Ratchet gates

1. **Immutable harness:** the loop cannot edit the locked `evaluation/` tree.
2. **Hash-chained receipts:** canonical JSON contains integers, strings, booleans, arrays, and objects only. Floats are forbidden. Each receipt records the previous receipt SHA-256, or null for the genesis receipt.
3. **AST-identity null rejection:** an unchanged candidate is rejected. Canonical AST digests are recorded for changed Python verifier files.
4. **Pre-adaptation Goodhart latch:** after baseline, preserve results and halt adaptation until a fresh blind reviewer re-enters the raw pull-request sources without baseline scores or candidate hypotheses.
5. **Fixed compute:** both arms receive the same 15-minute execution cap and corpus.

A result missing any gate is an experiment, not a ratchet result. Verification oracles remain external to model weights. No paid provider or live model call is planned.

## Falsification and promotion

H1 fails if any clean replay diverges or errors. H2 fails if the fixed corpus has no baseline survivor; in that case no improvement claim is allowed and a new portal must be opened instead. H3 fails for a claim when independent arithmetic disagrees; upstream inaccessibility yields an explicit bounded verdict. H4 fails if the harness cannot distinguish a deliberately invalid control. H5 fails if the candidate only special-cases known values.

Promotion requires zero false accepts and false rejects, more kills than baseline, identical clean replay under all R4 modes, full public hygiene, and a non-author executable review. Otherwise the result remains on a research branch with its failure preserved.
