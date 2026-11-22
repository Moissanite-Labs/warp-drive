# Bounded read-only tokenpage trial — preregistration

UTC plan time: 2026-11-21T21:35:44Z (immediately after source inspection and hashing, before execution).

## Prior-art boundary

Base `81c752406e170e34fc99302538c738a3af88093a` has no studies. Open PRs #1, #5 and draft #13 and their visible reviews were read first. Already-reported tokenizer-waste corrections, stale QA resume behavior, option-order bias, probe saturation, PR #5 data hygiene and PR #13 proper-KL reversal are not targets of this trial.

## Steelmanned executable hypotheses

- H1 (selected): For any added `studies/<name>/`, the base workflow's `scripts/check_studies.sh` invocation either reruns it or fails loudly, so a successful workflow certifies that committed research artifacts reproduce.
- H2 (control): PR #13's intended pure-stdlib research entry point deterministically regenerates its committed JSON and documented SHA-256 despite the harness question.
- H3 (diagnostic): Explicitly naming PR #13's study fails loudly rather than silently skipping it.

Stage-A relational claim: result certification must form an edge `study -> execution -> drift check`; a successful exit with no execution edge is structurally insufficient. Stage-B invariants: `checked_studies == 1` on the clean PR, and a changed tracked result must produce nonzero exit. No coordinate, number-base, or cross-domain claim is involved.

## Falsification criterion

H1 is FALSIFIED if the unmodified PR #13 checkout's no-argument `scripts/check_studies.sh` returns exit 0 while printing `checked 0 studies`. A certified coverage counterexample additionally requires that, in a disposable worktree at the same commit, changing one tracked numeric result field without touching source or tests still gives exit 0 and `checked 0 studies`. H2 is VERIFIED only if the actual intended entry point returns 0 and the regenerated tracked artifact is byte-identical with SHA-256 `b0cba027918e623b6f1169499eb49693aa47bede08c0c58411542bd91c9408f8`.

The result mutation is solely a negative control in `/tmp`; no claim or test source is edited. No network model downloads, credentials, external writes, or paid services.

## Fixed commands / measurements

1. Clean checkout: `scripts/check_studies.sh`; capture stdout/stderr and exit status.
2. Actual research: `python3 -I -B studies/expedition-proper-kl-audit/probe_s2_nullmodem_tokenpage_channel.py`; capture status, SHA-256, and `git diff --exit-code`.
3. Independent replay: repeat intended research under `python3 -I -O -B -W error`; require the same digest.
4. Diagnostic: `scripts/check_studies.sh expedition-proper-kl-audit`; expect nonzero if selection is the issue.
5. Independent mutation oracle: in a second detached `/tmp` worktree, replace only the JSON value `"g1_legend_delta_proper_KL_emp_bits": 1.767` with `9999.0`; confirm exactly one line changed, run the untouched no-argument shell harness, and require detection under H1.
6. Preserve all logs and source/result hashes under `/tmp/tokenpage-harness-trial-20261121/`.

## Environment and immutable inputs

- PR #13 commit: `a694232ecd2dca2b568e7c6dda8d38e3515dcf78`.
- Main inspected commit: `81c752406e170e34fc99302538c738a3af88093a`.
- PR #5 prior-art commit: `4d28be29a306aa3332c79c90294f7402f0ed23f9`.
- `scripts/check_studies.sh`: `f80bf9027cc9b06a6c2b94a247e9fe751a44a7e9d52fa8feeb230cd8bdedfb8b`.
- Research script: `1de89b51523dee7646a6d0ab471a6c71e1e684999b9e3dd1c080e23690dce898`.
- Committed result: `b0cba027918e623b6f1169499eb49693aa47bede08c0c58411542bd91c9408f8`.
- Bundled raw QA: `8cc8f1ce33be37a2d2ece4b5dab0722db5772460478551bb2007d319b0508334`.
- Environment: macOS Darwin 27.0.0 arm64; git 2.54.0; Python 3.14.6; no RNG used by this harness trial.
