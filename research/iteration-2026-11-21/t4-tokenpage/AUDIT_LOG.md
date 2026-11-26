# Tokenpage bounded empirical trial — audit log

## Verdict

**FALSIFIED — N1 (local, reproducible integration defect).** At PR #13 commit `a694232ecd2dca2b568e7c6dda8d38e3515dcf78`, the repository's green no-argument study workflow does not execute the added study or detect drift in its committed result. This falsifies result-certification coverage, **not** PR #13's numerical research: the intended research script independently replayed twice with the documented digest and zero diff.

Prior-art scan covered main `81c752406e170e34fc99302538c738a3af88093a`, open PRs #1/#5/#13 and visible issues/review comments. No visible prior comment identifies this PR #13 harness-coverage gap. N1 is deliberately local; no global novelty claim.

## Preregistration

`PREREGISTRATION.md` SHA-256 `dc0fec6f25b72d1b18d12fa77fa26072f1e35bf8529be2cd849b3aad11904144`, written before execution. Falsification required exit 0 plus `checked 0 studies` on clean PR #13 and successful exit after a one-field tracked-result corruption in a separate disposable worktree. The numerical control required two executions to reproduce `b0cba027918e623b6f1169499eb49693aa47bede08c0c58411542bd91c9408f8` with no diff.

## Inputs and environment

- Research commit: `a694232ecd2dca2b568e7c6dda8d38e3515dcf78` (open draft PR #13).
- Underlying PR #5: `4d28be29a306aa3332c79c90294f7402f0ed23f9`.
- Harness SHA-256: `f80bf9027cc9b06a6c2b94a247e9fe751a44a7e9d52fa8feeb230cd8bdedfb8b`.
- Research script SHA-256: `1de89b51523dee7646a6d0ab471a6c71e1e684999b9e3dd1c080e23690dce898`.
- Raw QA SHA-256: `8cc8f1ce33be37a2d2ece4b5dab0722db5772460478551bb2007d319b0508334`.
- macOS Darwin 27.0.0 arm64; git 2.54.0; Python 3.14.6. No RNG, model downloads, credentials, paid services, or external writes.

## Exact commands and results

From `/tmp/tokenpage-pr13-a694232`:

```bash
scripts/check_studies.sh
```

Output: `skip studies/expedition-proper-kl-audit: no measure.py and requirements.txt`; `checked 0 studies`; exit **0**. This is the workflow's no-argument invocation.

```bash
python3 -I -B studies/expedition-proper-kl-audit/probe_s2_nullmodem_tokenpage_channel.py
shasum -a 256 studies/expedition-proper-kl-audit/probe_s2_nullmodem_tokenpage_results.json
git diff --exit-code
```

Research exit **0**; digest `b0cba027918e623b6f1169499eb49693aa47bede08c0c58411542bd91c9408f8`; diff exit **0**.

```bash
python3 -I -O -B -W error studies/expedition-proper-kl-audit/probe_s2_nullmodem_tokenpage_channel.py
shasum -a 256 studies/expedition-proper-kl-audit/probe_s2_nullmodem_tokenpage_results.json
git diff --exit-code
```

Independent interpreter-mode replay: research exit **0**, identical digest, diff exit **0**.

```bash
scripts/check_studies.sh expedition-proper-kl-audit
```

Output: `error: ... has no measure.py and requirements.txt`; `failed: expedition-proper-kl-audit`; exit **1**. The checker fails loudly when named; silent zero coverage occurs only in the workflow's automatic discovery path.

From `/tmp/tokenpage-aletheia-20261121`, create the independent negative-control worktree:

```bash
git worktree add --detach /tmp/tokenpage-pr13-mutation a694232ecd2dca2b568e7c6dda8d38e3515dcf78
python3 - <<'PY'
from pathlib import Path
p = Path('/tmp/tokenpage-pr13-mutation/studies/expedition-proper-kl-audit/probe_s2_nullmodem_tokenpage_results.json')
s = p.read_text(encoding='utf-8')
old = '"g1_legend_delta_proper_KL_emp_bits": 1.767'
new = '"g1_legend_delta_proper_KL_emp_bits": 9999.0'
if s.count(old) != 1:
    raise SystemExit(f'expected one target value, got {s.count(old)}')
p.write_text(s.replace(old, new), encoding='utf-8')
PY
cd /tmp/tokenpage-pr13-mutation
git diff --stat
./scripts/check_studies.sh
git diff --quiet -- studies/expedition-proper-kl-audit/probe_s2_nullmodem_tokenpage_results.json
```

Only one result line changed; no claim/test source changed. Harness output again `checked 0 studies`, exit **0**. `git diff --quiet` exit **1**, independently confirming that drift remained present and undetected.

From `/tmp`:

```bash
python3 -I -B /tmp/tokenpage-harness-trial-20261121/independent_audit.py
python3 -I -O -B /tmp/tokenpage-harness-trial-20261121/independent_audit.py
python3 -I -B -W error /tmp/tokenpage-harness-trial-20261121/independent_audit.py
```

Zero-shared-code audit independently recomputed the changed quantity from all 240 paired G1 QA rows:

- without legend: `-6.651419738969508` bits;
- with legend: `-4.8844556181300325` bits;
- published rounded-cell delta: **`1.767` bits**;
- mutated value **`9999.0`** is therefore a genuine numerical contradiction, not an unused metadata edit.

All three audit modes produced JSON SHA-256 `26e668c23c56761546c25343656e53d7e0c7fff7a86b530f204552878310bb1e`. Audit script has zero bare asserts, zero CRLF, and exits nonzero on check failure. Original PR #13 worktree and main checkout remained clean.

## Resonance / bounded repair

The anomaly is a broken certification edge, not a numerical anomaly: PR #13 supplies `probe_s2_nullmodem_tokenpage_channel.py` but no `measure.py` and `requirements.txt`, while automatic discovery silently skips such directories. The smallest PR-local repair is a conventional `measure.py` entry point (which may delegate to the existing probe unchanged) plus a pinned or empty `requirements.txt` as appropriate, followed by deliberately mutating a result to prove nonzero CI failure. A repository-level alternative is to make unrecognized nonempty `studies/*` directories fail instead of skip, but that broadens scope and was not tested here.

## Publication-ready receipt

> **FALSIFIED / N1-local — tokenpage PR #13's green study check executes zero studies.** At `a694232ecd2dca2b568e7c6dda8d38e3515dcf78`, the unchanged workflow command exits 0 with `skip studies/expedition-proper-kl-audit` / `checked 0 studies`. In a disposable detached worktree, changing the tracked G1 legend delta from the independently recomputed `1.767` to `9999.0` still exits 0 with zero studies, while `git diff` confirms drift. Explicitly naming the study exits 1, isolating automatic discovery as the gap. Control: the intended research script replayed under `-I -B` and `-I -O -B -W error`, both reproducing SHA-256 `b0cba027918e623b6f1169499eb49693aa47bede08c0c58411542bd91c9408f8` with zero diff; its numerical findings are not falsified. Minimal repair: add the expected `measure.py` + `requirements.txt` adapter and a mutation-fails CI control. Logs, hashes, preregistration and clean-room audit: `/tmp/tokenpage-harness-trial-20261121/`.
