# Full audit, 2026-11-22

## Head audited

- Repo: Moissanite-Labs/warp-drive.
- Head: 063aaeeba9638c51c7f3fbb4ea86d5af11a3ee67.
- Branch for this record: audit/2026-11-22 from origin/main.
- Head check: the value above matched the claim time value 063aaee.
- Claim record: kept in the team's internal coordination log, not published here.
- Tracked files on main: 97.
- Parent repo: siliconcordat/warp main e3899d3.
- Fork state: ahead 45, behind 0. The parent head is an ancestor.

## Scope

- Lane A: code in src/warp_modeld. All 14 files. 7389 lines.
- Lane B: studies, certificates, schemas, and the demo manifest.
- Lane C: the GitHub surface. Pull requests, issues, branches, ruleset, checks.
- Lane D: docs and counted claims. README, architecture, plan, package file.
- Verifier: an independent rerun with new probes. No lane code was reused.
- This record carries every confirmed or narrowed finding. It also carries passes and open items.

## Method

- Each lane opened the file bodies it cites. Search results alone count as leads only.
- Each claim has a class. Exact means recomputed from the repo at the head above.
- Sampled means run on this host under stated limits.
- Anchor means taken from a dated external record or a pinned older commit.
- Each sharp claim was paired with its strongest repaired reading before any defect verdict.
- Exact claims used exact arithmetic. Integer checks used a second route with no shared code.
- Checkers ran in three modes. The modes are python3 -I -B, python3 -I -O -B, and python3 -I -B -W error.
- Checkers hold no bare asserts on validation paths. Files use LF only.
- Failed runs stay on record. Nothing was deleted to hide a failure.
- The audit tooling itself made no commits, pushes, or comments on GitHub. Fifteen of the drafts in issues.md were filed as GitHub issues alongside PR #43 (per the PR body); draft C3 was held back.

## Verdict in stated scope

- The offline codebase passes its own suites. The count is 218 passed, 2 skipped, 134 subtests passed.
- The demo manifest digests recompute clean. The bounded controller certificate regenerates clean.
- The trust boundary has fail open paths on the library surface. See F1 to F10 in the table.
- One schema file cannot load in a validator. See finding S1.
- Two README claims need correction. See findings D1 and D2.
- Live paths stay unverified. No GPU host, no llama server, no Cerebras key was present.
- Merge state needs care. PR 41 holds PR 37 in full. Five pull requests await new pushes after CHANGES_REQUESTED reviews.

## Findings table

| ID | Title | Severity | Class | State |
| --- | --- | --- | --- | --- |
| F1 | Stage 2 certificate is self attested | High | Exact | Confirmed |
| F2 | Stage 1 file binding is optional on the library path | High | Exact | Confirmed, library path only |
| F3 | Acceptance policy returns ACCEPT on NaN scalar gates | Medium | Exact | Confirmed, six scalar gates |
| F4 | Receipt log append does not verify the chain | Medium | Exact | Confirmed |
| F5 | Missing slot listing reads as clean | Low | Exact | Confirmed, fake clients only |
| F6 | llama client coercions accept NaN scale and bool id | Low | Exact | Confirmed, string NaN only |
| F7 | Controller mounts before digest record | Medium | Exact | Confirmed |
| F8 | Kill switch does not gate base inference | Question | Exact | Code fact confirmed, product call open |
| F9 | Signed ledger live append trusts memory head | Low | Exact | Partial, next open fails closed |
| F10 | Cerebras context accepts NaN constraint | Low | Exact | Confirmed, constraints only |
| S1 | Receipt schema file fails schema check | Medium | Exact | Confirmed |
| D1 | README test count line is stale | Low | Exact | Confirmed, line 77 |
| D2 | README live timing line has no run record in repo | Medium | Anchor | Unsupported in repo, line 79 |
| C1 | PR 41 contains PR 37 and both stay open | High | Exact | Confirmed overlap, 3 files |
| C2 | Merge gate has no required checks and no suite run | Medium | Exact | Confirmed, ruleset 27494833 |
| C3 | Label needs decision is missing and two issues lack an owner | Low | Exact | Confirmed |

Severity counts: High 3, Medium 6, Low 6, Question 1. That is 15 counted defects plus 1 open product question, 16 items in total. F8 is the question and is not counted as a defect.

## What passed, with counts

- Test suites, exact. PYTHONPATH=src pytest tests/ gave 218 passed, 2 skipped, 134 subtests passed.
- The two skips are the opt in live tests. unittest discover gave Ran 128 tests, OK, skipped 2.
- Counts, exact. Modules 14 with init, 13 without. Lines 7389 with init, 7193 without.
- Test files, exact. tests/test_*.py count is 15. Test dir python files total 19.
- Canaries, exact. 9 ids in schemas/verifier-canaries.json. The demo safety suite pins the same 9.
- Demo suites, exact. Task 112, retention iid 24, retention shifted 80, safety 9.
- Demo digests, exact. All 10 manifest digests and the combined digest recompute clean.
- Reuse count, anchor. 110 of 112 reuse holds as a documented claim. Source harvest data is outside this repo.
- Certificates, exact where stated. Bareiss study output regenerates clean at 1771 bytes.
- Bounded controller certificate regenerates clean at 6068 bytes. Gram upgrade certificate regenerates clean at 3235 bytes.
- Hygiene, exact. CRLF files 0. Bare asserts in src 0 in 14 files. Bare asserts in studies 0 in 14 files.
- Hygiene, sampled. No home path leaks in tracked files. No tracked build output. Token pattern hits were names and deny strings only.
- Package facts, exact. Zero dependencies. requires-python is at least 3.11. Source imports are stdlib plus relative imports.
- Three mode parity, exact. Verifier files gave 186 passed plus 81 subtests in each mode.

## Checker reruns in this record

Run all checkers from the repo root. Lane B needs the repo root as its sole argument.

| File | -I -B | -I -O -B | -I -B -W error | Output hash prefix |
| --- | --- | --- | --- | --- |
| checkers/laneA_probes.py | rc 0 | rc 0 | rc 0 | b83b604fd74fa61b |
| checkers/laneA_probes2.py | rc 0 | rc 0 | rc 0 | c33b7b4b33db0c73 |
| checkers/laneA_probes3.py | rc 0 | rc 0 | rc 0 | 2fe67b13b5acb530 |
| checkers/laneB_checker.py . | rc 0 | rc 0 | rc 0 | cde2c29ab82e8633 |
| checkers/laneD_checker.py | rc 0 | rc 0 | rc 0 | not pinned (output embeds HEAD) |
| checkers/falsify_probe.py | rc 0 | rc 0 | rc 0 | 25704d5baf093611 |
| checkers/run_pytest_iso.py tests/test_stage2_certificate.py -q | SKIP without pytest | SKIP without pytest | SKIP without pytest | per run tail |

- Output hashes above match across the three modes for each row. Hash prefixes are from the 2026-11-26 re-run on this branch after the review fixes to the checkers. Audited-head prefixes were laneA_probes 27aef84f4366123d, laneA_probes2 3c7e7655f930aa1a, laneA_probes3 c5647e7973b6bb61, laneB d617ba7bdc21, falsify_probe 57895e7c9884c9b1.
- laneD_checker.py output embeds git rev-parse HEAD and git ls-files, so its hash changes with every commit and is not pinned. The audited-head prefix was 7055aaa4b67337c7.
- Checkers run on stdlib-only Python. pytest and jsonschema are not declared dependencies of this repo, so rows that can use them print a SKIP line with a clear message when the package is absent: laneB_checker.py and falsify_probe.py skip schema validation without jsonschema, laneA_probes2.py prints SKIP for the test-module fakes (laneA_probes3.py uses inline stdlib fakes instead), and run_pytest_iso.py prints SKIP without pytest under -I. Where pytest is importable, run_pytest_iso.py prints the per-run tail: 9 passed, 5 subtests passed for tests/test_stage2_certificate.py -q.
- unittest discover needs pytest importable for tests/test_experiment_controller.py; on a stdlib-only host that module fails to import and the run reports an error instead of the OK count.
- MANIFEST.sha256 lists SHA-256 digests and file names only, no byte counts. Run sha256sum -c MANIFEST.sha256 from this folder.
- Falsify probe v1 failed on a probe bug. The failure is noted in findings.md. No lane verdict rests on v1.
- Lane B checker v1 failed on the schema defect before its repaired form was added. The failure stays noted.

## What is unverified

- Live inference paths. No llama server, GPU, or Cerebras key on this host. Class sampled at best.
- Reuse provenance. The harvest file lives in the ml-os repo. It was not fetched here.
- Live timing receipt for README line 79. No gguf, log, or jsonl run file is tracked in this repo.
- Live certificate regeneration for three studies. Each needs pinned checkouts outside this repo.
- Mutate rates in study prose. The tool was absent. No mutant files sit in this repo.
- Site page bodies in PR 42. Only the seven counted numbers were recomputed against main.
- Hardware size estimates and the dated model catalog lines. No fresh fetch or host run backs them here.
- Overlap of F1 and F2 with the WD-SB registry. The registry sits outside these lanes. Dedupe at landing.
- Whether PR 41 meets the latest PR 37 review probes. PR 41 has zero reviews at audit time.
- Sequential merge text conflict on README.md across PR 41 and PR 36. It needs a merge test at land time.

## Dedupe notes

- Out of scope set, reference only: WD-SB-01 to WD-SB-04 residuals and issue 31 guards.
- PR 37 carries those fixes. Its body closes issues 16, 19, and 31. All three issues stay open until a merge.
- PR 41 holds the same 3 files as PR 37 plus more. PR 41 has no closing words. A PR 41 merge alone would not close those issues.
- PR 37 latest review is CHANGES_REQUESTED at its head. No later push answers it. PR 41 has no reviews yet.
- PR 11 lane 7 fail open list was triaged separately before this audit. It is not refiled here.
- PR 11 still shows CHANGES_REQUESTED at its head with no answering push. Issue 7 points to PR 11. Live proof waits for an RTX host.
- PR 36 cross repo fixture digests sit on hold. The digests are declared, not measured. They are not refiled here.
- README line 77 stale count stays in scope. It is finding D1. No open issue owns it.
- Open issues are 39, 31, 19, 16, 14, 7, 6. Issue 39 has no pull request. Issue 6 has no open pull request owner by GitHub refs.
- Open pull requests are 42, 41, 38, 37, 36, 35, 23, 21, 20, 11. All target main. All show mergeable.
- Pairwise file overlap is two pairs only. PR 41 with PR 37 shares 3 files. PR 41 with PR 36 shares README.md.
- Heads current with main are PR 42, PR 41, PR 37. Seven heads are behind main and still mergeable.
- Checks on each head are CodeQL only, plus one site gate on PR 42. No suite check runs on GitHub.
- Branch count is 28 plus main. Cleanup candidates are 16 merged branches plus 1 orphan branch.

## Files in this record

- README.md: this report.
- findings.md: one section per confirmed or narrowed finding.
- issues.md: issue drafts. Fifteen were filed as GitHub issues alongside PR #43 (per the PR body); draft C3 was held back.
- checkers/: seven rerunnable scripts. Each passed the three modes above.
- MANIFEST.sha256: hash list for this folder. It excludes itself.

## Status at 2026-11-26

Main has since merged fixes for some findings. Each item below was verified on 2026-11-26 on this branch (main 3a458acb merged in) by running the named checker under python3 -I -B from the repo root. The verdicts above are unchanged and still describe the audited head 063aaee.

- F3 closed on main (PR #59 merged): falsify_probe.py prints F3_nan_verdict=raise:ControllerError, and laneA_probes.py prints P2_nan_policy: CLOSED with raise:ControllerError.
- F4 closed on main (PR #59 merged): falsify_probe.py prints F4_append_after_tamper=raise:ControllerError, and laneA_probes.py prints P3_receiptlog_tamper_append: CLOSED.
- D1 closed on main (root README reconciled): the stale 53 passing count line is gone from the root README; laneD_checker.py reports readme_needle_lines with an empty list for the 53 passing needle, and the root README documents both runners with the pytest-optional note.
- D2 closed on main (root README reconciled): the live timing figures are now labeled a past unarchived author-host live run of 2026-11-19 with no committed receipt, which matches the finding text above.
- Still open on this tree, confirmed by the same 2026-11-26 checker runs: F1, F2, F5, F6, F7, F9, F10, S1 (see the falsify_probe.py, laneA_probes.py, laneA_probes2.py, and laneA_probes3.py lines), plus the GitHub-surface findings C1, C2, C3, which cannot be re-verified from a local checkout.
- D2 attribution note carried from the PR #43 review: the live timing figures trace to the parent siliconcordat/warp repo's Wave 4 run records outside this fork; this repo holds no local receipt for them.

