# Independent harness audit, round 1

## Independence and scope

A reviewer who did not author the runner inspected the first locked POC harness. The judgment model tier was `cerebras/moonshotai-kimi-k3.1-pro-trial`. The reviewer worked read-only in the POC and Cave checkouts and used a separate temporary workspace for probes. A Gate-10 advocate independently reran the attacks and alternatives.

The reviewed lock digest was `5926db4ee17910adfd5dd4ba68961779cec28a3b3c6a79ea5f17197eac8e125f`. The target was Cave commit `a714ef7981421266bea78e8357d61f3586f0eda0`. The target worktree was clean. Environment checks reported Python 3.14.6 and numpy 2.5.4.

The original private probes remain outside the public research record. This public report preserves their commands' outcomes, counts, hashes, and claim boundaries without local paths.

## Verification performed

The reviewer verified seven of seven locked source hashes with no mismatch. `cases.json` had SHA-256 `d8616d8708ea98c5b4704964ecdcde0d3e3bc11e17e66d6741fc6d29d5ba66d0`.

The reviewer ran these commands in all three locked Python modes:

```bash
python3 -I -B evaluation/test_harness.py
python3 -I -O -B evaluation/test_harness.py
python3 -I -B -W error evaluation/test_harness.py
```

Each reported 15 tests passing, for 45 passing control executions. Independent probe logs were byte-identical across the three modes. Their SHA-256 was `33684310ce3c0f3d8a9bf5ad248f907b6ba3cce995122a69e7bf5c909a32523f`. Advocate alternative logs were also identical, with SHA-256 `9893fdeb4468c51ee39e75696fc949d504f991771177ce5fc543a91521aba3d2`.

## Finding 1: contradictory trailing output was accepted

Gate-10 ruling: `stands_narrowed`.

K summary parsing did not require the summary line to be terminal. U01 and R01 accepted the pass marker anywhere in output. Adding failure text after the accepted output, rebuilding valid receipt hashes, and regenerating the summary still produced `REFERENCE_REPLAY_COMPLETE`.

The probes found three direct classifier false accepts covering U01, R01, and K1. The first full mutation changed six receipts across U01 and K1 and was accepted across all 18 receipts. The expanded advocate mutation changed nine output files and receipts across U01, R01, and K1 and was also accepted.

K trailing text directly violated the protocol's terminal-summary rule. The U01/R01 issue was a semantic false-accept risk because their marker rules had not explicitly required uniqueness and terminal placement.

Existing controls still rejected a missing mode, naive output edits without rebuilt hashes, duplicate K summaries, and return-code mismatches. Valid final newlines and harmless prefixes were accepted.

## Finding 2: publication enforcement was incomplete

Gate-10 ruling: `stands_narrowed`.

Redaction covered configured checkout paths and common home-directory forms but missed tested package-manager and temporary-directory path families. Six local-path occurrences survived in three mutated U01 outputs. The verifier accepted them after hashes were rebuilt.

The verifier also accepted an unlisted evidence file and an extra `SOURCE.json` field containing a local path. The publication mutation comprised three changed receipts, one unlisted file, and one unbound source field.

Advocate controls confirmed that configured path redaction and common home-path replacement did work. This finding did not establish that private material had been published. It established that the verifier's publication gate was incomplete, not that the receipt chain was broken.

## Ruling and remedy

The reviewer ruled the first harness invalid for unattended claim evaluation. No target result was established. Only the cancelled U01-plain development run had executed, with one matching receipt. No K case ran and no summary existed.

The author then required unique terminal K summaries and exact unique terminal U01/R01 markers. The verifier now requires an exact public manifest, rejects symlinks and nested directories, requires the exact source schema, and scans all run files for forbidden local-path and attribution patterns.

The corrected lock is `50e74e2d1760cf21f05c71ec27304174ac9bd8656d3f6bfd021fdc860d76dea1`. The expanded harness has 19 controls, including a rebuilt-chain trailing-output mutation and tests for unlisted files, unexpected source fields, and unredacted public paths. All 19 passed in each of the three modes, for 57 passing control executions.

These findings concern harness behavior, not Cave's scientific results. Novelty remains `N0`. No target, model, real-data, or network-performance claim follows.
