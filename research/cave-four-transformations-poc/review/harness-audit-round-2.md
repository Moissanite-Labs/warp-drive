# Independent harness re-review

## Ruling

The independent reviewer ruled the corrected harness valid for the authoritative `N0` reference replay. The reviewer found no new false acceptance and no unjustified rejection of locked normal outputs within the reviewed scope and probes. This is tooling readiness, not scientific correctness.

The reviewer was not an author of the runner. The judgment model tier was `cerebras/moonshotai-kimi-k3.1-pro-trial`. No target case ran during this review.

## Lock and controls

Reviewed lock SHA-256: `50e74e2d1760cf21f05c71ec27304174ac9bd8656d3f6bfd021fdc860d76dea1`.

- All seven locked source hashes matched.
- Cave target binding: `a714ef7981421266bea78e8357d61f3586f0eda0`.
- `cases.json` SHA-256: `d8616d8708ea98c5b4704964ecdcde0d3e3bc11e17e66d6741fc6d29d5ba66d0`.
- Reviewed `evaluation/run.py` SHA-256: `96d3f7a5cc8fbfb213e885d33984a11325db04598eb54c775ffe1d1f963e9f8d`.
- `evaluation/test_harness.py` SHA-256: `ddd9dc3e06e02477a8bbc92ba29c198fcc6d649a2dbe1201a689efaac22be888`.
- Environment: Python 3.14.6 and numpy 2.5.4.

Each locked Python control command reported 19 passing tests with no failures or skips:

```bash
python3 -I -B evaluation/test_harness.py
python3 -I -O -B evaluation/test_harness.py
python3 -I -B -W error evaluation/test_harness.py
```

That is 57 passing control executions. Four locked Python files had zero bare asserts and zero CRLF line endings.

## Independent mutations

The reviewer used an independently written synthetic receipt and summary generator in all three modes.

- Locked normal synthetic outputs classified correctly in 18 of 18 cases.
- The valid baseline had 18 receipts: 13 pass, two fail, and three operational failures.
- The rebuilt-chain trailing-output attack changed nine files and receipts across U01, R01, and K1. All nine became operational failures, and verification rejected them because their outcomes no longer followed from stored output.
- An unlisted file failed the exact public-manifest check.
- An extra `SOURCE.json` field failed the source-schema check.
- Six tested local-path families were redacted with no original path surviving. Six unredacted-path mutations with rebuilt receipt chains were all rejected.

The three independent probe logs were byte-identical, 1,619 bytes each. Their SHA-256 was `bb9ccffa8989753f6d5e8567f1315bef29707eee8cb63f8c0592b612769cf146`.

## Post-review hygiene edit

The author then split string literals in the verifier's own publication-ban regex so the source would not itself contain banned path or attribution text. This does not change the regular expression or control expectations. A new lock is required.

The final run record names its exact lock and evidence hashes. The final evidence review must recheck that lock rather than silently transferring this reviewed lock's digest.

No POC or Cave file was modified by the reviewer. No model or paid run occurred. Real-data readiness remains `BLOCKED`.
