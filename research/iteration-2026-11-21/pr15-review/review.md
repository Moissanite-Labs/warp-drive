## Requesting changes

Reviewed head: `e6ad0967c2386eb3e3bdc7d81ff3a47808d53a1e`.

Two claims at this head fail independent execution. The shipped certificate fix and the four filed state-isolation defects hold.

### Blocking

1. `blueprints/sandbox/warp-sandbox-exec.sh` calls `realpath -e`. On this host that option is illegal:

```text
realpath: illegal option -- e
usage: realpath [-q] [path ...]
```

The script therefore reports `ERR_SANDBOX_WORKTREE` before it can reach the pinned bubblewrap check or the seccomp check. The full suite shows the effect:

```text
PYTHONPATH=src python3 -B -W error -m unittest discover -s tests
Ran 72 tests in 19.549s
FAILED (failures=2, skipped=1)
```

The failures are `test_shell_scripts_syntax_and_fail_closed_sandbox_behavior` and `test_wd_sandbox_01_and_wd_x06_wd_x07_blueprint_hardening`. Stderr SHA-256: `3a39c6e1b2f34d908b00a9efb8cb013f48a46cd4fd1ca5b075069b8ec26dcc10`.

2. `studies/expedition-trust-boundary-verifier/WARP_DRIVE_RUNTIME_SANDBOX_REPORT.md` says pinned `repair_ledger` at `e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` already used exclusive creation and `fsync` before unlink. Lines 330-366 of that blob use `write_text`, `chmod`, and `unlink`. They contain neither `O_EXCL` nor `fsync`. Witness SHA-256: `1fd9f6825f28cb189074d7531ba7b757e46964c26be20aae9ca054c001826ccc`.

### What holds

Shipped `verify_stack_division_free` rejects the earlier singleton forgery: component norm squares are 16 and the composed certificate claims 0. The error is `inconsistent single-adapter composed certificate composed_frobenius_sq`. Output SHA-256: `3417b3eaf59357a1ee53cf61e5040c4af2984dd036d03b305f41ba57691baa35`. Certificate source SHA-256: `f032d120692f323be7a5e5fa0d004e0a819b2d317cc3109f70987fb4b9e4f7fe`.

A direct receipt probe rejects `verified_clean=True` when `ssm_recurrent` was requested but only `kv_cache` was confirmed. It also rejects an unknown bank. Output SHA-256: `745f7efbf6a52d6ad0a2a934fa8aa7b33e1a46bee66ef09ba4e6d4ef69b76ddc`.

These three tests pass in 1.119s: `test_wd_flush_01_and_wd_x01_ssm_only_unconfirmed_flush_fails_closed`, `test_wd_canary_01_and_02_code_fence_boundaries_and_external_runner`, and `test_wd_fp_01_wd_x02_wd_x03_wd_x04_cross_org_alignment`. Output SHA-256: `490b8149fbe25f6f91852c3b3c440580e972dc3130241a76651054231cb1be6e`.

Mutation counts, standalone study hashes, and live model behavior were not rerun. KV-only flush confirmation still defaults to confirmed when the backend omits `banks_flushed`. That matches the current shipped branch and is outside the two defects above.

> Automated posting by agentic team with human oversight.
