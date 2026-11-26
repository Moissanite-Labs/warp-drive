# Final PR #15 executable review evidence

## Scope and pin

- Repository: `Moissanite-Labs/warp-drive`.
- Exact reviewed head: `1117bbdcd0160bed91d2916161e86698137e12cb`.
- Fresh detached worktree: `/tmp/warp-pr15-final-review`.
- Evidence: `/tmp/warp-pr15-final-evidence`.
- Host: macOS arm64. Python `3.14.6`.
- This is bounded, independent, non-author, post-merge executable evidence, **not approval or a merge-readiness claim**.
- No GitHub writes/reviews/comments/merges/pushes/Actions changes. No mutation sweep. No live-model, paid-provider, CUDA, or physical-GPU testing.
- Source hashes and clean-worktree status are in `source-pin.txt`. Relevant source line anchors are in `source-anchors.txt`.

## Finding

### Low: direct constructors coerce the string `"false"` to legacy KV opt-in

Locations:

- `src/warp_modeld/verifier.py:101`
- `src/warp_modeld/canary.py:498`
- `src/warp_modeld/canary.py:754`

All three constructors use `bool(allow_legacy_implicit_kv_flush)`. Consequently, the nonempty string `"false"`, integer `1`, and other truthy non-boolean values enable legacy implicit KV confirmation. The end-to-end witness constructed `WarpModeld(..., allow_legacy_implicit_kv_flush="false")`. An erase response omitting `banks_flushed` was accepted and produced `banks_confirmed=('kv_cache',)`. The exact same response with the real boolean `False` raised `StateFlushError` as intended.

Reproduction:

```sh
cd /tmp/warp-pr15-final-review
PYTHONPATH=/tmp/warp-pr15-final-review/src:/tmp/warp-pr15-final-review \
  python3 -B -W error /tmp/warp-pr15-final-evidence/legacy_nonbool_repro.py
```

Return code: `0` (the reproduction's assertions completed). Raw witness: `legacy-nonbool-repro.log`:

```text
input=False stored_modeld=False stored_canary=False stored_external=False
flush=input:False rejected=StateFlushError: slot 0 erase failed to confirm required state banks ['kv_cache'] (confirmed=[])
input='false' stored_modeld=True stored_canary=True stored_external=True
flush=input:'false' accepted slots=(0,) confirmed=('kv_cache',)
```

Boundary: `_cmd_serve` already rejects non-boolean JSON config values at `src/warp_modeld/cli.py:60-62`. This finding is limited to callers using the direct Python constructors. The proper booleans retain the intended KV-only opt-in behavior. A strict `type(value) is bool` check in all three constructors would close the discrepancy.

## Normal and optimized suites

Executed from `/tmp/warp-pr15-final-review`:

```sh
PYTHONPATH=src:. python3 -B -W error -m unittest discover -s tests
```

- Return code: `0`
- Count: **81 tests**, **1 skipped**
- Raw output: `test-normal.log`. Command and return code in corresponding `.command.txt` / `.rc.txt` files.

```sh
PYTHONPATH=src:. python3 -B -W error -O -m unittest discover -s tests
```

- Return code: `0`
- Count: **81 tests**, **1 skipped**
- Raw output: `test-optimized.log`.

## Standalone verifier study tests

```sh
python3 -I -B -W error studies/expedition-trust-boundary-verifier/test_weft_cross_audit_r5.py
```

- Return code `0`. **6 tests**, OK (`test_weft_cross_audit_r5.py.log`).

```sh
python3 -I -B -W error studies/expedition-trust-boundary-verifier/test_warp_drive_runtime_r5.py
```

- Return code `0`. **11 tests**, OK (`test_warp_drive_runtime_r5.py.log`).

## Independent defect-class witnesses

Witness source: `independent_witnesses.py` (authored in the fresh evidence directory. does not invoke the shipped PR regression tests).

```sh
PYTHONPATH=/tmp/warp-pr15-final-review/src:/tmp/warp-pr15-final-review \
  python3 -B -W error /tmp/warp-pr15-final-evidence/independent_witnesses.py
```

- Return code `0`. **8 test methods**, OK. Raw output: `independent-witnesses.log`.
- Singleton composed-certificate end-to-end valid control passed. Forged zero values were rejected with the exact singleton error for each of Frobenius, spectral norm, leakage energy, and max safety dot metrics.
- Sandbox `/`, `//`, `///`, `////`, a temporary protected directory with multiple leading slashes, a protected parent, and symlink-to-protected variants all returned `126` before command execution. Actual bubblewrap confinement was not executable on this host.
- An allowed sibling passed path validation and reached the expected `ERR_SANDBOX_UNAVAILABLE` because this macOS host has no `/usr/bin/bwrap` or `/bin/bwrap`. The shell file resolver resolved a multi-hop relative symlink on macOS and rejected a symlink loop.
- Empty `/slots` raised `StateFlushError` for KV/SSM and `LatticeFlushError` for lattice, with **zero erase calls**, under both legacy boolean settings.
- Legacy response-matrix witnesses passed for real booleans: default rejection, explicit KV-only opt-in, SSM rejection even when opted in, and rejection of empty-list/string/non-dict confirmations.
- Ledger source uses `O_WRONLY|O_CREAT|O_EXCL` and `_write_all_and_fsync` for archive and digest. Executable instrumentation observed two `O_EXCL` opens and two `fsync` calls with mode `0400`. Archive bytes/digest/modes matched. A real frozen-timestamp collision raised `FileExistsError` and preserved both archive and source. Injected write/fsync failure preserved the source.

The first witness run is preserved as `independent-witnesses.harness-initial.log` with return code `1`. It was a **harness regex error**, not a product failure: the implementation rejected all four forgeries using metric aliases such as `composed_frobenius_sq`, while the harness expected raw field names. The corrected assertions verify those exact aliases. No repository source was changed.

## Verdict and boundaries

One low-severity strict-type finding above. No additional finding was demonstrated in the requested certificate, sandbox path, ledger-repair, empty-slot, or proper-boolean legacy-KV scopes. The evidence does not establish behavior outside those bounds and makes no live-model, paid-provider, CUDA, physical-GPU, approval, or merge-readiness claim.
