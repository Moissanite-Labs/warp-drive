# Preregistration: digest before mount

Pinned head: `4653d62e520586d1e2b94efa04544438634b7633`.

## Hypotheses

H1. Recording the candidate digest before mounting closes the window where a live adapter has no digest record.

H2. A mount failure still leaves the candidate unbound and cannot produce a success receipt.

## Scope

Only `src/warp_modeld/experiment.py` and `tests/test_experiment_controller.py`.

No live endpoint, GPU, paid provider, or network backend is used.

## Method

Move the digest record before the mount call and append a separate mount event when the mount succeeds. Run the audit checker that records event order. Run pytest and unittest in `-B`, `-O -B`, and `-B -W error`.

## Expected outcomes

E1. The audit checker reports `log:candidate_digest_recorded` before `mount`.

E2. A failed mount still refuses evaluation and writes no success receipt.

E3. The full fake experiment still produces a valid receipt and sealed log.

E4. Every suite passes in every mode.

## Decision rule

Submit for independent review only if E1 through E4 hold in every mode. A missed expectation stays recorded as a negative result. Do not merge on these logic checks alone.

## Results, 2026-11-22

E1 held. The audit checker reports `F7_order=['log:candidate_proposed', 'log:candidate_digest_recorded', 'mount', 'log:adapter_mounted']` at this head. At the pinned base it reported the digest record after the mount.

E2 held. The mount failure test now asserts that the digest record exists, no mount event was written, and evaluation still refuses to bind.

E3 held. The full fake run still produces a valid receipt and a verified sealed log.

E4 held. `PYTHONPATH=src python3 -m pytest -q` gave 302 passed, 2 skipped, and 134 subtests passed. `PYTHONPATH=src python3 -m unittest discover -s tests` gave 128 tests, OK, skipped 2. Both results held under `-B`, `-O -B`, and `-B -W error`.

The audit checker copy needed a local guard at its F3 probe because merged PR 59 now raises ControllerError on NaN gates. That guard changed only the checker copy in a temporary tree, not product code.

No live endpoint, GPU, paid provider, or network backend was used. These are local control-flow checks only.

## Post-review addendum (2026-11-26)

Review `abu-aska` on PR #63 (`CHANGES_REQUESTED` pinned to `1a2c0547`) raised two blocking findings and two non-blocking notes. All four are addressed in this tree:

1. In `compile_and_bind`, the `adapter_mounted` receipt is now appended before `self._bound_candidate`, `self._bound_compile`, and `self._deploy_ms` are assigned, so an `append` failure on `adapter_mounted` leaves the controller unbound and `evaluate()` refuses to run. Covered by `test_mounted_receipt_append_failure_leaves_no_binding`.
2. `deploy_ms` returned by `runtime.mount_adapter` is now validated with `_require_number` (rejects non-numbers, bools, NaN, and infinities) and rejected when negative, raising `ControllerError` before any receipt append or binding. Covered by `test_compile_rejects_invalid_deploy_ms` with `nan`, `inf`, `-1.5`, and `True`.
3. `compile_and_bind` clears `_bound_candidate`, `_bound_compile`, and `_deploy_ms` on entry, so a failed second run cannot leave a stale binding. Covered by `test_failed_second_compile_clears_stale_binding`.
4. Scope note: the Scope section above lists only `src/warp_modeld/experiment.py` and `tests/test_experiment_controller.py`; the preregistration file itself (`audits/digest-before-mount-2026-11-22.md`) is also part of this branch and is omitted from that list.

Observed after the fix, run in this tree with `PYTHONPATH=src python3 -B -m pytest -q tests/`: 263 passed, 2 skipped, 263 subtests passed. `PYTHONPATH=src python3 -B -m unittest discover -s tests`: Ran 139 tests, OK (skipped=2). The 2 skips are the opt-in live smoke tests (`tests/test_live_cerebras_smoke.py`, `tests/test_live_llama_smoke.py`). No live endpoint, GPU, paid provider, or network backend was used; these are local control-flow checks only.
