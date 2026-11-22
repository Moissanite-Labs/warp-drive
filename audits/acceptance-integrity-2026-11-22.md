# Preregistration: acceptance integrity

Pinned head: `063aaeeba9638c51c7f3fbb4ea86d5af11a3ee67`.

## Hypotheses

H1. `apply_acceptance_policy` accepts NaN scalar gates. The fix must make every non-finite scalar fail closed at the function boundary.

H2. `ReceiptLog.append` extends a tampered hash chain. The fix must refuse an append whenever `verify_chain` returns False.

## Scope

Only `src/warp_modeld/experiment.py` and `tests/test_experiment_controller.py`.

This is offline logic. No live model, GPU, paid provider, or network backend is used. No claim about adapted-model quality or novelty follows from it.

## Method

Inject NaN and both infinities into each scalar gate field. Include a clean passing control.

Tamper one stored receipt entry. Call append on that log. Include a clean log control.

Run unittest discovery and pytest. Run three interpreter modes: `-B`, `-O -B`, and `-B -W error`.

## Expected outcomes

E1. The clean control returns ACCEPT.

E2. Each non-finite scalar raises ControllerError and never returns ACCEPT.

E3. A tampered log append raises ControllerError and writes no new line.

E4. A clean log append succeeds and `verify_chain` stays True.

E5. Every suite passes in every mode.

## Decision rule

Submit for independent review only if E1 through E5 hold in every mode. A missed expectation stays recorded as a negative result. Do not merge on these logic checks alone.

## Results, 2026-11-22

E1 held. The clean passing control returned ACCEPT.

E2 held. Twenty-four non-finite cases raised ControllerError. None returned ACCEPT. The cases cover the seven scalar gates under NaN, positive infinity, and negative infinity, plus one margin case under NaN and infinity and one rollback difference case under NaN.

E3 held. The audit `falsify_probe.py` reported `F4_tampered_verify_chain=False`, `F4_append_after_tamper=raise:ControllerError`, and `F4_after_verify_chain=False` at this head.

E4 held. The clean log control appended a third entry and `verify_chain` stayed True.

E5 held. `PYTHONPATH=src python3 -m pytest -q` gave 283 passed, 2 skipped, and 134 subtests passed. The same result held under `-B`, `-O -B`, and `-B -W error`. `PYTHONPATH=src python3 -m unittest discover -s tests` gave 128 tests, OK, skipped 2, and the same result held under the same three modes.

The audit checker reported `F3_nan_verdict=raise:ControllerError` at this head. At the audited main head it reported ACCEPT. The checker was guarded locally so it could continue to its F4 probe. The local guard changed only the checker copy, not the product code.

No live model, GPU, paid provider, or network backend was used. These are logic checks only. No adapted-model quality or novelty claim follows from them.
