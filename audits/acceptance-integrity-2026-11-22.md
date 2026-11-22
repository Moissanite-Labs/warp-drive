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
