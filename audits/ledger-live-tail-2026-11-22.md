# Preregistration: live ledger tail

Pinned head: `063aaeeba9638c51c7f3fbb4ea86d5af11a3ee67`.

## Hypotheses

H1. `SignedLedger.append` trusts its in-memory head. After an on-disk tamper in the same session it appends a receipt that `LedgerVerifier` rejects.

H2. Checking the on-disk head before each append makes the live handle fail closed on tamper while leaving a clean append unchanged.

## Scope

Only `src/warp_modeld/ledger.py` and one new test module. No other module changes.

No live endpoint, GPU, paid provider, or network backend is used.

## Method

Open a signed ledger, append two receipts, tamper one stored line on disk, then append again through the original handle. Include a clean control.

Run pytest and unittest in three modes: `-B`, `-O -B`, and `-B -W error`.

## Expected outcomes

E1. Append after an on-disk tamper raises LedgerTamperError and writes no new line.

E2. Fresh verification of the tampered file still raises LedgerTamperError.

E3. A clean handle appends and verifies successfully.

E4. Every suite passes in every mode.

## Decision rule

Submit for independent review only if E1 through E4 hold in every mode. A missed expectation stays recorded as a negative result. Do not merge on these logic checks alone.
