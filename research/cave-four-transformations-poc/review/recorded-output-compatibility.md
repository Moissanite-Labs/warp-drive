# Recorded-output compatibility check

Before restarting execution, the parent parsed Cave's recorded output files under the corrected parser and lock `9f1c5cd103696d342b2b152de8058cde278e371d980526b5db6e3e08946f6466`. This read-only check did not execute target code.

The matrix covered U01, R01, K1, and K6 in all three modes, plus K2, K3, and K4 in plain mode. Expected return codes were supplied from the lock: zero for passes and one for expected failures. The parser recomputed each outcome from the recorded output bytes.

- 15 of 15 classifications matched their locked outcome.
- Thirteen expected passes parsed as `pass`.
- K2 and K3 parsed as `fail`.
- No mismatch remained.

K5's three operational-failure modes were excluded because this check covered recorded non-operational verdict outputs. K5 retains its locked expectation of operational failure and must be observed in the live replay.

The check included the actual U01 output from `development-run-002-cancelled`. Its final two lines are the count marker and `PASS`. The corrected parser classifies that saved output and return code zero as `pass`.

This is a parser compatibility check against previously recorded Cave files. It is not a fresh target result, a claim that old recorded files are trustworthy, or a scientific validation. The authoritative run must still execute all 18 case-mode pairs and verify its new receipts.
