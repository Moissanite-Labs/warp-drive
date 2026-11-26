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

## Results, 2026-11-22

E1 held. After an on-disk tamper, append through the original handle raises LedgerTamperError and the file still has two lines.

E2 held. Fresh verification of the tampered file raises LedgerTamperError.

E3 held. A clean handle appends a second receipt with sequence 2 and the first receipt digest as its parent. Verification returns both receipts.

E4 held. `PYTHONPATH=src python3 -m pytest -q` gave 258 passed, 2 skipped, and 134 subtests passed. The same result held under `-B`, `-O -B`, and `-B -W error`. `PYTHONPATH=src python3 -m unittest discover -s tests` gave 130 tests, OK, skipped 2, and the same result held under the same three modes.

The audit checker `falsify_probe.py` now reports `F9_append_after_tamper=raise:LedgerTamperError` and `F9_verify_after=raise:LedgerTamperError` at this head. At the audited main head it reported ok for the append.

The tail check reads and verifies the whole ledger on each append. That cost is bounded by the local file size and was not benchmarked on a large ledger. No live endpoint, GPU, paid provider, or network backend was used. These are local file logic checks only.

## Post-review addendum (2026-11-26)

Appended after review 3 (abu-aska, WD61-01/WD61-02) on PR #61. No earlier text above was edited.

### Scope boundary: single-writer assumption

`_require_undisturbed_tail()` and the append in `SignedLedger.append()` use no advisory file lock (`fcntl.flock` or equivalent). The verify-then-append sequence is therefore not atomic: with concurrent writers on the same path, another process can race between the tail verification and the append. The ledger is designed for a single writer per path; concurrent writers are out of scope and can interleave receipts that each pass verification individually.

### Fixed items

- WD61-01 (blocking): `LedgerVerifier.verify_file` now fails closed with `LedgerTamperError` for a non-regular-file path (directory substitution), non-UTF-8 bytes, and any other unreadable `OSError`; `prev_receipt_sha256` and `receipt_sha256` must match the lowercase ASCII 64-char hex SHA-256 shape (`.isascii()` + regex) before `hmac.compare_digest`, and the `signature` field gets the same guard in `verify_file` and in `HmacSha256Signer.verify`, so non-ASCII hash/signature tampers raise `LedgerTamperError` instead of `TypeError`. A missing file on a live handle that already has entries raises `LedgerTamperError` via the "missing or out of sequence" tail guard. A missing or 0-byte file still verifies as an empty ledger (`[]`), unchanged.
- WD61-02 (blocking): `tests/test_ledger_live_tail.py` gained tests that reach each `_require_undisturbed_tail` guard with a valid on-disk chain: external valid write on a fresh `count == 0` handle ("unknown to this handle"), truncation and unlink-plus-external-append on an active handle ("missing or out of sequence"), and a different valid same-length chain signed with the same key copied over the file ("head changed").
- Non-blocking: the head-hash comparison in `_require_undisturbed_tail` now uses `hmac.compare_digest` (both operands are validated lowercase hex digests).

### Verification after the fixes (commands run in this tree, 2026-11-26)

- `PYTHONPATH=src python3 -B -m pytest -q tests/` -> 266 passed, 2 skipped, 263 subtests passed.
- `PYTHONPATH=src python3 -B -m unittest discover -s tests` -> Ran 149 tests, OK (skipped=2).
- `PYTHONPATH=src python3 -B -m pytest -q tests/test_ledger_live_tail.py` -> 10 passed.
- The 2 skips are the pre-existing live smoke skips (no live endpoint used).
