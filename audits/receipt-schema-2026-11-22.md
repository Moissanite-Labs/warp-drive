# Preregistration: receipt schema

Pinned head: `6dcf915812c14d37a86e7a5e8bff65517d038a57`.

## Hypotheses

H1. `receipt.schema.json` cannot be loaded because `receipt_schema_version` is a bare string where JSON Schema requires a schema object.

H2. Replacing it with a const object makes `check_schema` pass and lets one emitted receipt validate.

## Scope

Only the receipt schema, the demo manifest digest and version, the manifest checksum, and one new test module. No product source changes.

## Method

Run `Draft7Validator.check_schema` on the committed schema. Build one receipt with the existing fake controller and validate it against the schema. Recompute the schema digest in the manifest and the checksum of the manifest. Run pytest and unittest in `-B`, `-O -B`, and `-B -W error`.

## Expected outcomes

E1. Schema loading succeeds.

E2. One emitted receipt validates.

E3. The manifest digest and checksum match the committed files after a versioned manifest bump.

E4. Every suite passes in every mode.

## Decision rule

Submit for independent review only if E1 through E4 hold in every mode. A missed expectation stays recorded as a negative result. Do not merge on these logic checks alone.

## Results, 2026-11-22

E1 held. `Draft7Validator.check_schema` now accepts the committed schema. The audit `laneB_checker.py` reports PASS for the draft 07, 2020-12, and declared validator rows for `receipt.schema.json`.

E2 held. One receipt emitted by the fake controller validates against the schema.

E3 held. The manifest schema digest is `66437485bede0fb859004df455a913a8dacbdc6e675dc1a817c341a70654c0ff`. The manifest checksum is `52feb794f91d72f4e25626a3f09ce306b6efc3dcf2a20efadcfb9227fd0a769f`. Both manifest and threshold versions were bumped to 0.1.2, with the threshold digest updated.

E4 held after one recorded iteration. The first run failed two contract tests that pinned the old 0.1.1 versions. Those pins were updated to 0.1.2 with no gate value changed. The rerun gave pytest 277 passed, 2 skipped, and 134 subtests passed, and unittest 131 tests, OK, skipped 2, in each of the three modes.

No live model, GPU, paid provider, or network backend was used. No gate threshold was changed. The schema repair changes only how the version value is expressed and how the contract versions are pinned.
