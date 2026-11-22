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
