# Preregistration: data hygiene

Pinned head: `063aaeeba9638c51c7f3fbb4ea86d5af11a3ee67`.

## Hypotheses

H1. The llama client coerces a boolean adapter id and a string NaN scale into accepted values. Both paths must reject them.

H2. `validate_propose_context` accepts a NaN constraint and serializes it as bare NaN. Both validation and encoding must reject non-finite values.

## Scope

Only `src/warp_modeld/llama_client.py` and `src/warp_modeld/cerebras_client.py`, plus their two test modules. No live endpoint is contacted.

## Method

Call `list_lora_adapters` and `set_lora_adapters` with a boolean id and a string NaN scale. Include clean controls.

Validate a propose context with NaN and infinite constraints. Encode the cleaned context. Include a clean control.

Run pytest and unittest in three modes: `-B`, `-O -B`, and `-B -W error`.

## Expected outcomes

E1. Each malformed adapter value raises LlamaClientError and no adapter is accepted.

E2. Clean adapter parsing and setting still succeed.

E3. Non-finite constraints raise CerebrasSchemaError at validation.

E4. No encoder emits a bare NaN or infinity token.

E5. Every suite passes in every mode.

## Decision rule

Submit for independent review only if E1 through E5 hold in every mode. A missed expectation stays recorded as a negative result. Do not merge on logic checks alone.

## Results, 2026-11-22

E1 held. Boolean ids and non-finite scales raise LlamaClientError in both the list and set paths. The audit checker `falsify_probe.py` now reports `F6_bool_id=raise:LlamaClientError` at this head.

E2 held. Clean adapter entries still parse and set, with the outbound payload unchanged.

E3 held. NaN and both infinities in constraints raise CerebrasSchemaError. The audit checker reports `F10_nan_constraint_accepted=raise:CerebrasSchemaError` at this head.

E4 held. Every Cerebras encoder now routes through `_json_dumps`, which forces `allow_nan=False`. A direct test confirms ValueError for NaN and both infinities.

E5 held. `PYTHONPATH=src python3 -m pytest -q` gave 267 passed, 2 skipped, and 134 subtests passed. The same result held under `-B`, `-O -B`, and `-B -W error`. `PYTHONPATH=src python3 -m unittest discover -s tests` gave 139 tests, OK, skipped 2, and the same result held under the same three modes.

At the audited main head the checker reported a boolean id of 1, a NaN scale, and an accepted NaN constraint. The local checker copy was guarded so it could reach its later probes. The guard changed only the copy, not the product code.

No live endpoint, GPU, paid provider, or network backend was used. These are input-boundary logic checks only. No adapted-model quality or novelty claim follows from them.
