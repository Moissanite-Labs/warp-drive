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
