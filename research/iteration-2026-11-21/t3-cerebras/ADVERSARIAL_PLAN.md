# PR #9 independent adversarial test preregistration

Observed base: 38a7072f8d23fe865b4d48d1da285a6db4fc14d1
Observed head: bf8de4b0e3f0451a496a76d87a537003b3377931

Scope: local mocks and direct validation only. No live/paid call and no credentials. These tests are external to the PR source and were written before execution.

1. `test_oversized_integer_is_schema_error_not_numeric_crash`: pass an out-of-range integer larger than a C double as candidate strength. Expected: typed `CerebrasSchemaError`, proving exact schema rejection fails closed rather than escaping `OverflowError`.
2. `test_wrapped_timeouts_count_every_attempt_within_retry_budget`: mock every `urlopen` call to raise `URLError(TimeoutError("timed out"))`, with `max_retries=2`. Expected: exactly 3 attempts, 2 retries, and 3 timeouts in the embedded failure receipt; no live network.
3. `test_http_error_receipt_redacts_key_and_pii`: local mock returns HTTP 400 whose body deliberately echoes the fake bearer key, fake email, and private task summary. Expected: one attempt (non-retryable), typed transport error, and none of those markers in the exception or embedded receipt.
4. `test_duplicate_candidate_key_is_rejected_end_to_end`: mock one HTTP 200 response whose candidate JSON contains duplicate `rank` keys. Expected: typed `CerebrasSchemaError`, no candidate returned, exactly one request, and no silent last-key-wins acceptance.

Success criterion: all four tests pass. Any exception other than the declared typed error, incorrect accounting, or disclosure is a defect; failures will be preserved and not patched.
