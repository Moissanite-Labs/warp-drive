## Request changes: three reproduced client-boundary defects

Reviewed head `bf8de4b0e3f0451a496a76d87a537003b3377931` against base `38a7072f8d23fe865b4d48d1da285a6db4fc14d1` in a clean detached checkout with Python 3.14.6.

### 1. Provider error bodies defeat receipt redaction

At `src/warp_modeld/cerebras_client.py:442-450`, the raw HTTP response body enters `detail`, then `failures` and the raised exception. `ProviderReceipt.to_dict()` serializes that list at line 163.

A mocked HTTP 400 response containing `fake-key`, `alice@example.invalid`, and `private acquisition planning` reproduced all three markers in the exception and `receipt["failures"]`. Provider-controlled response text must not be copied into redacted receipts.

Minimal witness: `test_http_error_receipt_redacts_key_and_pii`.

### 2. Wrapped socket timeouts are omitted from timeout accounting

At `cerebras_client.py:455-460`, only a top-level `TimeoutError` increments `timeouts`. A `URLError(TimeoutError("timed out"))` is recorded as a generic transport failure.

With `max_retries=2` and zero retry delay, the mocked client made exactly three attempts and recorded two retries, but reported `timeouts=0`. The retry bound held. The timeout receipt did not. Expected `timeouts=3`.

Minimal witness: `test_wrapped_timeouts_count_every_attempt_within_retry_budget`.

### 3. Oversized integers escape typed schema validation

At `cerebras_client.py:169-170` and `:189-191`, `math.isfinite(value)` converts an arbitrarily large integer to float and raises `OverflowError`.

Calling `validate_candidate()` with otherwise valid fields and `strength=10 ** 10000` produced `OverflowError: int too large to convert to float`, not the declared `CerebrasSchemaError`. No candidate was accepted, but the typed fail-closed boundary and its receipt behavior were not preserved.

Minimal witness: `test_oversized_integer_is_schema_error_not_numeric_crash`.

### Test evidence

Adversarial expectations were recorded before execution in `ADVERSARIAL_PLAN.md`. Its SHA-256 is `8830067d57b432903c258d00ed61f1b5fe3cf6b4583d83d4b21b9a62904cbaac`. The external test source SHA-256 is `da38fa1e7c32ab9b33052487e38bef2700e2dbd96e93fb084e4fcefcd93408b4`.

- Focused PR tests: 34 run, 33 passed, 1 optional live test skipped.
- Full repository suite: 92 run, 90 passed, 2 optional live tests skipped.
- Four preregistered adversarial methods ran. Duplicate candidate-key rejection passed. The other three methods exposed the defects above.
- Both available checks report `SUCCESS`: `Analyze (python)` and `CodeQL`.

All adversarial transport was local or mocked. No credentials, paid calls, or live provider requests were used. These results establish client control flow only, not live model behavior.
