# Ratchet 001 post-baseline blind review

## Blinding record

- Run: `108f1b8a-4b4f-4476-88e9-5c0032280bd6`.
- Child session: `agent:main:subagent:16a30aa6-897c-4325-93b7-35af14d0e295`.
- Model tier: `cerebras/moonshotai-kimi-k3.1-pro-trial`.
- Context: isolated and marked blind. No baseline scores, observations, receipts, corpus, harness, pull-request discussion, or repair hypotheses were supplied.
- Scope: read-only static audit of the frozen candidate boundary and same-file helpers. The reviewer did not execute the candidate or edit files.
- Verified candidate source SHA-256: `4d04687cb70b86a4b91e4661f16d6292b81c4760f60931f9bbf8228ca9dfb15d`.
- Independence limit: this was a separate-context review on the same model tier, not an independent-vendor review.

The Goodhart latch is released only for a separately versioned evaluation portal. Ratchet 001 remains unchanged and cannot acquire new cases or an improvement claim.

## Reviewer report

For the concrete secret case, let `H` be:

```python
H = {
    "vocab_clip": Fraction(0), "bregman_normalized": False,
    "fused_serving_artifact": False, "fused_outputs_rejudged": False,
    "quick_dream_enabled": False,
    "rule_requires_explicit_user_approval": False,
    "review_fail_closed": False, "hindsight_fence_escaped": True,
    "control_requires_bearer_token": True,
    "installation_id_publicly_disclosed": False,
    "root_routes_guarded": True,
    "base_fingerprint_mode": "content_sha256",
    "includes_tokenizer_and_gguf": True, "base_sha256": "a" * 64,
    "body_secret_redaction_enabled": True,
    "sample_recorded_body": "[REDACTED]",
    "strict_json_verdict_only": True,
    "runtime_pip_require_hashes": True,
    "eval_temperature": 0, "eval_top_p": 1,
}
```

### Definite defect 1: High. Valid bearer secrets can pass redaction governance

Source: lines 29–35, 424–428, 473–478.

`Bearer` matching is case-sensitive and requires at least eight token characters. HTTP authentication scheme names are case-insensitive, and bearer syntax does not establish that minimum length.

Minimal input:

```python
{**H, "sample_recorded_body": "Authorization: bearer abcdefghij"}
```

`"Authorization: Bearer abc"` is another missed form.

Actual: neither regex matches. With `H` otherwise unchanged, the result is `{"admitted": True, "reasons": []}`.

Contract-consistent: reject with `admitted=False` and `BODY_SECRET_REDACTION_MISSING`. Enabling redaction must not certify a body still containing a recognized credential.

### Definite defect 2: Medium. Malformed configurations raise instead of producing a closed verdict

Source: direct indexing throughout lines 434–488. Nominal result construction occurs at line 490.

Minimal input: `{}`.

Actual: raises `KeyError("vocab_clip")` at line 435. Other missing fields and non-mapping inputs similarly escape the declared dictionary-returning boundary.

Contract-consistent: return a structured rejection, or explicitly document a denial exception handled by every caller. As written, fail-closed behavior depends on unspecified caller exception handling. This is an availability/integration defect rather than a demonstrated `admitted=True` bypass.

### Ambiguities and residual source-only risks

- Attestations are not artifact verification. Lines 442–489 accept booleans for fused rejudging, fence escaping, bearer/root guards, strict JSON, and hash-required installs without inspecting the corresponding artifacts or operations. Likewise, lines 467–472 validate only the digest’s lowercase hexadecimal syntax.

  For example, `{**H, "base_sha256": "0" * 64}` is admitted. No tokenizer/GGUF bytes are hashed or bound to that value. This is a definite limitation, but only a defect if this function, rather than an upstream attestation producer, is expected to establish those facts.
- Uppercase SHA-256 text is rejected because lines 27–28 and 184–189 permit only lowercase. That is fail-closed and harmless if lowercase canonical encoding is intentional.
- No additional admission bypass was found in the reviewed type checks. Sampling requires exact `Fraction` or non-Boolean `int` values equal to temperature `0` and top-p `1`. Positive clipped KL requires Bregman normalization. Fused serving requires rejudging. The boolean security controls use strict identity checks.

## Parent disposition after unblinding

The two bearer variants are new must-reject cases for ratchet 002. The malformed-configuration finding is already represented by preserved v1 operational failures and supports testing structured rejection in v2. The attestation limitation remains explicitly out of scope for this source-only boundary. No artifact-verification capability is claimed.
