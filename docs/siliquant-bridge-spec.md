# SiliQuant bridge specification

This document specifies the verifier-owned SiliQuant bridge implemented in
`src/warp_modeld/siliquant_bridge.py`. Every statement below matches that code;
where a value is computed, it is the value the code computes. The bridge ingests
a SiliQuant weft payload plus a codebook receipt and verifies both against
verifier-owned expectations before accepting a Stage 2 fixed-radix certificate.

All arithmetic is exact integer arithmetic. Floats are rejected at every input
boundary. Every failure raises `CertificateError` (fail-closed).

## Inputs

### Weft payload

`ingest_weft_certificate(payload)` accepts a mapping whose key set is exactly
`PAYLOAD_KEYS`, or `PAYLOAD_KEYS` minus `{"radix_scale_exp2"}`. Any other key
set (missing or unknown keys) is rejected.

`PAYLOAD_KEYS` is the 8 weft body fields plus the 4 identity fields:

- body fields (`WEFT_BODY_FIELDS`):
  `radix_scale_exp2`, `frobenius_sq_scaled`, `spectral_norm_sq_scaled`,
  `leakage_energy_scaled`, `max_safety_dot_sq_scaled`, `projector_epoch`,
  `factor_digest`, `quant_dtype`
- identity fields: `adapter_id`, `adapter_sha256`, `base_weights_sha256`,
  `weft_sha256`

`radix_scale_exp2` is **optional** with default `DEFAULT_RADIX_EXP2 = 32`: no
SiliQuant export emits it, so a producer that never had the field keeps
working. When present it must be an exact integer in `[8, 48]`
(`WEFT_RADIX_EXP2_MIN`/`WEFT_RADIX_EXP2_MAX`); when absent, the effective radix
is `DEFAULT_RADIX_EXP2` (32) both for the Stage 2 certificate
(`radix_scale = 1 << 32`) and for the comparison against
`expected.radix_scale_exp2` in `verify_siliquant_bridge`. An omitted field can
therefore never let a payload pass under a non-default pinned radix, and a
payload that declares `radix_scale_exp2 = 48` is still rejected when the
verifier pins 32 (relabel attack).

Field types: the six scaled metrics and `projector_epoch` are exact integers
(`type(v) is int`, booleans rejected) or canonical decimal strings (ASCII,
decimal, no leading zeros except `"0"` itself); `factor_digest`,
`adapter_sha256`, `base_weights_sha256`, `weft_sha256` are 64-char lowercase
hex digests; `adapter_id` is a non-empty UTF-8-encodable string (lone
surrogates rejected); `quant_dtype` is a non-empty string.
`ingest_weft_certificate` also enforces
`spectral_norm_sq_scaled <= frobenius_sq_scaled` (inside
`FixedRadixCertificate.from_weft_dict`).

`weft_body_sha256(body)` accepts exactly `WEFT_BODY_FIELDS`, or
`WEFT_BODY_FIELDS` minus `{"radix_scale_exp2"}`; anything else is rejected. It
hashes the body fields actually present, so a producer that never had the
field hashes what it sent. The digest is
`sha256(json.dumps(dict(body), sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("utf-8")).hexdigest()`.
When `radix_scale_exp2` is present in the payload, `weft_sha256` must equal the
canonical digest of the full 8-field body (checked inside
`from_weft_dict`); when it is absent, `weft_sha256` must equal
`weft_body_sha256` of the 7-field body (checked in `ingest_weft_certificate`),
and the certificate is then ingested with `radix_scale_exp2` set to
`DEFAULT_RADIX_EXP2`.

### Codebook receipt

`_validate_receipt` / `codebook_receipt_sha256` accept a receipt mapping with
exactly one key `"certificate"`. The certificate has exactly the keys
`RECEIPT_KEYS` = `{"budget", "candidates", "pick"}`:

- `pick`: an exact integer (`type(v) is int`; booleans, floats and strings
  rejected) with `0 <= pick < len(candidates)`.
- `budget`: `None` or a `[numerator, denominator]` pair of exact integers with
  a positive numerator and a positive denominator (see the budget rule below).
- `candidates`: a nonempty list; each candidate has exactly the keys
  `CANDIDATE_KEYS` = `{"arm", "size", "codewords", "terms"}`:
  - `arm` must be in `SILIQUANT_ARMS`;
  - `size` a positive exact integer (or canonical decimal string) and a
    multiple of 8;
  - `codewords` a positive exact integer;
  - `terms` a mapping with exactly the six keys
    `TERM_KEYS` = `{"count", "groups", "sum_sq", "top_cube", "top_ball", "top_cross"}`,
    each an exact integer or canonical decimal string; `count`, `groups` and
    `sum_sq` must be positive, the `top_*` terms non-negative.

`codebook_receipt_sha256(receipt)` is
`sha256(json.dumps(cert, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()`
over the validated certificate dict.

## Verifier-owned expectations

`verify_siliquant_bridge` requires a `SiliquantExpectations` instance (frozen
dataclass). Each field pins one property of the payload, receipt or checker:

| field | type | what it pins |
| --- | --- | --- |
| `quant_dtype` | str | must be in `SILIQUANT_QUANTIZATIONS` = `{"siliquant_4_5", "siliquant_e8", "siliquant_ballpack"}` and must equal the payload's `quant_dtype` |
| `projector_epoch` | int | exact non-negative integer; must equal the payload's `projector_epoch` |
| `factor_digest` | str | 64-char lowercase hex; must equal the payload's `factor_digest` |
| `weft_sha256` | str | 64-char lowercase hex; must equal the payload's `weft_sha256` (which is itself bound to the body fields, see above) |
| `arm` | str | must be in `SILIQUANT_ARMS` = `{"X", "Z8:p1", "Z8:p2", "E8:p1", "E8:p2"}` and must equal the picked candidate's `arm`; must also satisfy the quant/arm coherence rule below |
| `budget` | (int, int) | exact integer pair with positive numerator and denominator; must equal the receipt's `budget` |
| `receipt_sha256` | str | 64-char lowercase hex; must equal `codebook_receipt_sha256(codebook_receipt)` |
| `checker_sha256` | str | 64-char lowercase hex; must equal the SHA-256 of the checker file's bytes |
| `radix_scale_exp2` | int, **optional, default `DEFAULT_RADIX_EXP2` = 32** | exact integer in `[8, 48]`; the payload's effective radix (its declared value, or 32 when the field is omitted) must equal it |

`verify_siliquant_bridge` additionally requires `expected_adapter_id`,
`expected_adapter_sha256` and `expected_base_weights_sha256`, which are checked
against the payload/certificate by the Stage 2 `verify_division_free` call,
and it requires both a `codebook_receipt` and a `checker_path` (both `None` is
rejected).

## quant_dtype to arm coherence (E8 rule)

The rule is computed by `_derive_quant_arm_prefixes` and stored in
`QUANT_ARM_PREFIXES`: for each quantization in `SILIQUANT_QUANTIZATIONS`, the
suffix after `"siliquant_"` (uppercased) is compared with the root of each arm
in `SILIQUANT_ARMS` (the part before `":"`, uppercased); if they match, the
quantization may only use arms starting with that root followed by `":"`.

The computed table is:

| quant_dtype | required arm prefix |
| --- | --- |
| `siliquant_e8` | `"E8:"` (so only `E8:p1` or `E8:p2`) |
| `siliquant_4_5` | none (any arm in `SILIQUANT_ARMS`) |
| `siliquant_ballpack` | none (any arm in `SILIQUANT_ARMS`) |

i.e. `QUANT_ARM_PREFIXES == {"siliquant_e8": "E8:"}`. A quantization whose name
embeds no arm root of `SILIQUANT_ARMS` accepts any arm in `SILIQUANT_ARMS`.
`SiliquantExpectations.__post_init__` enforces this: `siliquant_e8` requires an
arm starting with `"E8:"`, and any other combination from the table above is
rejected with `CertificateError`.

## Budget rule

`_validate_budget` requires a list/tuple of exactly two exact integers
(`type(v) is int`, booleans rejected) whose bit lengths are each at most 1024,
with `numerator > 0` and `denominator > 0`. It is applied to the receipt's
`budget`, to `expected.budget`, and to `expected_budget` when passed to
`verify_codebook_pick`. Negative or zero numerators (e.g. `(-5, 1)`, `(0, 1)`)
are rejected.

## Input caps

Decimal strings are capped at `_MAX_DECIMAL_DIGITS = 1024` digits and integers
at `_MAX_INT_BITS = 1024` bits, checked before any `int()`, `json.dumps()` or
`str()` conversion, so oversized inputs raise `CertificateError` instead of a
raw `ValueError`. This applies to every integer field of the payload, the weft
body, the receipt (budget, size, codewords, terms) and the expectations.

## Checker pinning

`load_siliquant_checker(checker_path, *, expected_checker_sha256=...)`:

- `checker_path` must be a `str` or `pathlib.Path` (bytes rejected), free of
  NUL bytes and UTF-8 encodable (lone surrogates rejected);
- the path must not be a symlink and must not live under a symlinked directory
  (symlinks are never followed or executed);
- the path must be an existing file, opened with `O_NOFOLLOW`;
- `expected_checker_sha256` is **required** (a `None` default is rejected) and
  must be a 64-char lowercase hex digest; the file's SHA-256 is compared to it
  with `hmac.compare_digest` before the source is executed via
  `exec(compile(source, ...))`;
- the loaded module must expose callable `check`, `identities` and
  `pi_bounds_hold`.

`verify_codebook_pick` requires `checker.identities() is True`,
`checker.pi_bounds_hold() is True`, and `checker.check(cert)` to return a
`list` or `tuple` of findings that is empty; any findings reject the pick, and
non-list/tuple returns are rejected.

## What the bridge does NOT prove

Scope copied from the "Known limits" section of `docs/alpha-readiness.md`:

- Real llama-server/GGUF lifecycle, Linux image boot, bare-metal recovery,
  CUDA multi-adapter checks, and real Lattice hardware remain untested here.
- The SiliQuant codebook receipt proves the best predicted pick among supplied
  candidates. It does not prove Frobenius, spectral, leakage, safety, adapter
  quality, or model quality.

In addition, as documented on `SiliquantExpectations`: the weft body norms
(`frobenius_sq_scaled`, `spectral_norm_sq_scaled`, `leakage_energy_scaled`,
`max_safety_dot_sq_scaled`) remain self-attested — the `weft_sha256` digest
binds the payload to the verifier's expected digest, but the norms themselves
are producer-declared and are only checked against the verifier's
`CertificateBounds` by the Stage 2 `verify_division_free` call; they are not
derived from adapter bytes here.
