# Study-Only Zero-Float Reference: Frozen Experiment Contract, 5-Op Bounded Controller & Redacted Advisory Boundary

> **Scope & Deduplication Notice (Study-Only Reference — Does NOT Close Issues `#4`, `#5`, or `#6`):**
> This directory is a **self-contained, study-only zero-float reference implementation** under `studies/expedition-bounded-controller/` (zero edits to `src/warp_modeld/`, `blueprints/`, `experiments/`, or `tests/`). It uses **synthetic placeholder digests and toy suites** to formally verify zero-float trust-boundary mechanics (the `385`-state monotone reconciler, exact `Fraction` Goodhart KL latch, Ring-0 lock, Gate-8 fence, strict duplicate-key JSON, and allowlisted egress). **Production lane closures belong to `@ahrazzle`'s shipped PRs (`PR #8` for Issue `#4` with real pinned `Qwen3.5-4B-Q8_0.gguf`/`ml-os`/`weft` digests, `PR #10` for Issue `#5`, and merged `PR #9` for Issue `#6`).** Explicitly labeled **`project-specific-weight-experiment-harness`** — **NOT** a standardized interoperable W-MCP interface.

Every module uses **only Python 3's standard library** (zero third-party runtime dependencies, zero external clones required, zero floats on trust paths or in JSON certificates, zero bare `assert` statements), passes `4/4` isolated `-I` deterministic replay (`-I -B`, `-I -O -B`, `-I -B -W error`, `-I -O -B -W error`), verifies live Stage 1 & Stage 2 `AdapterBundle` compatibility directly against the shipped [`src/warp_modeld/`](../../src/warp_modeld/verifier.py), and achieves **`159/159` (`100.0%`)** AST mutation kill rate (`aletheia v2.0.0 mutate --max-mutants 0 --add-cwd`: `58/58` `experiment_contract.py` + `101/101` `bounded_controller.py`) across both core modules.

> **Evidence Boundary Disclosure:**
> All controller runs in this study use explicitly marked fake compiler/runtime adapters (`evidence_scope: "logic_check_fake_runtime"`), synthetic placeholder digests, fixture timings aggregated from mock ledger receipts (`timing_source: "aggregated_from_mock_ledger_receipts_not_wall_clock"`), a deterministic tamper-evidence-only study HMAC key (`resolve_study_hmac_key`, overridable via `WARP_STUDY_HMAC_KEY` or explicit parameter; `ledger_hmac_scope: "tamper_evidence_only_not_external_secrecy"`), and a mock Cerebras transport (`transport_mode: "mock_contract"`, `live_credentials_used: false`, `live_rtx3080_checkpoint_scored: false`). They verify schema enforcement, split-leakage rejection, Ring-0 immutability, hash-before-eval ordering, deterministic local authority over advisory judge votes, multi-bank rollback enforcement, and Stage 1/2 `warp_modeld` compatibility — they are **logic and trust-boundary checks**, NOT empirical evidence of adapted-model quality on live RTX 3080 weights.

---

## Manifest

| File | Audit | Role & Exact Integrity |
|---|---|---|
| [`experiment_contract.py`](./experiment_contract.py) | `AUDIT-063R2` + PR `#13` + Issue `#29` closure | Study reference for versioned frozen manifest (`warp-experiment-contract/v0.1`), deep-copied isolation in `validate_frozen_manifest`, `FROZEN.md` `min_reader_version` & unknown-field preservation, recursive case-insensitive Ring-0 lock requiring matching `contract_sha256` on proposals (`ERR_CONTRACT_DRIFT` when omitted or mismatched), `\A...\Z` digest/layer validation, `98%`-trap split-leakage auditor, strict duplicate-key JSON (`SHA-256`: `10a754a6...`, **`58/58` `100.0%` R5 killed**) |
| [`bounded_controller.py`](./bounded_controller.py) | `AUDIT-063R2` + PR `#13` + Issue `#29` closure | Study reference for 5-op bounded controller (`propose_candidate`, `compile_and_bind`, `evaluate`, `promote_or_reject`, `rollback`) with manifest-integrity enforcement across all 5 ops, deep-copied callback isolation & post-runtime manifest/adapter-hash checks (`ERR_MANIFEST_TAMPERED`, `ERR_ADAPTER_HASH_DRIFT`), `rollback()` transitioning `phase` cleanly to `"RolledBack"`, self-contained `eval_record`, `unchanged_base` zero-task-gain check, exhaustive `385`-state monotone `(Phase, Contact)` reconciler lattice, exact `Fraction` affine clock-pair & `+55%` Goodhart KL latch, HMAC hash-chained ledger, closed-enum/regex egress on `propose()` & `diagnose()` (`candidate_id` `\A[a-z0-9][a-z0-9_-]{0,31}\Z`, closed enums for `verdict`, `failed_gate`, `failures`, `quantizations`) plus bounded free text (`<= 4096` chars, NUL-free) on `compare()`, and ANSI/NUL-sanitized rejected/error receipts (`SHA-256`: `698f4090...`, **`101/101` `100.0%` R5 killed**) |
| [`verify_bounded_controller.py`](./verify_bounded_controller.py) | `AUDIT-063R2` + PR `#13` + Issue `#29` closure | End-to-end 3-round loop + `19/19` adversarial trust-boundary matrix + env/parameter HMAC key resolver (`resolve_study_hmac_key`, zero hardcoded `SECRET_KEY`) + ledger-aggregated mock timings + in-repo `src/warp_modeld` Stage 1 & Stage 2 verification (`SHA-256`: `ef4be747...`; `-I -O -B -W error --json` stdout SHA-256 `d39c6f8def62c7adffc1245c062faf7b3fd96db623261a938f8482af454f3c46`; `--standalone` SHA-256 `48a86fa62c5e776198bd98a0b9442ea635f6fee9faaf5d050866afb90cdf376e`) |
| [`test_bounded_controller_r5.py`](./test_bounded_controller_r5.py) | `AUDIT-063R2` + PR `#13` + Issue `#29` closure | R5 refusal-site mutation, single-guard callback isolation, base64 egress rejection, & exact-invariant test suite (`SHA-256`: `83113417...`; `6/6` groups PASS; `-I -O -B -W error` stdout SHA-256 `8731a50db3c2573f0ebe8fdda7bc73deea7cc2d2a9b394b0300e285e795d45ce`) |
| [`bounded_controller_certificate.json`](./bounded_controller_certificate.json) | `AUDIT-063R2` + PR `#13` + Issue `#29` closure | Canonical zero-float JSON certificate (`SHA-256`: `d39c6f8d...`, `canonical_sha256`: `db22ca9521b4525aee7bd76c50a40b56bca8f294c678f1effd71ff7de5404fed`) |
| [`BOUNDED_CONTROLLER_REPORT.md`](./BOUNDED_CONTROLLER_REPORT.md) | `AUDIT-063R2` + PR `#13` + Issue `#29` closure | Full study-reference architecture mapping, red-team bypass closures (`CTRL-BYPASS-1..10` + Issue `#29`), and Law-4 `N0`/`N1` quarantine |

---

## Quick Reproduction (All 4 Isolated `-I` R4 Modes)

Run from the repository root (`Moissanite-Labs/warp-drive/`):

```bash
# 1. End-to-end verifier + in-repo src/warp_modeld Stage 1/2 check (4 isolated modes):
for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $f studies/expedition-bounded-controller/verify_bounded_controller.py --json | sha256sum
done
# Expected (all 4 modes): d39c6f8def62c7adffc1245c062faf7b3fd96db623261a938f8482af454f3c46

# 2. Pure standalone mode (zero dependency on src/warp_modeld):
python3 -I -O -B -W error studies/expedition-bounded-controller/verify_bounded_controller.py --standalone | sha256sum
# Expected: 48a86fa62c5e776198bd98a0b9442ea635f6fee9faaf5d050866afb90cdf376e

# 3. R5 refusal-site & exact-invariant test suite (6/6 groups PASS):
python3 -I -O -B -W error studies/expedition-bounded-controller/test_bounded_controller_r5.py | sha256sum
# Expected: 8731a50db3c2573f0ebe8fdda7bc73deea7cc2d2a9b394b0300e285e795d45ce

# 4. Existing warp-drive baseline suite (105 tests discovered: 103 pass, 2 live-GGUF/optional skipped):
PYTHONPATH=src python3 -B -W error -m unittest discover -s tests
```

---

## Summary of Capabilities Addressed

1. **Issue `#4` (Frozen Experiment Contract & Split-Leakage Audit):**
   - Pins base GGUF/tokenizer/chat-template digests, runtime flags, `siliconcordat/weft` compiler commit (explicitly rejecting `Moissanite-Labs/weft` per Issue `#2`), Plane 1 lineage (`contested_heads == []`), single pinned last-layer target (`blk.31`), allowed candidate knobs, exact rational thresholds (`100%` safety floor, `0` rollback logit diff), max `3` repair rounds, Gate-8 `plan_commit != data_commit` preregistration fence, required matching `contract_sha256` on proposals (`ERR_CONTRACT_DRIFT` when omitted or mismatched), and forward-compatible unknown-field preservation.
   - Reproduces and rejects a `49/50` (`98%`) pair-overlap leaky split (`ERR_SPLIT_LEAKAGE`) while certifying a `0/24` family-, prompt-, and pair-disjoint split.
2. **Issue `#5` (5-Op Bounded Controller & Monotone `385`-State Reconciler):**
   - Implements `propose_candidate`, `compile_and_bind` (recording `candidate_adapter_sha256` before evaluation), `evaluate` (signed exact rational `task_exact_gain` & `logprob_margin_delta`, exact Goodhart KL latch catching `ml-os#6`'s `+55%` preconditioning KL blowup), `promote_or_reject` (enforcing frozen local thresholds strictly and preventing non-`candidate` roles from ever promoting), and `rollback` (deriving mandatory state banks `kv_cache`, `ssm_recurrent`, `lattice_horizontal_streams` from the frozen `base_checkpoint` pin, requiring exact `0` baseline logit diff, and transitioning `candidate_state(cid)["phase"]` to `"RolledBack"`).
   - Exhaustively certifies all `385/385` `(Phase, Contact, Obs)` transitions (`0` phase regressions, `0` terminal swaps, `0` outage-fabricated verdicts, `0` duplicate terminal notices, `32` tombstone resolutions) and verifies the `23`-receipt HMAC-SHA256 tamper-evidence chain independently (`head_sha256: e8a4085f...`).
3. **Issue `#6` (Redacted Kimi-on-Cerebras Advisory Boundary):**
   - Bounds Cerebras/Kimi to `propose`, `diagnose`, and `compare`. On `propose()` and `diagnose()`, egress enforces strict allowlisted keys, exact integers, 64-hex `contract_sha256`, `blk.<idx>` layer, closed enums (`verdict`, `failed_gate`, `failures`, `quantizations`), and `<= 32`-char lowercase `[a-z0-9_-]` `candidate_id` tokens (rejecting unlisted keys, forbidden weight/secret/LoRA keys, and base64-encoded payloads before transport). On `compare()`, `case_id` obeys the same identifier regex while `baseline_text` and `adapted_text` carry bounded free text (`<= 4096` chars each, NUL-free) by design for prose comparison. Rejects silent model substitution (`ERR_MODEL_SUBSTITUTION`), validates strict duplicate-key JSON, provider metadata, and response schemas *before* logging `"status": "ok"` receipts, and proves local deterministic gates override a positive `"BETTER"` judge vote on the regressed plausible-text control.
4. **Live `src/warp_modeld` Stage 1 & Stage 2 Compatibility:**
   - Directly invokes [`src/warp_modeld/fingerprint.py`](../../src/warp_modeld/fingerprint.py) (`AdapterBundle.from_dict`, `verify_stage1`) and [`src/warp_modeld/certificate.py`](../../src/warp_modeld/certificate.py) (`verify_stack_division_free`) against the promoted candidate bundle across all 3 required state banks (`stage1_and_stage2_passed: true`), alongside [`PLAN.md`](../../PLAN.md) and [`ARCHITECTURE.md`](../../ARCHITECTURE.md).

See [`BOUNDED_CONTROLLER_REPORT.md`](./BOUNDED_CONTROLLER_REPORT.md) for the complete architecture cross-map, red-team bypass audit (`CTRL-BYPASS-1..10`), and Law-4 `N0`/`N1` quarantine.
