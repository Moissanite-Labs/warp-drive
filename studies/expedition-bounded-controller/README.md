# Study-Only Zero-Float Reference: Frozen Experiment Contract, 5-Op Bounded Controller & Redacted Advisory Boundary

> **Scope & Deduplication Notice (Study-Only Reference — Does NOT Close Issues `#4`, `#5`, or `#6`):**
> This directory is a **self-contained, study-only zero-float reference implementation** under `studies/expedition-bounded-controller/` (zero edits to `src/warp_modeld/`, `blueprints/`, `experiments/`, or `tests/`). It uses **synthetic placeholder digests and toy suites** to formally verify zero-float trust-boundary mechanics (the `385`-state monotone reconciler, exact `Fraction` Goodhart KL latch, Ring-0 lock, Gate-8 fence, strict duplicate-key JSON, and allowlisted egress). **Production lane closures belong to `@ahrazzle`'s shipped PRs (`PR #8` for Issue `#4` with real pinned `Qwen3.5-4B-Q8_0.gguf`/`ml-os`/`weft` digests, `PR #10` for Issue `#5`, and merged `PR #9` for Issue `#6`).** Explicitly labeled **`project-specific-weight-experiment-harness`** — **NOT** a standardized interoperable W-MCP interface.

Every module uses **only Python 3's standard library** (zero third-party runtime dependencies, zero external clones required, zero floats on trust paths or in JSON certificates, zero bare `assert` statements), passes `4/4` isolated `-I` deterministic replay (`-I -B`, `-I -O -B`, `-I -B -W error`, `-I -O -B -W error`), verifies live Stage 1 & Stage 2 `AdapterBundle` compatibility directly against the shipped [`src/warp_modeld/`](../../src/warp_modeld/verifier.py), and achieves **`155/155` (`100.0%`)** AST mutation kill rate (`aletheia v2.0.0 mutate --max-mutants 0 --add-cwd`: `57/57` `experiment_contract.py` + `98/98` `bounded_controller.py`) across both core modules.

> **Evidence Boundary Disclosure:**
> All controller runs in this study use explicitly marked fake compiler/runtime adapters (`evidence_scope: "logic_check_fake_runtime"`), synthetic placeholder digests, and a mock Cerebras transport (`transport_mode: "mock_contract"`, `live_credentials_used: false`, `live_rtx3080_checkpoint_scored: false`). They verify schema enforcement, split-leakage rejection, Ring-0 immutability, hash-before-eval ordering, deterministic local authority over advisory judge votes, multi-bank rollback enforcement, and Stage 1/2 `warp_modeld` compatibility — they are **logic and trust-boundary checks**, NOT empirical evidence of adapted-model quality on live RTX 3080 weights.

---

## Manifest

| File | Audit | Role & Exact Integrity |
|---|---|---|
| [`experiment_contract.py`](./experiment_contract.py) | `AUDIT-063R2` + PR `#13` review closure | Study reference for versioned frozen manifest (`warp-experiment-contract/v0.1`), deep-copied isolation in `validate_frozen_manifest`, `FROZEN.md` `min_reader_version` & unknown-field preservation, recursive case-insensitive Ring-0 lock, `\A...\Z` digest/layer validation, `98%`-trap split-leakage auditor, strict duplicate-key JSON (`SHA-256`: `4a638374...`, **`57/57` `100.0%` R5 killed**) |
| [`bounded_controller.py`](./bounded_controller.py) | `AUDIT-063R2` + PR `#13` review closure | Study reference for 5-op bounded controller (`propose_candidate`, `compile_and_bind`, `evaluate`, `promote_or_reject`, `rollback`) with manifest-integrity enforcement across all 5 ops, non-mapping callback rejection, post-callback manifest & adapter-hash tamper checks (`ERR_MANIFEST_TAMPERED`, `ERR_ADAPTER_HASH_DRIFT`), self-contained `eval_record` (`live_checkpoint_digest` + `live_adapter_sha256`), `unchanged_base` zero-task-gain check, exhaustive `385`-state monotone `(Phase, Contact)` reconciler lattice, exact `Fraction` affine clock-pair & `+55%` Goodhart KL latch, HMAC hash-chained ledger, strict allowlisted egress across both `propose()` (`validate_history_summary_egress` + manifest projection) and `diagnose()` (`validate_failure_report_egress`), and ANSI/NUL-sanitized rejected/error receipt recording on malformed provider metadata (`SHA-256`: `9a5cc14b...`, **`98/98` `100.0%` R5 killed**) |
| [`verify_bounded_controller.py`](./verify_bounded_controller.py) | `AUDIT-063R2` + PR `#13` review closure | End-to-end 3-round loop + `18/18` adversarial trust-boundary matrix + in-repo `src/warp_modeld` Stage 1 & Stage 2 verification (`SHA-256`: `ee84b17a...`; `-I -O -B -W error --json` stdout SHA-256 `8edb2118b8dda3989ddddb46a35decac6234ab72a32d36a03082f212da6bec8a`; `--standalone` SHA-256 `cfd28fd86de90094b1a5513828f3da2cbc49d13aded9d68345280605eb707b98`) |
| [`test_bounded_controller_r5.py`](./test_bounded_controller_r5.py) | `AUDIT-063R2` + PR `#13` review closure | R5 refusal-site mutation, adversarial callback regression, & exact-invariant test suite (`SHA-256`: `641f04d5...`; `6/6` groups PASS; `-I -O -B -W error` stdout SHA-256 `8731a50db3c2573f0ebe8fdda7bc73deea7cc2d2a9b394b0300e285e795d45ce`) |
| [`bounded_controller_certificate.json`](./bounded_controller_certificate.json) | `AUDIT-063R2` + PR `#13` review closure | Canonical zero-float JSON certificate (`SHA-256`: `8edb2118...`, `canonical_sha256`: `5200107049fd9abd05d885b90db2a486c4758dc9206a06c762a32419f2a21cde`) |
| [`BOUNDED_CONTROLLER_REPORT.md`](./BOUNDED_CONTROLLER_REPORT.md) | `AUDIT-063R2` + PR `#13` review closure | Full study-reference architecture mapping, red-team bypass closures (`CTRL-BYPASS-1..10`), and Law-4 `N0`/`N1` quarantine |

---

## Quick Reproduction (All 4 Isolated `-I` R4 Modes)

Run from the repository root (`Moissanite-Labs/warp-drive/`):

```bash
# 1. End-to-end verifier + in-repo src/warp_modeld Stage 1/2 check (4 isolated modes):
for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $f studies/expedition-bounded-controller/verify_bounded_controller.py --json | sha256sum
done
# Expected (all 4 modes): 8edb2118b8dda3989ddddb46a35decac6234ab72a32d36a03082f212da6bec8a

# 2. Pure standalone mode (zero dependency on src/warp_modeld):
python3 -I -O -B -W error studies/expedition-bounded-controller/verify_bounded_controller.py --standalone | sha256sum
# Expected: cfd28fd86de90094b1a5513828f3da2cbc49d13aded9d68345280605eb707b98

# 3. R5 refusal-site & exact-invariant test suite (6/6 groups PASS):
python3 -I -O -B -W error studies/expedition-bounded-controller/test_bounded_controller_r5.py | sha256sum
# Expected: 8731a50db3c2573f0ebe8fdda7bc73deea7cc2d2a9b394b0300e285e795d45ce

# 4. Existing warp-drive baseline suite (unchanged, 58 tests discovered: 57 pass, 1 live-GGUF skipped):
PYTHONPATH=src python3 -B -m unittest discover -s tests
```

---

## Summary of Capabilities Addressed

1. **Issue `#4` (Frozen Experiment Contract & Split-Leakage Audit):**
   - Pins base GGUF/tokenizer/chat-template digests, runtime flags, `siliconcordat/weft` compiler commit (explicitly rejecting `Moissanite-Labs/weft` per Issue `#2`), Plane 1 lineage (`contested_heads == []`), single pinned last-layer target (`blk.31`), allowed candidate knobs, exact rational thresholds (`100%` safety floor, `0` rollback logit diff), max `3` repair rounds, Gate-8 `plan_commit != data_commit` preregistration fence, and forward-compatible unknown-field preservation.
   - Reproduces and rejects a `49/50` (`98%`) pair-overlap leaky split (`ERR_SPLIT_LEAKAGE`) while certifying a `0/24` family-, prompt-, and pair-disjoint split.
2. **Issue `#5` (5-Op Bounded Controller & Monotone `385`-State Reconciler):**
   - Implements `propose_candidate`, `compile_and_bind` (recording `candidate_adapter_sha256` before evaluation), `evaluate` (signed exact rational `task_exact_gain` & `logprob_margin_delta`, exact Goodhart KL latch catching `ml-os#6`'s `+55%` preconditioning KL blowup), `promote_or_reject` (enforcing frozen local thresholds strictly and preventing non-`candidate` roles from ever promoting), and `rollback` (deriving mandatory state banks `kv_cache`, `ssm_recurrent`, `lattice_horizontal_streams` from the frozen `base_checkpoint` pin and requiring exact `0` baseline logit diff).
   - Exhaustively certifies all `385/385` `(Phase, Contact, Obs)` transitions (`0` phase regressions, `0` terminal swaps, `0` outage-fabricated verdicts, `0` duplicate terminal notices, `32` tombstone resolutions) and verifies the `23`-receipt HMAC-SHA256 chain independently (`head_sha256: 77a347dc...`).
3. **Issue `#6` (Redacted Kimi-on-Cerebras Advisory Boundary):**
   - Bounds Cerebras/Kimi to `propose`, `diagnose`, and `compare` over fixed text & structured reports only (`validate_failure_report_egress` + `sanitize_outbound_payload` block arbitrary keys, weights, tensors, secrets, and raw LoRAs before transport), rejects silent model substitution (`ERR_MODEL_SUBSTITUTION`), validates strict duplicate-key JSON, provider metadata, and response schemas *before* logging `"status": "ok"` receipts (logging `"status": "rejected"`/`"error"` redacted receipts on all failures), and proves local deterministic gates override a positive `"BETTER"` judge vote on the regressed plausible-text control.
4. **Live `src/warp_modeld` Stage 1 & Stage 2 Compatibility:**
   - Directly invokes [`src/warp_modeld/fingerprint.py`](../../src/warp_modeld/fingerprint.py) (`AdapterBundle.from_dict`, `verify_stage1`) and [`src/warp_modeld/certificate.py`](../../src/warp_modeld/certificate.py) (`verify_stack_division_free`) against the promoted candidate bundle across all 3 required state banks (`stage1_and_stage2_passed: true`), alongside [`PLAN.md`](../../PLAN.md) and [`ARCHITECTURE.md`](../../ARCHITECTURE.md).

See [`BOUNDED_CONTROLLER_REPORT.md`](./BOUNDED_CONTROLLER_REPORT.md) for the complete architecture cross-map, red-team bypass audit (`CTRL-BYPASS-1..10`), and Law-4 `N0`/`N1` quarantine.
