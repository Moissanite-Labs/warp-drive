# Frozen Experiment Contract, 5-Op Bounded Controller, and Redacted Cerebras/Kimi Advisory Boundary (Issues `#3`, `#4`, `#5`, `#6`)

Self-contained, zero-edit study packaged under `studies/expedition-bounded-controller/` (leaving `src/warp_modeld/`, `blueprints/`, and `tests/` completely untouched). Explicitly labeled **`project-specific-weight-experiment-harness`** — **NOT** a standardized interoperable W-MCP interface.

Every module uses **only Python 3's standard library** (zero third-party runtime dependencies, zero external clones required, zero floats on trust paths or in JSON certificates, zero bare `assert` statements), passes `4/4` isolated `-I` deterministic replay (`-I -B`, `-I -O -B`, `-I -B -W error`, `-I -O -B -W error`), verifies live Stage 1 & Stage 2 `AdapterBundle` compatibility directly against the shipped [`src/warp_modeld/`](../../src/warp_modeld/verifier.py), and achieves **`126/126` (`100.0%`)** AST mutation kill rate (`aletheia v1.3.0 mutate --add-cwd`) across both core modules.

> **Evidence Boundary Disclosure (Issues `#4`, `#5`, `#6`, `#7`):**
> All controller runs in this study use explicitly marked fake compiler/runtime adapters (`evidence_scope: "logic_check_fake_runtime"`) and a mock Cerebras transport (`transport_mode: "mock_contract"`, `live_credentials_used: false`, `live_rtx3080_checkpoint_scored: false`). They verify schema enforcement, split-leakage rejection, Ring-0 immutability, hash-before-eval ordering, deterministic local authority over advisory judge votes, multi-bank rollback enforcement, and Stage 1/2 `warp_modeld` compatibility — they are **logic and trust-boundary checks**, NOT empirical evidence of adapted-model quality on live RTX 3080 weights.

---

## Manifest

| File | Audit | Role & Exact Integrity |
|---|---|---|
| [`experiment_contract.py`](./experiment_contract.py) | `AUDIT-063R2` | Issue `#4` versioned frozen manifest (`warp-experiment-contract/v0.1`), `FROZEN.md` `min_reader_version` & unknown-field preservation, recursive case-insensitive Ring-0 lock, `\A...\Z` digest/layer validation, `98%`-trap split-leakage auditor, strict duplicate-key JSON (`SHA-256`: `557d9af9...`, **`57/57` `100.0%` R5 killed**) |
| [`bounded_controller.py`](./bounded_controller.py) | `AUDIT-063R2` | Issue `#5` 5-op bounded controller (`propose_candidate`, `compile_and_bind`, `evaluate`, `promote_or_reject`, `rollback`), exhaustive `385`-state monotone `(Phase, Contact)` reconciler lattice, exact `Fraction` affine clock-pair & `+55%` Goodhart KL latch, HMAC hash-chained ledger with exact top-level key/schema lock, and Issue `#6` redacted 3-call Cerebras/Kimi advisory boundary (`SHA-256`: `3c727b77...`, **`69/69` `100.0%` R5 killed**) |
| [`verify_bounded_controller.py`](./verify_bounded_controller.py) | `AUDIT-063R2` | End-to-end 3-round loop + `18/18` Issue `#7` adversarial trust-boundary matrix + in-repo `src/warp_modeld` Stage 1 & Stage 2 verification (`SHA-256`: `ee84b17a...`; `-I -O -B -W error --json` stdout SHA-256 `2245d5bb9ebbab07afc54c7b11c40317ac789634de4018991e35cc927c590499`; `--standalone` SHA-256 `59f51685a5dce4da062e312334350b705843b234b565f48c8679e1340eaf83e5`) |
| [`test_bounded_controller_r5.py`](./test_bounded_controller_r5.py) | `AUDIT-063R2` | R5 refusal-site mutation & exact-invariant test suite (`SHA-256`: `ebd1c327...`; `6/6` groups PASS; `-I -O -B -W error` stdout SHA-256 `8731a50db3c2573f0ebe8fdda7bc73deea7cc2d2a9b394b0300e285e795d45ce`) |
| [`bounded_controller_certificate.json`](./bounded_controller_certificate.json) | `AUDIT-063R2` | Canonical zero-float JSON certificate (`SHA-256`: `2245d5bb...`, `canonical_sha256`: `a130ee9ce5407ec9ef71284d1cde8ca5add3e02e15ad2c98f1f9b6f9aed3a9e2`) |
| [`BOUNDED_CONTROLLER_REPORT.md`](./BOUNDED_CONTROLLER_REPORT.md) | `AUDIT-063R2` | Full Issue `#4`/`#5`/`#6`/`#7` architecture mapping, red-team bypass closures (`CTRL-BYPASS-1..6`), and Law-4 `N0`/`N1` quarantine |

---

## Quick Reproduction (All 4 Isolated `-I` R4 Modes)

Run from the repository root (`Moissanite-Labs/warp-drive/`):

```bash
# 1. End-to-end verifier + in-repo src/warp_modeld Stage 1/2 check (4 isolated modes):
for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $f studies/expedition-bounded-controller/verify_bounded_controller.py --json | sha256sum
done
# Expected (all 4 modes): 2245d5bb9ebbab07afc54c7b11c40317ac789634de4018991e35cc927c590499

# 2. Pure standalone mode (zero dependency on src/warp_modeld):
python3 -I -O -B -W error studies/expedition-bounded-controller/verify_bounded_controller.py --standalone | sha256sum
# Expected: 59f51685a5dce4da062e312334350b705843b234b565f48c8679e1340eaf83e5

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
   - Exhaustively certifies all `385/385` `(Phase, Contact, Obs)` transitions (`0` phase regressions, `0` terminal swaps, `0` outage-fabricated verdicts, `0` duplicate terminal notices, `32` tombstone resolutions) and verifies the `23`-receipt HMAC-SHA256 chain independently (`head_sha256: 0adf6549...`).
3. **Issue `#6` (Redacted Kimi-on-Cerebras Advisory Boundary):**
   - Bounds Cerebras/Kimi to `propose`, `diagnose`, and `compare` over fixed text & structured reports only (`sanitize_outbound_payload` blocks weights, tensors, secrets, and raw LoRAs before transport), rejects silent model substitution (`ERR_MODEL_SUBSTITUTION`), validates strict duplicate-key JSON and response schemas *before* logging `"status": "ok"` receipts (logging `"status": "rejected"`/`"error"` redacted receipts on all failures), and proves local deterministic gates override a positive `"BETTER"` judge vote on the regressed plausible-text control.
4. **Live `src/warp_modeld` Stage 1 & Stage 2 Compatibility:**
   - Directly invokes [`src/warp_modeld/fingerprint.py`](../../src/warp_modeld/fingerprint.py) (`AdapterBundle.from_dict`, `verify_stage1`) and [`src/warp_modeld/certificate.py`](../../src/warp_modeld/certificate.py) (`verify_stack_division_free`) against the promoted candidate bundle across all 3 required state banks (`stage1_and_stage2_passed: true`), alongside [`PLAN.md`](../../PLAN.md) and [`ARCHITECTURE.md`](../../ARCHITECTURE.md).

See [`BOUNDED_CONTROLLER_REPORT.md`](./BOUNDED_CONTROLLER_REPORT.md) for the complete architecture cross-map, red-team bypass audit (`CTRL-BYPASS-1..6`), and Law-4 `N0`/`N1` quarantine.
