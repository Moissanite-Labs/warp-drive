# Wave 2 Round 6 — Arm R6-5 (`AUDIT-065`): Cross-Org Ecosystem Alignment, Drift Audit & Phase-3 Draft PR Blueprint for `Moissanite-Labs/warp-drive`

- **Owner:** `gravity-probe` (Arm R6-5, `#349` / `#351`)
- **Workspace:** `symbiosis/round6/arm5-weft-cross-audit/`
- **Artifacts:** `weft_cross_audit_gate.py`, `test_weft_cross_audit_r5.py`, `weft_cross_audit_certificate.json`, `WEFT_CROSS_AUDIT_REPORT.md`
- **Oracle Class & Honest Novelty Tag:** `exact+anchor` | **`N1`** (clean-room zero-shared-code cross-org contract unifier, `8` live-reproduced cross-repo drift/blueprint findings `WD-X01`..`WD-X08`, and Phase-3 Draft PR blueprint; ZERO floats, ZERO external writes, ZERO inflated `N2` claim).

---

## 1. Strict Law-4 `N0` Quarantine (`R6-N0-01`..`R6-N0-08`)

| Portal ID | Quarantined Prior Art (`N0` — Explicitly Credited, Never Claimed New) |
|---|---|
| `R6-N0-01` | Bareiss (1968) fraction-free elimination, Haynsworth (1968) inertia additivity, Sylvester (1852). |
| `R6-N0-02` | Linux `Landlock`, `seccomp-bpf`, `bubblewrap`, `systemd` sandboxing, `mkosi`, `btrfs`, and UKI rollback. |
| `R6-N0-03` | RFC 2104 HMAC-SHA256 hash-chained append-only audit logs. |
| `R6-N0-04` | Existing `siliconcordat/{warp, weft, mde, exo}` and `Moissanite-Labs/warp-drive@e3899d3e` 4-stage verifier & PR `#1` (`siliconcordat/warp#17`). |
| `R6-N0-05` | `Moissanite-Labs/ml-os#6` (`Qwen3.5-4B Q8_0` `blk.31`), Latent Lattice LM (`arXiv:2611.21608`), and Issues `#2`–`#7` specs. |
| `R6-N0-06` | Prior verified expedition audits `AUDIT-001`..`060` (`weft#227`, `weft-loom#42`, `scry#4`, `tokenpage#13`, `warp#17`). |

---

## 2. Pinned 10-Checkout Cross-Org Ecosystem Inventory (100% Read-Only, `0` Dirty)

| Checkout / Repo | Branch & Exact Pinned `HEAD` SHA | Live Parity / Role vs. `Moissanite-Labs/warp-drive` |
|---|---|---|
| `Moissanite-Labs/warp-drive` | `main @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` | Primary target (`45` files, `58` passed / `1` skipped). |
| `Moissanite-Labs/warp-drive#1` | `port/bareiss-gram-stack-cert @ 8d9f81557059631dfbb71eebf61988dfde5ef70a` | Adds `studies/expedition-bareiss-gram-cert/` (`3` files, **identical git blob SHAs** to `siliconcordat/warp#17 @ e3bd8ed1`). |
| `siliconcordat/warp` | `main @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` | **0-byte diff across all `45` files** vs. `Moissanite-Labs/warp-drive`. |
| `siliconcordat/weft` | `main @ 5d7eac03696c2ff07ec70308b23b86a1d4088c1e` | **L2 neural-weight compiler** (`src/weft/{binding,certificate,compiler,gguf_lora,quant,anchors,tangent}.py`); `FixedRadixCertificate` ingests cleanly into `warp-drive`, with `WD-X02`/`WD-X03` binding drifts. |
| `siliconcordat/mde` | `main @ 52ce0178854a67490eb718544961ba6cff710f22` | **L5 zone manifest source** (`schemas/zone-manifest.v0.1.json`, `src/zone_manifest.rs`); canonical `manifest_id = sha256:4e00656cb47fce97f687ae638afba22c569b9680b3780eeb2e5ea71a62c55eca` verifies bit-for-bit in `warp-drive` (`formal_proof:3, condensed_json:4, ui_module:2, code:1, prose:0`). |
| `siliconcordat/exo` | `main @ cb78b860d22504d88bfbe23a2196d1cbbba0e52d` | **L4 harness** (`src/exo/{bridge,router,ledger}.py`); mirrors `WD-X02b`/`WD-X03`, diverges on `WD-X04` (`u8`/dup `l1_bank_tag`), stronger on pre-JSON secret redaction (`WD-X05b`), weaker on blank lines/`fsync`/domain-separated HMAC (`ledger.py:168-169,216`). |
| `Moissanite-Labs/weft` (+ PR `#227`) | `main @ c08b9695d9930f637b8a6fdc00af5809fb883995` (`#227 @ 47669661`) | **Distinct from `siliconcordat/weft` (Issue `#2` verified programmatically):** houses `weft/runtime/{ic,invariants,plasm,gateway,ledger/*.sol}` (`0` `src/weft/binding.py`). PR `#227` (`AUDIT-033 N2`) supplies the exact non-importing dual-checker verifier pattern mandated by **Issue `#7`**. |
| `Moissanite-Labs/weft-loom` (+ PR `#42`) | `main @ 4b6b714500e377db5442036364c861a11d14caec` (`#42 @ ddc9eb42`) | `AUDIT-022/023` repair-signal Simpson's paradox & Schur null-law bounds directly warn **Issues `#4`/`#5`** against pooling heterogeneous task families or leaking splits (`ml-os#6` `98%` split leakage). |
| `Moissanite-Labs/scry` (+ PR `#4`) | `main @ 026b78e1cddd7c7220cc03835fcf1da2d96513aa` (`#4 @ e50eb4f5`) | `AUDIT-024` exact nonlinear top-$p$ support-truncation extinction underpins **Issue `#2`/`#4`**'s proof that text-only gating is unsound (`verifier.py:610-611` locks `temperature=0.0, top_p=1.0`, plus log-prob margin gating). |
| `Moissanite-Labs/tokenpage` (+ PR `#13`) | `main @ 81c752406e170e34fc99302538c738a3af88093a` (`#13 @ a694232e`) | `AUDIT-022` exact proper-KL & sub-text channel theorems reinforce **Issue `#2`**'s `+55%` unrelated-prompt KL warning (residual norm != behavioral retention). |

---

## 3. Eight Live-Reproduced Cross-Org Drift & Blueprint Findings (`WD-X01`..`WD-X08`)

Every finding below was reproduced live against the pinned files and paired with a hardened pure-stdlib zero-float validator in `weft_cross_audit_gate.py` (`100.0%` R5 killed):

1. **`WD-X01` [HIGH] — `ssm_recurrent`-Only Hybrid Bank-Flush Confirmation Gap (`src/warp_modeld/verifier.py:234-249, 269-295`):**
   - When `has_ssm_recurrent=True` and `has_horizontal_lattice=False` (every `Qwen3.5` / `Qwen3.8` Gated DeltaNet hybrid model), if `llama-server` returns standard JSON omitting `banks_flushed` and `state_banks`, `verifier.py:240` sets `confirmed = ()`, skips the missing-bank check (`L242` checks ONLY `if needs_lattice:`), skips `ssm_bank is None` at `L271`, and signs an HMAC-SHA256 rollback receipt claiming **`verified_clean: True`** with **`banks_requested: ['kv_cache', 'ssm_recurrent']`** and **`banks_confirmed: []`**!
   - **Hardened Fix (`verify_multibank_flush_receipt_strict`):** Fail closed whenever `needs_ssm` OR `needs_lattice` has any required bank omitted from `banks_flushed` or missing/unclean in `state_banks`.
2. **`WD-X02` [HIGH] — `weft-binding/v0.1` 3-Way Drift vs. `siliconcordat/weft` (`src/warp_modeld/fingerprint.py:259-265, 557-575` vs. `siliconcordat/weft/src/weft/binding.py:26-40, 252-253, 293-313`):**
   - **(a) Hard Veto 1 half-check:** `siliconcordat/weft` (`binding.py:252-253, 296-297`) requires non-empty `plane1_hashes` for `class1_rederivable`; `warp-drive` (`fingerprint.py:557-562`) ignores `plane1_hashes` and accepts `plane1_hashes: {}`.
   - **(b) Silent config/tokenizer blindness:** `fingerprint.py:259-260` (and `exo/bridge.py:117-123`) short-circuits `config_hashes.get("config.json") or sha256_json(config_hashes)` (same for `tokenizer.json`), dropping `generation_config.json`, `tokenizer_config.json`, `special_tokens_map.json`, `added_tokens.json`, `vocab.json`, and `merges.txt` — mutating `generation_config.json` & `special_tokens_map.json` yields an **identical** `CheckpointFingerprint.canonical_digest()` while `weft` raises `config_drift` / `tokenizer_or_chat_template_drift`!
   - **(c) Optional/disconnected `runtime_flags`:** `fingerprint.py:565` skips digest verification if `runtime_flags_sha256` is omitted, and never cross-checks shared `ctx_size` against host `RuntimeFlags`.
3. **`WD-X03` [MEDIUM] — `from_weft_binding` Drops Hybrid SSM & Latent Lattice Flags (`src/warp_modeld/fingerprint.py:234-279, 526-620, 695-707` & `exo/bridge.py:107-133`):**
   - `CheckpointFingerprint.from_weft_binding` hardcodes `has_ssm_recurrent=False, has_horizontal_lattice=False, lattice_layers=0, lattice_width=0`, causing immediate Stage-1 rejection (`CheckpointMismatchError: state-bank architecture mismatch`) on any hybrid SSM or Latent Lattice host.
4. **`WD-X04` [MEDIUM] — Asymmetric 3-Layer `zone-manifest/v0.1` Validation (`mde/src/zone_manifest.rs:21-40` vs. `exo/src/exo/router.py:53-128` vs. `warp-drive/src/warp_modeld/fingerprint.py:87-128`):**
   - `exo/router.py:90-92` omits `l1_bank_tag <= 255` (`u8`) and duplicate-tag checks (live-reproduced: accepts `tag=300` and duplicate `0, 0`, which `warp-drive` rejects);
   - `warp-drive/fingerprint.py:87-128` omits `precedence_order` and valid-zone checks (live-reproduced: accepts `precedence_order=[]` and `zone="bogus_zone"`, which `exo` rejects);
   - `test_weft_zone_alignment.py:93-108` tests a stripped synthetic dict instead of `siliconcordat/mde/schemas/zone-manifest.v0.1.json`.
   - **Hardened Fix (`verify_zone_manifest_unified`):** Enforces the exact intersection of `mde`, `exo`, and `warp-drive` with zero Python floats.
5. **`WD-X05` [MEDIUM] — `ledger.py` Duplicate-JSON-Key Acceptance & Missing Secret Redaction (`src/warp_modeld/ledger.py:125, 255-327` vs. `server.py:21-32` & `exo/ledger.py:19-78`):**
   - `LedgerVerifier.verify_file` calls bare `json.loads(raw_line)` (`ledger.py:125`), live-reproduced to accept a shadowed duplicate outer key (`"signature":"FORGED_SHADOW","signature":"<real>"`), whereas `server.py:21-32` rejects duplicate keys; and `SignedLedger` lacks `exo/ledger.py:19-78`'s pre-JSON secret redaction.
6. **`WD-X06` [HIGH] — `blueprints/recovery/warp-recovery.sh` UKI Rollback Subvolume Disconnect (`warp-recovery.sh:40-43, 54-75`, `mkosi.conf:21`, `ARCHITECTURE.md:128-133`):**
   - `cmd_checkpoint` snapshots `/` to `/var/lib/warp/snapshots/<id>` and copies `warp-current.efi` -> `warp-rollback-<id>.efi` whose UKI `KernelCommandLine` (`mkosi.conf:21`) still hardcodes `rootflags=subvol=@,compress=zstd:3`. `cmd_stage_rollback` runs `bootctl set-oneshot` without retargeting the UKI rootflags or swapping `@`, so rebooting mounts the still-broken current `@` subvolume; moreover, `@snapshots` is omitted from `ARCHITECTURE.md:128-131`'s persistent subvolume layout.
7. **`WD-X07` [MEDIUM] — `mkosi` / `systemd` Blueprint Hardening & Ownership Drift (`harden-image-modes.sh:32-52`, `mkosi.postinst:21-33`, `warp-modeld.service:9-15`):**
   - **(a)** `harden-image-modes.sh:32-45` omits `/etc/warp` (direct ancestor of `/etc/warp/canaries`, `/etc/warp/keys`, `/etc/warp/modeld.json`, `/etc/warp/llama-server.env`, `/etc/warp/landlock-policy.json`).
   - **(b)** `warp-modeld.service:9-14` sets `User=warp-modeld`, `Group=warp-rpc`, `StateDirectory=warp-ledger` (`0750`), colliding with `mkosi.postinst:24-28` (`root:warp-modeld 0750 /etc/warp/keys` and `warp-modeld:warp-modeld 0750 /var/lib/warp-ledger`): systemd chowns `/var/lib/warp-ledger` to `warp-modeld:warp-rpc` and drops `warp-modeld` as primary GID unless `SupplementaryGroups=warp-modeld` (or `Group=warp-modeld` + `SupplementaryGroups=warp-rpc` on socket) is configured.
   - **(c)** `mkosi.conf` lacks an `mkosi.extra/` installer placing `/usr/bin/warp-modeld`, `/usr/local/bin/warp-recovery.sh`, and `/etc/warp/{landlock-policy.json,modeld.json,canaries/verifier-canaries.json}`.
8. **`WD-X08` [LOW] — Test Suite Bare `assert`s & Helper SSM Omission (`tests/test_stage4_rollback_ledger.py:112,122`, `tests/test_live_llama_smoke.py:140`, `tests/helpers.py:127-135`):**
   - `3` bare `assert`s block `aletheia v1.3.0 audit-check PASS` on `tests/`; `make_adapter_bundle_dict` omits `has_ssm_recurrent` / `has_horizontal_lattice` / `lattice_layers` / `lattice_width`.

---

## 4. Phase-3 Clean Draft PR Packaging Blueprint for `Moissanite-Labs/warp-drive`

*(To execute ONLY after `@verifier` clears `AUDIT-061`–`065` and `@coordinator` authorizes Phase 3!)*

- **Hard Governance Constraints:**
  - NEVER push or merge `main`; NEVER modify PR `#1`'s branch `port/bareiss-gram-stack-cert` (`8d9f8155`); ZERO new GitHub Actions workflows (Issue `#3` billing limit); ZERO local user-home paths, credentials, weights, or bare `assert`s; every PR opened as **`--draft`** linked to its lane issue for non-author review.
- **3 Disjoint, Non-Conflicting Draft PRs:**
  1. **PR-A (`feat/hardening-trust-boundary-and-cross-org-gates`, Issues `#3`, `#7` — Arms R6-2 + R6-5):**
     - Patches `WD-X01..WD-X08` (`verifier.py`, `fingerprint.py`, `ledger.py`, `blueprints/{mkosi,recovery,systemd}`, `tests/{helpers,test_weft_zone_alignment,test_stage4_rollback_ledger,test_live_llama_smoke}.py`) + Arm R6-2 sandbox/runtime hardening + standalone non-importing verifier under `studies/expedition-trust-boundary-verifier/`.
  2. **PR-B (`feat/frozen-contract-and-bounded-controller`, Issues `#3`, `#4`, `#5`, `#6` — Arm R6-3):**
     - Adds versioned frozen manifest, family split-leakage audit, 5-op bounded experiment controller (`propose_candidate`, `compile_and_bind`, `evaluate`, `promote_or_reject`, `rollback` — explicitly labeled project-specific harness, NOT W-MCP), and redacted Kimi-on-Cerebras contract with zero edits to `src/warp_modeld/`.
  3. **PR-C (`feat/governed-weight-iteration-and-gram-upgrades`, Issues `#2`, `#3` — Arms R6-1 + R6-4):**
     - Adds non-author PR `#1` Gram-certificate review/upgrade study + exact last-layer `blk.31` & multi-bank lattice-state isolation math study without touching PR `#1`'s branch.

---

## 5. Reproducibility

From `symbiosis/round6/arm5-weft-cross-audit/`:

```bash
for m in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $m weft_cross_audit_gate.py --json | sha256sum
  python3 $m weft_cross_audit_gate.py --standalone --json | sha256sum
  python3 $m test_weft_cross_audit_r5.py
done
```
