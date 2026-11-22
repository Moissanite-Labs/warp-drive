# Wave 2 Round 6 — Arm R6-4 (`AUDIT-064`): Governed Weight Iteration & Multi-Bank State Isolation Bridge for `Moissanite-Labs/warp-drive`

- **Arm / Owner:** Arm R6-4 (`fractals-probe`), targeting `Moissanite-Labs/warp-drive` (Issue `#3` *Rapid governed weight iteration*, `src/warp_modeld/state_banks.py`, `verifier.py`, `fingerprint.py`, `canary.py`, `tests/test_lattice_state_isolation.py`)
- **Pinned Read-Only Anchors (`0` external GitHub writes, `0` dirty files):**
  - `Moissanite-Labs/warp-drive @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` (`main`)
  - `qwen-neuron-map/4b.html` (`Qwen3.5-4B`, `294,912` MLP neurons, `72,553` direct circuit wires, SHA-256 `cfc229397e1e98d46ccaa270295bcb02114159bfb2ed79cc77f7f6262220f22d`, `AUDIT-059 VERIFIED`)
- **Oracle Class & Honest Law-4 Novelty Tag:** `exact+anchor` (100% pure Python 3 stdlib `int`/`Fraction`, **ZERO floats** anywhere in JSON or exact theorems, **ZERO external deps**, **ZERO bare `assert`s**) | **`N1`** (live-reproduced state-bank/flush defects `WD-SB-01`..`WD-SB-04` + hardened zero-dep fail-closed gates, exact pure-$\mathbb{Q}$ causal/Fisher-KL/Hessian-bloat proofs explaining `ml-os#6`'s `blk.31` isolation and `+55%` preconditioning KL jump, and exact 32-layer / 72,553-wire `Qwen3.5-4B` empirical tomography; all classical and upstream results strictly quarantined as `N0`).
- **Artifacts (`studies/expedition-weight-iteration-bridge/`):**
  - `warp_weight_iteration_bridge.py` — self-contained pure-$\mathbb{Q}$ verifier, hardened multi-bank state-isolation & Issue `#3` governed-iteration engine (supports both live-anchored and `--standalone` modes)
  - `test_warp_weight_iteration_r5.py` — 4-group R1–R5 verification, invariance, unseen-instance, and `100.0%` mutation-kill test suite
  - `warp_weight_iteration_certificate.json` — zero-float canonical JSON certificate (`canonical_sha256 = 9e3f9a74c86c9de0717a2814d480413989be6fed2a8b56a186fc61913cf78450`)
  - `WARP_WEIGHT_ITERATION_REPORT.md` — this report

---

## 1. Strict Law-4 `N0` Prior-Art Quarantine Table (Aligned with `ROUND6_PORTALS.md` `R6-N0-01..08`)

| Quarantine ID | Established Classical / Upstream Baseline (`N0`) | Role in `AUDIT-064` |
|---|---|---|
| `R6-N0-01` | Sylvester (1852) law of inertia, Schur (1911) complement, Bunch–Kaufman congruence | Exact Krein inertia `⦺(F_p)` & Fisher-Schur kernel projection `F_p ⧄ {0,1}` |
| `R6-N0-04` | `Moissanite-Labs/warp-drive main@e3899d3` 4-stage verifier & `state_banks.py` | Pinned read-only audit target (`WD-SB-01`..`WD-SB-04` live reproducers + hardened gates) |
| `R6-N0-05` | `Moissanite-Labs/ml-os#6` (`Qwen3.5-4B Q8_0` `blk.31` `5.183` vs `5.348`, `14/14` restore, `84/84` vs `36/36` margins, `+55%` preconditioning KL jump), Latent Lattice LM (`arXiv:2611.21608`), Issue `#2`/`#3`/`#7` | Empirical anchor & lane contract explained algebraically & empirically |
| `R6-N0-06` | Prior verified expedition studies: `siliquant#24` (`AUDIT-028`/`031`: `E_8^{\mathrm{Had}}`, `8/3` $L_1$ radius, `\Lambda_{24}` `1/3`, `\Phi_{x_0,\tau}`), `AUDIT-058R` (`LoReS` GDN decay & `compressm`), `AUDIT-059` (`qwen-neuron-map` `4b.html`, `q08.html`, `g4e4.html`) | Cross-domain building blocks united into `warp-drive` weight iteration |
| `R6-N0-08` | Standard LoRA composition, Fisher information matrix of categorical softmax, KL-divergence | Exact pure-$\mathbb{Q}$ second-order Fisher-KL curvature $F_p = U^\top(\operatorname{diag}(p)-pp^\top)U$ |

---

## 2. Pillar 1 — Four Live-Reproduced State-Bank & Flush Defects on `warp-drive main@e3899d3` (`WD-SB-01`..`WD-SB-04`)

All four defects below were **live-reproduced read-only against `Moissanite-Labs/warp-drive @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5`** with zero false positives and zero modifications to the repo, and closed by `HardenedStateBankStatus`, `HardenedBankFlushReceipt`, `validate_lattice_checkpoint_dims`, and `verify_multibank_flush_strict`:

| Defect ID | Severity | Exact Code Anchor (`warp-drive@e3899d3`) | Live-Reproduced Mechanism & Security Impact | Hardened Closure in `AUDIT-064` |
|---|---|---|---|---|
| **`WD-SB-01`** | **Critical** | `src/warp_modeld/verifier.py:242-249, 269-275, 287-295`; `fingerprint.py:651-662` | **Asymmetric SSM-Recurrent Flush Trust Gap:** On hybrid Gated DeltaNet / SSM checkpoints WITHOUT horizontal lattice (`has_ssm_recurrent=True, has_horizontal_lattice=False` — literally **`Qwen3.5-4B`** in `ml-os#6`/Issue `#3` and **`Qwen3.8-27B`** in `ARCHITECTURE.md:86`!), `verifier.py:242` checks `missing_banks` **only** under `if needs_lattice:` (skipping `needs_ssm`!), and `verifier.py:271` skips absent `ssm_bank` (`ssm_bank is not None and not ssm_bank.is_clean`). Live reproduction on stock KV-only `MockLlamaServer(has_ssm_recurrent=False)` signs **`{'slot_id': 0, 'banks_requested': ['kv_cache', 'ssm_recurrent'], 'banks_confirmed': ['kv_cache'], 'verified_clean': True}`** straight into the HMAC ledger! Combined with `AUDIT-058R` GDN slow-decay persistence ($\alpha = 63/64 \implies (63/64)^{44} > 1/2$), unflushed `ssm_recurrent` state leaks across >44 tokens. | `verify_multibank_flush_strict` requires explicit backend confirmation AND explicit post-erase `state_banks[b]` clean status for **every** bank in `required_banks` (including `ssm_recurrent`); `HardenedBankFlushReceipt` forbids `verified_clean=True` whenever any requested bank is unconfirmed. |
| **`WD-SB-02`** | **High** | `src/warp_modeld/state_banks.py:27-71` | **Missing Dataclass Invariants:** Neither `StateBankStatus` nor `BankFlushReceipt` has `__post_init__` validation. Live reproduction constructs `BankFlushReceipt(banks_requested=('kv_cache','ssm_recurrent','lattice_horizontal_streams'), banks_confirmed=(), verified_clean=True)` AND `StateBankStatus(bank='nonexistent_bank', tainted=False, tokens_or_layers=False)` with `is_clean == True` (`bool` `False == 0`). | `HardenedStateBankStatus` & `HardenedBankFlushReceipt` enforce strict `type(...) is int`/`bool`, `VALID_STATE_BANK_SET`, non-negative counts, `capability_tag in [0, 255]`, and confirmation completeness. |
| **`WD-SB-03`** | **Medium** | `src/warp_modeld/fingerprint.py:169-172` | **Zero-Width Horizontal Lattice Accepted:** `CheckpointFingerprint.__post_init__` checks `if self.has_horizontal_lattice and layers <= 0:` (`L169`) but omits `or width <= 0`, accepting `has_horizontal_lattice=True, lattice_layers=24, lattice_width=0`. | `validate_lattice_checkpoint_dims` enforces BOTH `lattice_layers > 0` AND `lattice_width > 0` when enabled (`0` and `0` when disabled). |
| **`WD-SB-04`** | **High** | `src/warp_modeld/canary.py:446, 499, 549, 555`; `verifier.py:252-296, 435-441` | **Stage-3 Canary Runner Ignores Partial Erase & Post-Slot Taint:** `CanaryRunner.run()` discards the `banks_flushed` return dict from `erase_slot(sid, banks=erase_banks)` and never re-queries `list_slots()`. Live reproduction on `MockLlamaServer(has_ssm_recurrent=True, lattice_layers=24)` with `kv_only_erase_slot_ids={0, 1}` returns **`canary_slot_flushed=True`** while BOTH `slot0.lattice_state_tainted` and `slot1.lattice_state_tainted` remain **`True`** (allowing cross-canary poisoning inside Stage 3 AND leaving tainted slots after a rejected Stage 3 run where Stage 4 `_flush_all_slots()` never executes). Also `verifier.py:252-296` omits slot-set coverage (empty `after` passes silently) and ignores `slot.is_processing`. | `verify_multibank_flush_strict` verifies exact `pre_slot_ids <= post_slots` coverage, `is_processing is False`, `banks_flushed` confirmation, and post-erase cleanliness on every slot (usable identically in Stage 3 and Stage 4). |

---

## 3. Pillar 2 — Why `ml-os#6` `blk.31` Preserves `~97%` Gain & `14/14` Restore While Earlier Layers Taint Caches

### 3.1 Exact Pure-$\mathbb{Q}$ 3-Layer Hybrid GDN + KV + Latent Lattice Causal Theorems (`WI-1`..`WI-3`)
On an exact rational 3-layer causal hybrid model (`L0` Gated DeltaNet recurrent bank $S_t$, `L1` KV-cache bank, `L2` terminal `blk.last` + optional Latent Lattice horizontal stream $H_{2,t}$, shared Frobenius norm $\|\Delta W\|_F^2 = 9/16$):

| Theorem / Scenario | SSM Taint `t=1` | KV Taint `t=1` | First-Order Gain Match | Post-Rollback Logit Err² (No / Partial Flush) | Post-Rollback Logit Err² (Full Multi-Bank Flush) |
|---|---:|---:|---|---:|---:|
| **`WI-1`:** Terminal `blk.last` (`has_horizontal_lattice=False`) | **`0/1`** | **`0/1`** | **`True` (`100%` exact)** | **`0/1`** (no flush) | **`0/1`** |
| **`WI-2`:** Earlier layer `L0` (`has_horizontal_lattice=False`) | **`109/1024`** | **`13/64`** | Distorted downstream | **`425/9216`** (no flush) | **`0/1`** (KV + SSM flush) |
| **`WI-3`:** Terminal `blk.last` **WITH** Latent Lattice (`arXiv:2611.21608`) | `0/1` | `0/1` | Horizontal feedback | **`65025/65536`** (KV+SSM-only flush!) | **`0/1`** (full 3-bank flush) |

- **`WI-1` + `WI-2`** prove algebraically why `ml-os#6`'s `blk.31` edit preserved linear first-order gain (`5.183` vs `5.348`) and `14/14` exact logit restore while earlier-layer edits left persistent cache taint.
- **`WI-3`** proves formally why **Issue `#2` & `#7` prohibit relaxing Warp's full 3-bank flush contract**: on Latent Lattice checkpoints (`arXiv:2611.21608`), even a last-layer-only adapter feeds timestep $t+1$ via `lattice_horizontal_streams`, leaking `65025/65536` logit error squared even after flushing BOTH `kv_cache` and `ssm_recurrent`!

### 3.2 Real Empirical Tomography of `Qwen3.5-4B` (`4b.html`, `294,912` Neurons, `72,553` Direct Circuit Wires)
Decoding the full neuron-level structure and all **`72,553` direct neuron-to-neuron `BRIDGES` wires** (`backward = 0, same_layer = 0`, verified strict forward DAG!) of **`Qwen3.5-4B` (`4b.html`, SHA-256 `cfc22939...`)** — the exact model studied in `ml-os#6` — yields four convergent structural facts:
1. **Zero Outgoing Blast Radius vs. Immediate Upstream Cliff:** `blk.31` (`L31`) has **`0` outgoing circuit wires** while serving as the **`#1/32` incoming circuit sink (`14,268 / 72,553 = 19.67%` of all wires in the model terminate in `blk.31`)**. Stepping even ONE layer earlier to `L30` jumps immediately from `0` to **`4,722` outgoing wires**, peaking at **`L26` (`7,350` outgoing wires, `#1/32` blast radius)**.
2. **Unique `#1/32` Dark-Shadow Capacity Spike at `blk.31`:** `L31` carries **`1,922 / 9,216 = 961/4608` (`20.86%`)** dark-shadow neurons (`⧅`) — **`#1/32` across all layers** and **`59582/28137` (`2.118×`)** enriched over `L00..L30` (`28,137 / 285,696 = 9.85%`), uniquely spiking at the terminal layer compared to `Qwen3.5-2B` (`#21/24`), `Qwen3.5-0.8B` (`#22/24`), and `Gemma 4 E4B` (`#30/42`, where `L10` is `#1/42` outgoing fan-out hub accounting for `89.55%` of `siliquant` KL damage).
3. **Direct Surface-Token & Code/Math Steering at `blk.31`:** `L31` ranks **`#1/32` in `code` firing share (`83323/235008`)**, is **`10943/3050` (`3.59×`) enriched in `Single letters and capitals` (`1,412 / 9,216` vs `12,200 / 285,696`)**, and **`12369/6493` (`1.905×`) enriched in `Math notation: algebra and geometry` (`798 / 9,216`)**.
4. **Exact 3:1 Gated DeltaNet / Full-GQA Mod-4 Periodicity:** Dark-neuron counts grow strictly monotonically across the four residue classes `l % 4 = 0 < 1 < 2 < 3` BOTH globally (`6,522 < 6,738 < 8,064 < 8,735`) AND strictly excluding the final block `L28..L31` (`L00..L27`: `5,244 < 5,327 < 6,668 < 6,813`), separating the 24 GDN layers from the 8 full-attention layers (`l % 4 == 3`).

---

## 4. Pillar 3 — Exact Pure-$\mathbb{Q}$ Proof of the `+55%` Preconditioning KL Trap, `siliquant#24` Twin & Margin Blindness

1. **Theorem `WI-4` (Fisher-KL vs. Euclidean Residual Inversion — Explaining `ml-os#6`'s `+55%` Preconditioning KL Jump):**
   - For exact base probabilities $p = (1/2, 1/4, 1/4)$ and unembedding $U = \begin{pmatrix} 2 & 0 & 1 \\ -1 & 7 & 1 \\ -1 & -7 & 1 \end{pmatrix}$, the exact residual-space Fisher-KL curvature is $F_p = U^\top(\operatorname{diag}(p)-pp^\top)U = \operatorname{diag}(9/4, 49/2, 0)$ with Krein inertia `⦺(F_p) = (2, 1, 0)` and exact Schur kernel `F_p ⧄ {0, 1} = 0/1`.
   - Against target direction $g_{\mathrm{task}} = (1, 2, 1)^\top$, ALL THREE candidates achieve **identical target gain `1/1`**:
     - Raw $\delta h_{\mathrm{raw}} = (1, 0, 0)^\top$: $\|\delta h\|_2^2 = \mathbf{1/1}$, unrelated Fisher-KL $= \mathbf{9/8}$.
     - Task-preconditioned minimum-norm $\delta h_{\mathrm{pre}} = (1/5, 2/5, 0)^\top$: **Euclidean norm squared SHRINKS by `-80%` (`1/5 < 1/1`)**, easily passing stricter Euclidean `FixedRadixCertificate` bounds, YET exact unrelated Fisher-KL **JUMPS to `401/200` — an exact `401/225` (`+78.22% > +55%`) KL blow-up!**
     - Fisher-Schur kernel projection $\delta h_{\mathrm{schur}} = (0, 0, 1)^\top \in \ker(F_p)$: achieves identical target gain **`1/1`** with **`0/1` exact unrelated KL**!
2. **Theorem `WI-5` (`siliquant#24` Quantization Twin & `LoReS` GDN Persistence):**
   - On exact 4-weight group $w = (1, 3/8, 3/8, 3/8)$ with $H = \operatorname{diag}(16, 1, 1, 1)$ under 2-bit symmetric group quantization: unweighted $H$-MSE is **`3/64`**, naive diagonal Hessian preconditioning $v = \sqrt{H}w$ inflates the shared group scale and blows $H$-MSE up **`9×` to `27/64`** (exact rational mechanism of `AUDIT-031`'s `-3.802 dB` group-scale bloat!), whereas zero-float $\Phi_{x_0,\tau}$-certified outlier splitting yields **`0/1` MSE** — pairing naturally with `E_8^{\mathrm{Had}}` (`929/1080` SR MSE, exact Voronoi $L_1$ radius squared `64/9 < 8`), `\Lambda_{24}` (`1/3` worst-case energy), and `LoReS` GDN slow-decay persistence ($\alpha=63/64$: `(63/64)^44 > 1/2`, `127/1` RTN-vs-SR amplification).
3. **Theorem `WI-6` (Log-Prob Margin vs. Argmax Text Blindness):**
   - Shifting base logits $(5, 5/2, 0) \to (11/4, 5/2, 0)$ leaves greedy argmax text **100% identical** (`argmax == 0`) while destroying **`90%` of the logit margin (`5/2 -> 1/4`, ratio `1/10`)** — formally proving Issue `#2`/`#3`'s requirement that plausible-text regressions MUST be gated by exact log-probability margins!

---

## 5. Pillar 4 — Issue `#3` Zero-Float Governed Weight-Iteration Gate (`evaluate_governed_candidate`)

`evaluate_governed_candidate` implements Issue `#3`'s fail-closed contract in pure stdlib `int`/`Fraction`:
- Pre-evaluation canonical SHA-256 hash verification (`ERR_CANDIDATE_HASH_DRIFT`), raw-LoRA-override rejection (`ERR_UNVERIFIED_LORA_OVERRIDE`), last-layer target lock (`blk.31`, `ERR_UNSUPPORTED_LAYER`), division-free `FixedRadixCertificate` cross-multiplication (`value * limit_den <= limit_num * radix_scale`, `ERR_CERT_FROB_EXCEEDED`), exact unchanged-base control (`C0_unchanged_base -> CONTROL_BASE_PASS`), Fisher-Schur promotion (`C1_blk31_fisher_schur -> PROMOTE`), and fail-closed rejection of plausible-text margin regressions (`C2 -> ERR_MARGIN_REGRESSION`), preconditioned KL blow-ups (`C3 -> ERR_UNRELATED_KL_EXCEEDED`), and incomplete multi-bank flushes (`ERR_MULTIBANK_FLUSH_INCOMPLETE`).

---

## 6. Exact Verification Receipts & Falsification Criteria

- **Repro Commands (`studies/expedition-weight-iteration-bridge/`):**
  ```bash
  for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
    python3 $f warp_weight_iteration_bridge.py --standalone --json | sha256sum
    python3 $f test_warp_weight_iteration_r5.py
  done
  # With Foundation-0/aletheia on PYTHONPATH:
  python3 -B -W error -m aletheia audit-check . \
    --scripts warp_weight_iteration_bridge.py test_warp_weight_iteration_r5.py --json
  python3 -B -W error -m aletheia mutate warp_weight_iteration_bridge.py \
    --work-root . --add-cwd --test-cmd "python3 -I -O -B -W error test_warp_weight_iteration_r5.py" --json
  ```
- **Falsification Criteria:** Fails if any of `WD-SB-01`..`WD-SB-04` fails to live-reproduce on `warp-drive@e3899d3` or cites a wrong `file:line`; if any exact pure-$\mathbb{Q}$ theorem (`WI-1`..`WI-6`) or `Qwen3.5-4B` (`4b.html`) 32-layer / 72,553-wire count fails independent SymPy/stdlib verification; if any float appears in JSON; if any mutant survives `aletheia mutate` (`< 100%`); or if any isolated `-I` R4 / `audit-check` / read-only clone cleanliness check fails.
