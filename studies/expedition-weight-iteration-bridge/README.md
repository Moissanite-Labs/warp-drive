# Expedition Governed Weight-Iteration & Multi-Bank State Isolation Bridge (`AUDIT-064`)

Self-contained, zero-dependency Python 3 standard-library (`int`, `fractions.Fraction`) mathematical and empirical study for `Moissanite-Labs/warp-drive` (Issue `#2`, Issue `#3` *Rapid governed weight iteration*, `src/warp_modeld/state_banks.py`, `verifier.py`, `fingerprint.py`, `canary.py`, and `tests/test_lattice_state_isolation.py`).

- **Audit Status:** `AUDIT-064` independently **`VERIFIED`** (`exact+anchor`, honest Law-4 novelty **`N1`**, **`100/100` (`100.0%`)** R5 mutation kill via `aletheia v1.3.0 mutate --add-cwd`, `0` floats in JSON, `0` bare `assert`s).
- **Pinned Audit Anchors:** Read-only against `Moissanite-Labs/warp-drive @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` and `qwen-neuron-map/4b.html` (`Qwen3.5-4B`, `294,912` MLP neurons, `72,553` direct circuit wires, SHA-256 `cfc229397e1e98d46ccaa270295bcb02114159bfb2ed79cc77f7f6262220f22d`). Zero edits to `src/warp_modeld/`, `blueprints/`, or `tests/`.

---

## Manifest

| File | Role |
|---|---|
| [`warp_weight_iteration_bridge.py`](warp_weight_iteration_bridge.py) | Pure-$\mathbb{Q}$ causal multi-bank propagation proofs (`WI-1..WI-3`), Fisher-KL preconditioning inversion (`WI-4`), Hessian group-scale bloat vs. certified split (`WI-5`), argmax-vs-margin blindness (`WI-6`), hardened fail-closed multi-bank flush gates (`HardenedStateBankStatus`, `HardenedBankFlushReceipt`, `validate_lattice_checkpoint_dims`, `verify_multibank_flush_strict`), and Issue `#3` governed candidate gate (`evaluate_governed_candidate`). |
| [`test_warp_weight_iteration_r5.py`](test_warp_weight_iteration_r5.py) | 4-group R1–R5 verification, invariance, unseen-instance, recursive zero-float, and `100/100` mutation-kill suite. |
| [`warp_weight_iteration_certificate.json`](warp_weight_iteration_certificate.json) | Sealed zero-float canonical JSON certificate from the live-anchored `AUDIT-064` run (`c4d3ab6f...`, `canonical_sha256 = 9e3f9a74...`). |
| [`WARP_WEIGHT_ITERATION_REPORT.md`](WARP_WEIGHT_ITERATION_REPORT.md) | Full audit report, Law-4 `R6-N0-01..08` quarantine, verbatim `WD-SB-01..04` defect table, `Qwen3.5-4B` `blk.31` 72,553-wire tomography, and falsification criteria. |

---

## Quick Standalone Reproduction

Run directly from `studies/expedition-weight-iteration-bridge/` (zero external clones or third-party packages required):

```bash
# 4-mode isolated -I R4 bit-identical standalone certificate
for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $f warp_weight_iteration_bridge.py --standalone --json | sha256sum
  # Expected: 371495f0ef46ff9401d43300d008caa7e39486e6b562b707dcb7c486ea09524d
  python3 $f test_warp_weight_iteration_r5.py
done
```

---

## Key Verified Results

1. **Four Live-Reproduced State-Bank / Flush Defects (`WD-SB-01..04`) + Hardened `⫩` Gates:**
   - `WD-SB-01` (`verifier.py:242-249, 269-275`): asymmetric SSM-recurrent flush gap on `has_ssm_recurrent=True, has_horizontal_lattice=False` (`Qwen3.5-4B`/`3.8-27B` hybrids) signing `verified_clean=True` with missing `ssm_recurrent`.
   - `WD-SB-02` (`state_banks.py:27-71`): missing `__post_init__` invariants on `StateBankStatus` & `BankFlushReceipt`.
   - `WD-SB-03` (`fingerprint.py:169-172`): accepts `has_horizontal_lattice=True` with `lattice_width=0`.
   - `WD-SB-04` (`canary.py:446, 499, 549, 555`): Stage-3 `CanaryRunner` ignores `erase_slot` return `banks_flushed` and post-erase slot taint.
2. **Explaining `ml-os#6`'s `blk.31` Isolation (`WI-1..WI-3` + `Qwen3.5-4B` 72,553-Wire Tomography):**
   - Exact 3-layer pure-$\mathbb{Q}$ hybrid GDN+KV+Lattice model proves `0/1` KV/SSM taint and `0/1` no-flush rollback error at `blk.last` without horizontal lattice (`WI-1`), nonzero taint (`109/1024`, `13/64`, `425/9216`) from earlier layers (`WI-2`), and **`65025/65536` re-contamination leak even from `blk.last` under Latent Lattice `arXiv:2611.21608`** unless all 3 banks flush (`WI-3`, formally justifying Issue `#2`/`#7`'s non-relaxable flush contract).
   - Live `Qwen3.5-4B` (`4b.html`) census confirms `blk.31` has **`0` outgoing circuit wires** (vs. `4,722` at `L30` and `7,350` at `L26`), **`#1/32` incoming sink (`14,268/72,553`)**, **`#1/32` dark-shadow spike (`1,922/9,216`, `2.118×` rest)**, **`#1/32` code share**, `3.59×` `Single letters and capitals`, and strict `l % 4 = 0 < 1 < 2 < 3` hybrid GDN/GQA periodicity globally and on `L00..L27`.
3. **Explaining `ml-os#6`'s `+55%` Preconditioning KL Jump (`WI-4..WI-6`) & Issue `#3` Candidate Gate:**
   - Exact residual Fisher-KL curvature $F_p = \operatorname{diag}(9/4, 49/2, 0)$ proves task-preconditioning can cut Euclidean $\|\delta h\|^2$ by **`-80%` (`1/5 < 1`)** at identical target gain `1/1` while inflating exact unrelated Fisher-KL **`401/225` (`+78.22% > +55%`)**, solved to **`0/1` KL** by Fisher-Schur kernel projection `F_p ⧄ {0,1}` (`WI-4`), mirrored by `9×` naive Hessian 2-bit quantization bloat vs. `0/1` certified outlier split (`WI-5`) and `-90%` margin drop at identical greedy argmax (`WI-6`).
