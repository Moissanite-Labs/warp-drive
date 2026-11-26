# Expedition `sous-labs/songe` Distillation Governance & Security Bridge (`AUDIT-073R`)

Self-contained, zero-dependency Python 3 standard-library (`int`, `fractions.Fraction`) audit and standalone reference governance study analyzing **`sous-labs/songe`** (*Idle-compute local LoRA/distillation training engine for coding agents*, `main @ 5b7b13768e1ac67e7e3284043ec51f24394a740f`) with reference/blueprint gates mapped to `Moissanite-Labs/warp-drive` (`#12`/`#13`/`#15`), `Moissanite-Labs/hillclimb#4`, and `magnitudedev/magnitude` (`AUDIT-068R` / `Moissanite-Labs/siliquant#26`).

- **Scope Boundary (Honest Disclosure):** This study adds standalone audit and reference-gate artifacts under `studies/` only; `evaluate_songe_governance_boundary` and `hardened_clustered_ville_gate` are standalone reference/blueprint gates and are **not** wired into `src/`, `tests/`, `blueprints/`, or `schemas/` in this PR.

- **Audit Status:** `AUDIT-073R` independently **`VERIFIED`** (`exact+anchor`, honest Law-4 novelty **`N1`**, **`29/29` (`100.0%`)** R5 mutation kill via `aletheia v2.0.0 mutate --add-cwd`, `0` floats in JSON, `0` bare `assert`s, `check_064` `41e3fb9a...`, `bypass_count = 0`).
- **Pinned External Source (Strictly Read-Only, `0` External Writes):**
  - `sous-labs/songe @ 5b7b13768e1ac67e7e3284043ec51f24394a740f` (Apache-2.0, `Songe 0.1.0a14`, `21/21` verbatim `file:line` anchors live-verified).

---

## Manifest

| File | Role |
|---|---|
| [`songe_distill_governance_audit.py`](songe_distill_governance_audit.py) | Zero-float pure-stdlib Mercator-interval oracle for `SNG-01` clipped forward-KL gradient reversal + Bregman repair, standalone reference `SNG-02` clustered two-sided Bonferroni Ville supermartingale gate, and standalone reference 9-invariant fail-closed `evaluate_songe_governance_boundary` gate (not wired into `src/`). |
| [`test_songe_governance_r5.py`](test_songe_governance_r5.py) | 11-test R1–R5 verification, adversarial red-team, and `29/29` (`100.0%`) mutation-kill suite. |
| [`songe_governance_certificate.json`](songe_governance_certificate.json) | Sealed zero-float canonical JSON certificate from the live-anchored `AUDIT-073R` run (`479e137e...`). |
| [`SONGE_DISTILL_AUDIT_REPORT.md`](SONGE_DISTILL_AUDIT_REPORT.md) | Full audit report: Law-2 steelman, Law-4 `R8-2-N0-01..06` quarantine, `SNG-01`..`SNG-08` verbatim findings matrix, 3-way cross-pollination matrix, and explicit falsification criteria. |

---

## Quick Standalone Reproduction

Run directly from `studies/expedition-songe-distill-governance/` (zero external clones or third-party packages required):

```bash
# 4-mode isolated -I R4 bit-identical standalone certificate + R5 test suite
for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $f songe_distill_governance_audit.py --standalone --json | sha256sum
  # Expected: ae145338308d52767d4e38ad6341c1a286c702a96412ac5f4d9b57bed71fe47e
  python3 $f test_songe_governance_r5.py
done
```

---

## Key Verified Findings & Standalone Reference Governance Blueprint

1. **`SNG-01` [CRITICAL] — Asymmetric Clipped Forward-KL Anti-Teacher Gradient Reversal (`objective.py:38-42`):** Upper-only clipping $\sum_v \min(p_v \ln(p_v/q_v), \tau)$ at default `vocab_clip = 1.0` strictly rewards moving *away* from the hindsight teacher (`Q=(1/16,15/16)` -> `Q'=(1/32,31/32)`, exact saturated softmax gradient `+1/128 > 0` driving $q_0 \to 0$) and violates Gibbs' inequality at `clip = 1/4 < 1/e`. Addressed in the standalone reference oracle by Bregman-normalized clipped KL $d_v = p_v \ln(p_v/q_v) - p_v + q_v \ge 0$ (flips saturated gradient to `-31/4096 < 0`, pulling $q_0 \to p_0$).
2. **`SNG-02` [HIGH] — Single-Moment Bootstrap Degeneracy (`gate.py:51-86`, `pool.py:87`):** Under default `learning="dreams"`, `gate.decide()` breaks conversation clustering and accepts on `n = 1` unanimous win (`p_null = 1/2`, `3/4` FWER across 2 scales). Addressed in the standalone reference gate `hardened_clustered_ville_gate` (independent conversation clustering + two-sided Bonferroni Ville supermartingale $M_n(s) \ge 2K/\alpha$, requiring `n >= 9` independent wins at `K=2, alpha=1/20`: `M_9(9) = 1023/10 >= 80 > 511/9 = M_8(8)`).
3. **`SNG-03`..`SNG-08` [HIGH/MED] — Fused-Artifact Re-Judging, Prompt/Delimiter Poisoning, Unauthenticated Control API, Stat-Only Fingerprints, & Secret Hygiene:** Modeled as 9 fail-closed invariants (with strict missing-key presence validation) in the standalone reference/blueprint gate `evaluate_songe_governance_boundary`, designed as a reference specification for `warp-drive` (`#12`/`#13`/`#15`) and `hillclimb#4` (not wired into `src/`, `tests/`, `blueprints/`, or `schemas/` in this study PR).
