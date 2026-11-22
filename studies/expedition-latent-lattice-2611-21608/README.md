# Expedition Latent Lattice Tomography & 4-Bank Isolation Bridge (`AUDIT-072R`)

Self-contained, zero-dependency Python 3 standard-library (`int`, `fractions.Fraction`) study bridging **Latent Lattice Language Models** (`arXiv:2611.21608v1` + `ShivamDuggal4/latent-lattice-language-models @ 23876839517155db4333fb08d26b8b118a3db2e1`) to `Moissanite-Labs/warp-drive` (`src/warp_modeld/{fingerprint.py,state_banks.py,llama_client.py,verifier.py}`, `tests/test_lattice_state_isolation.py`, extending `AUDIT-064` `WI-3`) and `Moissanite-Labs/siliquant` (`#24`/`#26`).

- **Audit Status:** `AUDIT-072R` independently **`VERIFIED`** (`exact+anchor`, honest Law-4 novelty **`N1`**, **`89/89` (`100.0%`)** R5 mutation kill via `aletheia v1.4.0 mutate --add-cwd`, `0` floats in JSON, `0` bare `assert`s, `check_065` `8ad1a369...`, `bypass_count = 0`).
- **Pinned External Sources (Strictly Read-Only, `0` External Writes):**
  - `arXiv:2611.21608v1` (`1,167,713` B PDF, `sha256: a23d2413843e7d8ccd07f1569e61d415c4ffed130d2ee28e82f0d90a55bd5a86`)
  - `ShivamDuggal4/latent-lattice-language-models @ 23876839517155db4333fb08d26b8b118a3db2e1` (`index.html` `sha256: b67e6ece88f8c2a27b1790262e7527ba6bb106625ba2bdbff3d5fbdb0c20d41a`, listing `Code (coming soon)`)

---

## Manifest

| File | Role |
|---|---|
| [`latent_lattice_audit.py`](latent_lattice_audit.py) | Zero-float pure-stdlib exact 2D Block-Schur (`⧄ ⦺`) transfer/overshoot & `J3` companion-loop verifier, 4-regime rollback & learned-`r_0` restoration proof, exact BF16/FP32 carry-scan & `siliquant` horizontal quantization oracle, and fail-closed `validate_hardened_lattice_contract` + `verify_4bank_lattice_flush` governor. |
| [`test_r5_latent_lattice.py`](test_r5_latent_lattice.py) | 8-test R1–R5 dual-oracle Bareiss vs. Faddeev–LeVerrier, boundary, duplicate-slot, path-traversal, and `89/89` (`100.0%`) mutation-kill suite. |
| [`latent_lattice_certificate.json`](latent_lattice_certificate.json) | Sealed zero-float canonical JSON certificate from the live-anchored `AUDIT-072R` run (`07285734...`, `certificate_sha256: dd7b7580...`). |
| [`REPORT_R8_1_LATENT_LATTICE.md`](REPORT_R8_1_LATENT_LATTICE.md) | Full audit report: Law-2 steelman, Law-4 `R8-N0-01/08/09/10` quarantine, exact `LL-1`..`LL-4` & `LLLM-SQ-01` derivations, live `warp-drive` gap table (`LLLM-WD-01`..`03`), and paper-vs-webpage discrepancy log. |

---

## Quick Standalone Reproduction

Run directly from `studies/expedition-latent-lattice-2611-21608/` (zero external clones or third-party packages required):

```bash
# 4-mode isolated -I R4 bit-identical standalone certificate + R5 test suite
for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $f latent_lattice_audit.py --standalone | sha256sum
  # Expected: 60fbf1b36abbe05b00c20fb267120fa26bc1eae4ab2d4358daceecc1360e14e3
  python3 $f test_r5_latent_lattice.py
done
```

---

## Key Verified Findings & `warp-drive` Hardening Blueprint

1. **Exact 2D Block-Schur `⧄` & Non-Normal Transient Overshoot (`LL-1`, `LL-2`):** Eliminating vertical depth yields unit lower-triangular $S_{J0}$ (`det = 1/1`) and $T_{J0} = S_{J0}^{-1} G$ with all eigenvalues `= 3/4 < 1` (preserved under `vstream = 1/2`), yet dual Bareiss + Faddeev–LeVerrier certify `⦺(I - T_J0^T T_J0) = (2, 1, 0)` (non-contractive!) and unit bottom-layer taint amplifies `27/8` (`t=1`), `1215/128` (`t=2`), peak `203541903/8388608 ≈ 24.264x` (`t=6`; `125715321/4194304 ≈ 29.973x` under `vstream = 1/2`).
2. **Exact `J3` Companion-Loop Instability & Sweep Divergence (`LL-3`):** Top-to-bottom feedback $f e_1 e_3^\top$ gives exact `det(I - T_seq(f)) = (1 - 80f)/64` (`f_crit = 1/80`, `phi_crit = 1/20`); at `f = 1/40`, `det = -1/64 < 0` proves a real eigenvalue `> 1` despite `g = 3/4 < 1`. Three-sweep `J3` agrees identically for `t = 1..3` and first diverges at `t = 4` by exact `384 f^6`, explaining `Table 1`'s `+707/14026` (`14.026 -> 14.733`) FineWeb-Edu and `+5475/62923` (`62.923 -> 68.398`) LAMBADA-Std degradation.
3. **4-Regime Rollback & Learned-$r_0$ Restoration (`LL-4`) + Live `warp-drive` Gaps (`LLLM-WD-01`..`03`):** Live inspection of `warp-drive` (`main@38a7072` & `PR#15@e6ad096`) identifies missing `E/L/D`, `jacobi_infer_mode`/`sweeps`, `fp32` carry-scan precision, 4th state bank `lattice_jacobi_feedback`, `learned_r0_restore`/`r0_sha256` verification (`Sec. 3.2.2` learned non-zero $r_0^\ell$), `per_bank_rmsnorm` isolation, and unvalidated `llama_client.py:181-182` `int(lattice_layers_tainted)` parsing — all closed fail-closed by `validate_hardened_lattice_contract` and `verify_4bank_lattice_flush`.
4. **`siliquant#24/#26` Horizontal-State Quantization Bridge (`LLLM-SQ-01`):** Proves exact BF16 (`p=7`) carry-scan freeze at `g = 511/512` (`1/1` forever -> `>170%` error by `t=512` vs FP32 `0/1`), Global vs Per-Bank `RMSNorm` bleed (`9/16` vs `1/1`), Asymmetric FiLM leakage (`0/1` vs `61/256`), and `d_r = 256` outlier-masked RMS blindness under exact `comparison.rs` `w^2 / 12` variance (`802160640/16779511 ≈ 47.806 < 64` vs bulk-split `1048576/3 > 64`).
