# Expedition Gram-Certificate Upgrades & Stage-2 Audit (`AUDIT-061R`)

Self-contained, zero-dependency Python 3 standard-library (`int`, `fractions.Fraction`) study accompanying `Moissanite-Labs/warp-drive` (`src/warp_modeld/certificate.py`, Issue `#2`, Issue `#3`, and PR `#1` `studies/expedition-bareiss-gram-cert/`).

- **Audit Status:** `AUDIT-061R` independently **`VERIFIED`** (`exact+anchor`, honest Law-4 novelty **`N1`**, upgraded with PR `#12` review singleton-equality closure -> **`104/104` (`100.0%`)** R5 mutation kill via `aletheia v2.0.0 mutate --max-mutants 0 --add-cwd`, `0` floats in JSON, `0` bare `assert`s).
- **Pinned Audit Snapshots:** Audited read-only against `main @ e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` and PR `#1` pre-merge snapshot `8d9f81557059631dfbb71eebf61988dfde5ef70a`. *(Note: PR `#1` subsequently landed review fixes `0cb8fbd` in `38a7072` on `main`; this study preserves the exact Stage-2/Gram upgrades without modifying `src/warp_modeld/` or `studies/expedition-bareiss-gram-cert/`.)*

---

## Manifest

| File | Role |
|---|---|
| [`warp_drive_gram_cert_audit.py`](warp_drive_gram_cert_audit.py) | Zero-float pure-stdlib exact KKT indefinite `R_H4`, constructive singular-$G_{kk}$ blind-drift witness extractor, multifrontal `SignedTree` block-Schur certifier, hardened `verify_stack_hardened` (incl. `n == 1` singleton equality `COMPOSED_SINGLETON_MISMATCH`), and 8-glyph operator compression (`⧄ ⧅ ⦺ ⩩ ⫩`). |
| [`test_r5_warp_drive_gram_cert.py`](test_r5_warp_drive_gram_cert.py) | 11-test R1–R5 verification, dual-oracle Bareiss vs. Faddeev–LeVerrier, singleton forgery regression, recursive zero-float, and `104/104` mutation-kill suite. |
| [`warp_drive_gram_cert_certificate.json`](warp_drive_gram_cert_certificate.json) | Sealed zero-float canonical JSON certificate regenerated directly from `--standalone` (`9c40dd41...`, `certificate_sha256: d70e966b...`) so it is 100% byte-for-byte reproducible from this PR tree alone. |
| [`REPORT_R6_1_WARP_DRIVE_GRAM_CERT.md`](REPORT_R6_1_WARP_DRIVE_GRAM_CERT.md) | Full audit report, Law-2 steelman, Law-4 `R6-N0-01..08` quarantine, `WARP-CERT-01..05` & `PR1-B1..B5` tables, and exact mathematical derivations. |

---

## Quick Standalone Reproduction

Run directly from `studies/expedition-gram-cert-upgrades/` (zero external clones or third-party packages required; reproduces `warp_drive_gram_cert_certificate.json` byte-for-byte):

```bash
# 4-mode isolated -I R4 bit-identical standalone certificate (matches committed JSON byte-for-byte)
for f in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $f warp_drive_gram_cert_audit.py --standalone | sha256sum
  # Expected: 9c40dd410564d677d01800a36cdeaab2eb9d8156efce52d8fcdb76c591d2ee76
  python3 $f test_r5_warp_drive_gram_cert.py
done
```

*(Optional live-clone inspection mode: omitting `--standalone` additionally inspects read-only sibling checkouts `../repos/warp-drive` @ `e3899d3` and `../repos/warp-drive-pr1` @ `8d9f815` when present locally; those external checkouts are not committed in this PR, so the committed JSON is sealed from `--standalone` for full self-contained reproducibility.)*

---

## Key Verified Upgrades Delivered

1. **Exact KKT Moment-Cone Theorem for Indefinite `R_H4` (`r_h4_stieltjes_sound`):** Enforces `S1 > 0, S2 > 0, S3 > 0, S1*S3 >= S2^2, S2*S4 > S3^2` so `R_H4 <= n_+(H) <= rank(P) + b` holds even on indefinite `H = P + Q` (eliminating false rank certificates like `2/1 > 1` on `diag(3, -2)`).
2. **Constructive Singular-$G_{kk}$ (`SP-09`) Blind-Drift Witness Extractor (`certify_blind_drift_with_witness` + `verify_blind_drift_witness_exact`):** Extracts and verifies a primitive integer vector `dw in ker(J_k) cap Z^d` proving exact blindness (`J_k dw = 0`) and exact threshold breach (`tau_d ||J_o dw||^2 > tau_n D^2 ||dw||^2`), even when `G_kk` is rank-deficient.
3. **Multifrontal `SignedTree` Block-Schur Certifier (`evaluate_signed_tree_inertia`):** Recursive `leaf` / `block_sum` / `schur_couple` inertia evaluator enforcing exact range containment `col(B) <= col(A)`, cutting peak pivot bit-length from `9` to `4` bits (triple-oracle verified against flat Bareiss & Faddeev–LeVerrier).
4. **Stage-2 `certificate.py` Hardening Blueprint (`WARP-CERT-01..05`):** Strict `\A[0-9a-f]{64}\Z` SHA-256 matching, GCD-canonicalized `stack_composition_digest`, exact root-free reverse-triangle consistency check on `composed_certificate`, verified Bareiss Gram PSD escape hatch (`verify_stack_hardened`), and 18 missing Stage-2 mutation-kill test targets (`14/32 -> 32/32`).
