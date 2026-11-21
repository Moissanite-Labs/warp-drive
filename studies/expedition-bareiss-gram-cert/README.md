# Exact Fraction-Free Bareiss Stacked-Adapter Gram Gate (Addressing `siliconcordat/warp#15`)

The gate module uses only the Python 3 standard library. The study runner also imports the shipped `warp_modeld.certificate` runtime for its direct comparison. The study addresses the mathematical and bit-growth challenges raised in [`siliconcordat/warp#15`](https://github.com/siliconcordat/warp/issues/15) without changing runtime code.

## Problem Addressed (`warp#15`)

In `src/warp_modeld/certificate.py`, `verify_stack_division_free` bounds a stack of $N$ adapters via Cauchy–Schwarz:
$$\left\|\sum_{i=1}^N s_i \Delta_i\right\|^2 \le N \sum_{i=1}^N s_i^2 \|\Delta_i\|^2,$$
charging up to an $N^2\times$ spectral over-penalty ($16\times$ for $N=4$, $64\times$ for $N=8$ orthogonal adapters) and preventing a composed certificate from admitting stacks rejected by the worst-case rule. Issue `#15` further observed that clearing rational denominators in a naive $L D L^\top$ certificate caused the integer multiplier $c$ to blow up to ~`4,330` bits even on a small case, and asked for:
1. A fraction-free exact elimination checker on $Q_{\mathrm{stack}}(s) = s G_B - G_B G_A G_B \succeq 0$,
2. A multiplication-only integer PSD acceptance certificate $C \cdot P Q P^\top = \sum_k w_k \tilde{\ell}_k \tilde{\ell}_k^\top$, and
3. An explicit integer rejection witness $x \in \mathbb{Z}^R$ satisfying $x^\top Q x < 0$.

## What This Study Ships

- **`bareiss_gram_gate.py`** (`int`/`Fraction`/`math.gcd`/`math.lcm`, no floating-point arithmetic or bare `assert`s):
  1. **Fraction-Free Bareiss Pivoted Symmetric Congruence (`1x1` and `2x2` zero-diagonal blocks):** Exact Sylvester divisibility at every step (`% prev_det == 0` verified fail-closed) with zero floating-point arithmetic.
  2. **Reduced Bareiss Integer Cholesky-Sum PSD Certificate (`verify_integer_psd_certificate`):** Factors column GCDs $g_k = \gcd(\ell_k)$ and reduces $g_k^2 / (\Delta_k \Delta_{k+1}) = p_k / q_k$ before taking $C = \operatorname{lcm}_k(q_k)$, keeping the multiplication-only verifier free of division while sharply cutting certificate bit-lengths (`237` bits cert / `97`-bit max pivot vs. `793` bits for naive rational LDL clearing on a dense coupled $R=8$ 4-adapter stack).
  3. **Constructive Integer Rejection Witness (`verify_integer_rejection_witness`):** On first negative $1\times 1$ or $2\times 2$ pivot, exact integer Cramer/Bareiss back-substitution over the SPD leading block produces a primitive integer vector $x \in \mathbb{Z}^R$ verified directly via $x^\top Q_{\mathrm{stack}}(s) x < 0$.
  4. **Singular-$G_{kk}$ Haynsworth–Schur Blind-Drift Certifier (`certify_heedle_blind_drift_haynsworth`):** Certifies exact worst-case outside-probe drift inside $\ker(J_{\mathrm{known}})$ via
     $$n_{\mathrm{unsafe}}(\tau) = n_-\!\begin{pmatrix}-\tau_{\mathrm{den}} G_{kk} & \tau_{\mathrm{den}} G_{ko} \\ \tau_{\mathrm{den}} G_{ok} & \tau_{\mathrm{num}} D^2 I - \tau_{\mathrm{den}} G_{oo}\end{pmatrix} - \operatorname{rank}(G_{kk})$$
     with zero matrix inversion or pseudoinverses, even when $G_{kk}$ is singular.
  5. **Higher-Moment Covert-Rank Gate (`certify_covert_rank_backdoor_gate`):** Demonstrates that a dense Householder-rotated rank-3 perturbation evading norm-only Frobenius/spectral caps and 2nd-moment `R_opt = 49/61 <= 1` is caught deterministically by exact 4th-moment `R_H4 = 904/573 > 1`.
  6. **Independent Dual Oracle (`faddeev_leverrier_descartes_inertia`):** Faddeev–LeVerrier characteristic polynomial and exact Descartes root counting provide separate inertia arithmetic. The oracle shares input validation with the Bareiss path.
- **`run_bareiss_warp_study.py`:** Executable comparison directly invoking `warp_modeld.certificate.verify_stack_division_free` alongside `certify_stacked_mde_gram`.

## Executable Measurements

- **Dual-oracle agreement:** `120/120` exact inertia matches (Bareiss vs. Faddeev–LeVerrier/Descartes) in the study runner using random seed `20261121`. The runner verifies 31 PSD certificates, checks the fourth-moment bound against exact positive rank on those 31 matrices, and verifies 89 rejection witnesses. No SymPy comparison is included in this study.
- **Eliminating `warp#15` Cauchy–Schwarz tax:**
  - $N=4$ orthogonal rank-2 adapters ($R=8$, true Frobenius$^2 = 8$, spectral$^2 = 1$): live `verify_stack_division_free` **rejects** (`16x` spectral tax); `certify_stacked_mde_gram` **certifies exact $s=1$** and rejects $s=99/100$ with an exact integer witness $x^\top Q x < 0$.
  - $N=8$ orthogonal rank-2 adapters ($R=16$): certifies exact $s=1$, eliminating a **`64x`** spectral tax.
- **Bit-length reduction on dense coupled $R=8$ 4-adapter stack:** Reduced Bareiss cert scale `237` bits (`97`-bit max pivot) vs. naive rational LDL clearing `793` bits (**`3.35x`** reduction).
- **Shared-carrier conflict + zone gating:** Overlapping carrier fails $s=1$ (`inertia [0, 1, 3]`, integer witness $x^\top Q(1) x = -824633720832 < 0$); muting the conflicting adapter (`route_num=0`) restores exact $s=1$ PSD.

## Reproduction (All 4 Isolated R4 Modes)

```bash
python3 -I -B studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py | shasum -a 256
python3 -I -O -B studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py | shasum -a 256
python3 -I -B -W error studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py | shasum -a 256
python3 -I -O -B -W error studies/expedition-bareiss-gram-cert/run_bareiss_warp_study.py | shasum -a 256
```

Each command must print `ad358f5c8bdf707ef7782abeaa7d56d388a46bc433ef7ad951853486639f295c` followed by `-`. The output is 1,771 bytes and is byte-identical across all four modes.

The repository suite remains unchanged. `PYTHONPATH=src python3 -B -m unittest discover -s tests` discovers 58 tests: 57 pass and the optional live-GGUF test is skipped.
