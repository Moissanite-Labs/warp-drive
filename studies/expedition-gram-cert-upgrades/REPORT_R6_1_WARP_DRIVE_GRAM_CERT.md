# Wave 2 Round 6 — Arm R6-1 (`AUDIT-061`): Non-Author Audit & Exact Upgrades for `Moissanite-Labs/warp-drive`

- **Arm / Owner:** Arm R6-1 (`spectral-prover`), target audit `AUDIT-061`
- **Target Repository (strictly read-only in Phases 1–2):** `Moissanite-Labs/warp-drive`
  - `main`: `e3899d3e0ef7697052e74e7a4f99f510d2b63ad5` (`dirty=0`)
  - PR `#1` (`port/bareiss-gram-stack-cert`, OPEN, non-draft): `8d9f81557059631dfbb71eebf61988dfde5ef70a` (`dirty=0`)
- **Novelty Rating (Law-4 Honest Classification):** **`N1`** — rigorous non-author mathematical, R1–R5, and mutation audit plus clean exact upgrades transferring verified expedition techniques (`AUDIT-014`, `AUDIT-051`, `AUDIT-052`). Zero `N2`/`N3` claims; strict compliance with `R6-N0-01..08` quarantine.

---

## 1. Executive Review Verdict

### PR `#1` (`port/bareiss-gram-stack-cert` @ `8d9f815570`)
**Verdict: Approve after 4 targeted surgical fixes (`PR1-B1..B4`).**

- **Law-2 Steelman (What Is Already Mathematically Sound — Do NOT Falsely Flag):**
  1. **Stacked Gram PSD equivalence (`Q_stack(s) = s G_B - G_B G_A G_B >= 0 <=> sigma_max^2(B A) <= s`)** holds identically **even when `G_B` is singular**, because `ker(G_B) = ker(B) <= ker(G_B G_A G_B)`.
  2. **2x2 zero-diagonal Bareiss update** (`studies/expedition-bareiss-gram-cert/bareiss_gram_gate.py:331-343`) is algebraically exact.
  3. **Generalized Haynsworth blind-drift inertia additivity** (`bareiss_gram_gate.py:935-1004`) holds identically **even when `G_kk` is singular (`SP-09`)**, because `ker(G_kk) = ker(J_k^T) <= ker(G_ok)` forces `r_cross = 0`.
  4. **Hygiene:** `0` CRLF files, `0` absolute home-directory path leaks, `0` bare `assert`s across all 3 PR `#1` files.

- **Required Pre-Merge Fixes on PR `#1`:**
  - **`PR1-B1` (Soundness Bug + Silent Float Coercion in Exported Public API):** `bareiss_gram_gate.py:741-783` (`r_h4_stieltjes_hankel_exact`) and `L735-738` (`r_opt_exact`).
  - **`PR1-B2` (Zero-Float Docstring Contradiction / JSON Float Emission):** `bareiss_gram_gate.py:16,861,863,865` and `run_bareiss_warp_study.py:240`.
  - **`PR1-B3` (Missing Input Validation Guards -> Raw `ZeroDivisionError`/`TypeError`/`AttributeError` + `bool` Acceptance):** `bareiss_gram_gate.py:391,522,525-526,836-844,851-852`.
  - **`PR1-B4` (R5 Mutation Blind Spot on `_req` + 53 Untested Guards + Dead Branch):** `bareiss_gram_gate.py:34-36,295-296` and `run_bareiss_warp_study.py:204-217`.

### `main` Stage-2 Gate (`src/warp_modeld/certificate.py` @ `e3899d3e`)
**Verdict: 4 concrete fail-closed/canonicity/mathematical hardening fixes (`WARP-CERT-01..04`) + 18 surviving R5 mutants (`WARP-CERT-05`, `14/32` = `43.75%` kill rate in repo Stage-2 unit tests).**

---

## 2. Detailed Findings on `src/warp_modeld/certificate.py` (`main @ e3899d3e`)

| ID | File : Line | Verified Live Behavior | Mathematical / Security Impact | Hardened Fix (Implemented & Verified) |
|---|---|---|---|---|
| **`WARP-CERT-01`** | `src/warp_modeld/certificate.py:16,103,105,112,227,250` | `SHA256_RE = re.compile(r"^[0-9a-f]{64}$")` uses `$` instead of `\Z`. `"a"*64 + "\n"` passes `SHA256_RE.match(...)`, `FixedRadixCertificate.create`, `verify_division_free`, and `from_weft_dict` (`factor_digest` / `adapter_sha256` / `base_weights_sha256`). | R3 trailing-newline smuggling into canonical certificate digests & downstream log/ledger records. | Replace regex with `re.compile(r"\A[0-9a-f]{64}\Z")` (`STRICT_SHA256_RE`). |
| **`WARP-CERT-02`** | `src/warp_modeld/certificate.py:403-417` | `stack_composition_digest([("a1", h1, 1, 1)])` (`c627775b...`) `!=` `stack_composition_digest([("a1", h1, 1000, 1000)])` (`cd725366...`); also accepts invalid scales like `(-5, 0)` without raising `CertificateError`. Note `(1000, 1000)` is used in `tests/test_weft_zone_alignment.py:211-212`. | Equivalent rational scales hash to distinct stack digests, breaking composed-certificate binding across callers using different radix representations; invalid scales are silently hashed. | Validate exact positive ints, reject duplicate `adapter_id`, enforce `\Z` SHA-256, and reduce `(scale_num, scale_den)` by `math.gcd` (`canonical_stack_composition_digest`). |
| **`WARP-CERT-03A`** | `src/warp_modeld/certificate.py:486-495` | `verify_stack_division_free` checks `composed_certificate` digest + `joint_bounds` + `spec <= frob`, with **zero cross-consistency check** against per-adapter certificates. Live repro: `\|\|Delta_1\|\|_F^2 = 16`, `\|\|Delta_2\|\|_F^2 = 1` (true `\|\|Delta_1+Delta_2\|\|_F^2 >= (4-1)^2 = 9`), yet a forged `composed_certificate` claiming `frobenius_sq_scaled = 0` is **ACCEPTED** (`composed_cert_verified = True`). | Unchecked `composed_certificate` can report physically impossible norm cancellation (`0 < 9`). | Exact root-free rational triangle check (`check_composed_norm_triangle_exact`): for `N=2`, `(a1 + a2 - c)^2 <= 4*a1*a2` (exact iff `(\|x1\|-\|x2\|)^2 <= \|x1+x2\|^2 <= (\|x1\|+\|x2\|)^2`); for `N>2`, dominant-adapter bound with `B_k = (N-1) sum_{j!=k} a_j`. |
| **`WARP-CERT-03B`** | `src/warp_modeld/certificate.py:467-484` | Multi-adapter `verify_stack_division_free` unconditionally enforces loose `N * sum s_i^2 \|\|Delta_i\|\|^2 <= joint_bounds` **before** checking `composed_certificate`. Live repro: honest orthogonal 2-adapter stack (`a1=1, a2=1`, true `Frob^2=2, Spec^2=1`) with exact `composed_certificate` and `joint_bounds=2` is **REJECTED** (`4 > 2`). | Even with an exact composed certificate, the `N^2` Cauchy–Schwarz tax blocks safe orthogonal/cancelling stacks (`warp#15`). | Support optional independently verified Bareiss Gram PSD escape hatch (`verified_gram_report` in `verify_stack_hardened`) **strictly bound to `adapter_ids`, PSD `(G_B, G_A)`, per-adapter diagonal Frobenius blocks, recomputed `tr(G_B G_A) <= joint_bounds.max_frobenius_sq`, and recomputed `Q_stack(s_cap) >= 0` with `s_cap <= joint_bounds.max_spectral_norm_sq`**, while **ALWAYS enforcing `joint_bounds.max_leakage_energy` and `joint_bounds.max_safety_dot_sq`** via exact CS (`AUDIT-061R` closing `GRAM-ESC-BYPASS-1` & `GRAM-ESC-BYPASS-2`). |
| **`WARP-CERT-03C`** | `src/warp_modeld/certificate.py:467` | `if len(items) > 1:` skips `joint_bounds` completely for 1-adapter stacks (unless `composed_certificate` is supplied). Live repro: 1-adapter stack with `norm=5` passes `single_bounds=10, joint_bounds=1`. | Policy tightening via `joint_bounds < single_bounds` is silently bypassed on single-adapter mounts (`verifier.py:416-422`). | Enforce `joint_bounds` uniformly on `len(items) == 1` as well. |
| **`WARP-CERT-04`** | `src/warp_modeld/certificate.py:338-347` | Passing `bytes` as `expected_adapter_sha256` or `expected_base_weights_sha256` to `verify_division_free` raises raw `TypeError` inside `hmac.compare_digest` (and `bounds=None` raises raw `AttributeError`), bypassing `CertificateError` and `WarpModeld.mount_stack`'s `except WarpError:` handler (`src/warp_modeld/verifier.py:423`). | Unhandled non-`WarpError` exception bypasses signed rejection ledger logging in `verifier.py:423-425`. | Explicitly validate `isinstance(bounds, CertificateBounds)` and strict `str` + `\Z` regex before `hmac.compare_digest` (matching `from_weft_dict:250`). |
| **`WARP-CERT-05`** | `src/warp_modeld/certificate.py` vs `tests/test_stage2_certificate.py` + `tests/test_weft_zone_alignment.py` | Live `aletheia v1.3.0 mutate` run: **`14/32` killed (`43.75%`), `18` survivors**! Critical security survivors: `M026` (`L334` `expected_adapter_id`), `M027` (`L338` `expected_adapter_sha256`), `M028` (`L342` `expected_base_weights_sha256`), `M031` (`L436` empty stack), `M032` (`L445` duplicate `adapter_id`), `M018`/`M029` (`L232,L350` `spec == frob` boundary), plus `M006..M014, M020, M024`. | Deleting all three cryptographic binding guards (`adapter_id`, `adapter_sha256`, `base_weights_sha256`) passes 100% of existing Stage-2 + weft unit tests. | Add explicit negative-control unit tests killing all 18 mutants to reach `32/32` (`100.0%`). |

---

## 3. Detailed Findings on PR `#1` (`studies/expedition-bareiss-gram-cert/`, `8d9f815570`)

| ID | File : Line | Verified Live Behavior | Mathematical / Engineering Diagnosis | Hardened Fix (Implemented & Verified) |
|---|---|---|---|---|
| **`PR1-B1`** | `bareiss_gram_gate.py:735-738, 741-783` | **(a) Mathematical Unsoundness:** On indefinite rank-1 counterexample `P = diag(3, 0)`, `Q = diag(0, -2)` (`b = n_+(Q) = 0`, true `rank(P) = 1`; `H = diag(3, -2)`, `S1=1, S2=13, S3=19, S4=97`), `r_h4_stieltjes_hankel_exact(Fraction(1), Fraction(13), Fraction(19), Fraction(97), 0)` returns **`Fraction(2, 1) > 1 = rank(P)`** (FALSE rank certificate!). **(b) Silent Float Return:** Calling `r_h4_stieltjes_hankel_exact(1, 13, 19, 97, 0)` or `r_opt_exact(1, 0, 2, 0)` with `int` arguments returns IEEE-754 **`float`** (`2.0`, `0.5`)! | Without `S1*S3 >= S2^2`, the KKT quadratic coefficient `c2 = (S2^2 - S1*S3)/D > 0` makes `f(x) = 1 - (1 - c1*x - c2*x^2)^2 > 0` on negative eigenvalues, so unconstrained `R_H4` bounds total rank `n_+(H) + n_-(H)` instead of `n_+(H)`. **Exact Theorem (proved in Section 4):** Adding `S1 > 0, S2 > 0, S3 > 0, S1*S3 >= S2^2, D = S2*S4 - S3^2 > 0` forces `c1 > 0` and `c2 <= 0`, making `f(x) <= 1_{x>0}` on ALL of `R`, hence `R_H4 <= n_+(H) <= rank(P) + b` even for **indefinite** `H`! | Coerce exact `int | Fraction` (reject `bool`/`float`), guard the Schur term with `S1 > 0 and S2 > 0 and S3 > 0 and S1*S3 >= S2*S2 and denom > 0`, and fall back to `max(0, S1^2/S2 - b, S3^4/S4^3 - b)` when `S1*S3 < S2^2` (`r_h4_stieltjes_sound`). |
| **`PR1-B2`** | `bareiss_gram_gate.py:16, 861, 863, 865`; `run_bareiss_warp_study.py:5, 240` | Docstrings claim `"Zero floats"`, yet `certify_covert_rank_backdoor_gate` returns 3 floats (`R_opt_float`, `R_H4_float`, `R_Q34_float`) via `round(float(...), 6)` and `run_bareiss_warp_study.py:240` emits JSON float `"bit_reduction_factor": 3.35`. | Violates strict zero-float JSON contract (`parse_strict_json_text(..., allow_float=False)`). | Emit exact integer `(num, den)` + `"num/den"` strings everywhere (`frac_dict`); remove float fields. |
| **`PR1-B3`** | `bareiss_gram_gate.py:391, 522, 525-526, 836-844, 851-852` | `certify_covert_rank_backdoor_gate` never validates `norm_cap_frob_sq`, `norm_cap_spec_sq`, or `max_allowed_extra_rank`: `f_den=0` raises raw `ZeroDivisionError`; `(1.5, 1)` raises raw `TypeError`; `max_allowed_extra_rank=True` (`bool`) is **silently accepted**. `verify_integer_psd_certificate([[1]], None)` and `certify_stacked_mde_gram([123], ...)` raise raw `AttributeError` instead of `GramGateError`. | Breaks fail-closed structured `GramGateError` boundary on untrusted JSON/RPC inputs. | Validate every mapping, rational pair (`require_rational_pair`), and exact integer (`type(v) is int`) via `require(...)`. |
| **`PR1-B4`** | `bareiss_gram_gate.py:34-36, 295-296`; `run_bareiss_warp_study.py:204-217` | Live `aletheia v1.3.0 mutate` reports **`1/1 (100.0%)`** on unmodified `bareiss_gram_gate.py` ONLY because `def _req(...)` (called **51 times**) is not in `aletheia/mutator.py:29` (`_REQUIRE_FUNC_NAMES`). Renaming `_req -> require` in an isolated temp copy reveals **`74` real mutants**, of which `run_bareiss_warp_study.py` (only 4 negative controls at `L204-217`) kills only **`21/74` (`28.38%`)**, leaving **`53` survivors**! Also `L295-296` (`if p2 == k: p2 = p1`) is dead code (`p2 > p1 >= k` by loop `L275-276`). | False sense of 100% R5 coverage masking 53 untested guards, plus a dead branch in 2x2 Bareiss pivoting. | Rename `_req` -> `require`, delete unreachable `L295-296`, and ship a dedicated R5 unit test suite killing 100% of guards. *(Also logged as an `aletheia v1.4` reverse-gem below!)* |
| **`PR1-B5`** | `bareiss_gram_gate.py:935-1004` | `certify_heedle_blind_drift_haynsworth` counts `n_unsafe_blind_directions`, but does not construct or verify an integer blind-drift witness `dw in ker(J_k) cap Z^d`. | Operators seeing `n_unsafe > 0` lack a directly replayable integer witness proving blindness (`J_k dw = 0`) and breach (`\|\|J_o dw\|\|_2^2 / \|\|dw\|\|_2^2 > tau`). | Implemented constructive primitive-integer witness extractor + 2-line independent integer verifier (`certify_blind_drift_with_witness`, `verify_blind_drift_witness_exact`) working even for singular `G_kk` (`SP-09`) and rank-0 `J_k`. |

---

## 4. Verified Exact Upgrades Delivered in `studies/expedition-gram-cert-upgrades/`

All four upgrades are implemented in pure Python 3 stdlib with zero floats, zero bare `assert`s, and `100.0%` R5 mutation kill in [warp_drive_gram_cert_audit.py](warp_drive_gram_cert_audit.py) and tested in [test_r5_warp_drive_gram_cert.py](test_r5_warp_drive_gram_cert.py):

1. **Exact KKT Moment-Cone Theorem for Indefinite `R_H4` (`r_h4_stieltjes_sound`):**
   Whenever `S1 > 0, S2 > 0, S3 > 0, S1*S3 >= S2^2`, and `D = S2*S4 - S3^2 > 0`, automatically `(S1/S2)*(S4/S3) > (S2/S3)*(S3/S2) = 1 => c1 = (S1*S4 - S2*S3)/D > 0` and `c2 = (S2^2 - S1*S3)/D <= 0`. Then `f(x) = 1 - (1 - c1*x - c2*x^2)^2` obeys `f(x) <= 1` for all `x in R` and `f(x) <= 0` for all `x <= 0`, proving `R_H4 = sum_i f(lambda_i) - b <= n_+(H) - b <= rank(P)` even on **indefinite** `H = P + Q`. On `H = diag(3, -2)` (`S1*S3 - S2^2 = -150 < 0`), the guard rejects the unconstrained Schur term and returns `130321/912673 <= 1` (`certified_min_rank = 1`), whereas on PSD `H = diag(10, 1, 1)` it yields `R_H4 = 3/1 > 24/17 = R_opt` with certified KKT dual `(c1, c2) = (11/10, -1/10)`.
2. **Constructive Singular-`G_kk` Blind-Drift Witness Extractor (`certify_blind_drift_with_witness`):**
   Extracts a maximal linearly independent row basis `J_k^{(r)}` of `J_k`, solves `G_rr X = G_ro` in exact `Q`, forms the `lcm`-cleared integer generalized Schur complement `S_int(tau) = L * (tau_n D^2 I - tau_d J_o P_k J_o^T)`, takes Bareiss negative witness `y` (`y^T S_int y < 0`), and projects `dw = prim(P_k J_o^T y) in Z^d`. By Cauchy–Schwarz `\|y\|_2 \|J_o v\|_2 >= y^T J_o v = \|v\|_2^2`, `dw` is guaranteed nonzero, strictly blind (`J_k dw = 0`), and strictly breaching (`tau_d \|J_o dw\|_2^2 > tau_n D^2 \|dw\|_2^2`). Demonstrated live on rank-1 singular `G_kk` (`J_k = [[1,0,0],[2,0,0]]`, `J_o = [[1,0,0],[0,3,4]]`, `tau = 10`): emits `dw = [0, 3, 4]` with exact `J_k dw = [0, 0]` and exact amplification `25/1 > 10/1`.
3. **Multifrontal `SignedTree` Block-Schur Certifier (`AUDIT-052` transfer):**
   Recursive `leaf` / `block_sum` / `schur_couple` evaluator enforcing exact generalized range containment `col(B) <= col(A)` via `solve_consistent_linear_rational(A, B)`. On a 3-layer stack with a rank-1 singular coupled `A = [[2,2],[2,2]]` block (`dim = 8`), `SignedTree`, flattened Bareiss, and independent Faddeev–LeVerrier all certify identical inertia `[7, 0, 1]`, while `SignedTree` cuts peak pivot bit-length from `9` bits to `4` bits.
4. **8-Glyph Operator Calculus Compression (`AUDIT-051`):**
   - Stacked Gram PSD: `⦺(G_stack ⧄ B_blk) ⩩ (r_+, 0, r_0) ⫩ R5_gate`
   - Singular-`G_kk` Blind-Drift (`SP-09`): `⦺(M_blind ⧄ G_kk) ⩩ (m_o - n_u, n_u, 0) ; dw in ⧅(J_k, J_o)`
   - Multifrontal Coupled Schur (`SignedTree`): `⦺(M_coupled) ⩩ ⦺(A) + ⦺(M_coupled ⧄ A)  [col(B) <= col(A)]`

---

## 5. Reverse-Gem for `Foundation-0/aletheia v1.4`

During `PR1-B4`, `aletheia v1.3.0 mutate` missed all 51 `_req(...)` calls in `bareiss_gram_gate.py` because `aletheia/mutator.py:29` matches only a fixed allowlist `_REQUIRE_FUNC_NAMES = {"require", "require_ok", "require_cert", "check", "ensure"}`. Adding a 10-line AST pre-pass in `aletheia/mutator.py` that discovers any local wrapper `def f(cond, ...): if not cond: raise ...` (single-statement refusal wrapper on parameter 0) automatically exposes custom helpers like `_req`, `_check`, and `_guard` to R5 mutation testing without requiring callers to rename private helpers.

---

## 6. Law-4 Quarantine & Verification Checklist

- **Strict `R6-N0-01..08` Compliance:** No novelty claimed for standard `FixedRadixCertificate` cross-multiplication, textbook Bareiss/Haynsworth identities, or standard Python regex/packaging fixes; all upgrades are honest `N1` engineering/certification transfers.
- **Read-Only Discipline:** Both pinned snapshots (`Moissanite-Labs/warp-drive@e3899d3e` and PR `#1` `@8d9f8155`) were audited strictly read-only (`dirty=0`).
- **Artifacts in `studies/expedition-gram-cert-upgrades/`:**
  - [warp_drive_gram_cert_audit.py](warp_drive_gram_cert_audit.py)
  - [test_r5_warp_drive_gram_cert.py](test_r5_warp_drive_gram_cert.py)
  - [warp_drive_gram_cert_certificate.json](warp_drive_gram_cert_certificate.json)
  - [REPORT_R6_1_WARP_DRIVE_GRAM_CERT.md](REPORT_R6_1_WARP_DRIVE_GRAM_CERT.md)
