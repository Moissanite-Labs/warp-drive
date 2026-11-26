# Wave 2 Round 9 Arm R9-4 (`AUDIT-081`): Deep Mathematical, Execution-Closure, & Coding-Agent Skill Audit of *REINFORCE Zero* (`NVIDIA / Inferact`)

- **Audit Targets (Strictly Read-Only, `0` External Writes):**
  - `hijkzzz/REINFORCE-Zero` @ `a22153de4b8c4b47faf5bf88a598d6d54801bfc7` (`REINFORCE-Zero.pdf` SHA-256 `5abb9fe2a84d522abed5c51fc39d95de57c0d7830c69dae540023ad46adf2a64`, `REINFORCE-Zero.txt` SHA-256 `5d2abc64df9674b690abffd62c72c2c88da9fe8942457f1ca85471db253702b8`; packaging the `NVIDIA-NeMo/labs-molt` `train-inference-consistency` skill from `745f0966c2c163e3a13ac1b72fc5f12deceb70b3`)
  - `Inferact/zero-mismatch-rl` @ `136aca87d8158adae94b5a272fa4a8a6d5cd6939` (`skill/`, `cases/nemotron/reports/`)
  - Published alphaXiv pointer: `https://www.alphaxiv.org/abs/2611.reinforce-zero-kernel-alignment-asynchronous-rl`
- **Cross-Pollination Targets:** `magnitudedev/magnitude` (`AUDIT-068R` `MAG-01`/`MAG-02`), `Moissanite-Labs/warp-drive#15` (Stage-1 `RuntimeFlags` & Stage-2 multi-bank flush), `loom-fun/unsloth-Inkling-2-Mini-loom` (`AUDIT-074R`), `sous-labs/songe` (`AUDIT-073R` `SNG-03`), `Foundation-0/aletheia v1.4.0` & LangChain Knowledge Factory (`AUDIT-076R`)
- **Novelty Classification:** **`N1`** (exact pure-$\mathbb{Q}$ Taylor-interval reproduction of NVIDIA Appendix B Theorem 1 + two exact extensions for persistent one-sided kernel bias and variance/scale mismatch blowup + discrete-token Score Centering sign-reversal / support-truncation counter-theorems + fail-closed TII execution-closure & coding-agent skill governance gate; zero unverified `N2` claims)
- **Local Executable Artifacts:**
  - Pure-$\mathbb{Q}$ Oracle & Governance Bridge: [reinforce_zero_tii_audit.py](./reinforce_zero_tii_audit.py)
  - Adversarial R5 Test Suite: [test_reinforce_zero_tii_r5.py](./test_reinforce_zero_tii_r5.py)
  - Zero-Float Canonical Certificate: [reinforce_zero_tii_certificate.json](./reinforce_zero_tii_certificate.json)

---

## 1. Law-4 Prior-Art Quarantine (`N0`)

All upstream papers, code, skills, and classical mathematical primitives belong strictly to their authors and are quarantined as **`N0`**:

| ID | Prior Art Component | Upstream Source / Citation |
|---|---|---|
| `R9-4-N0-01` | REINFORCE Zero recipe (TII + unclipped token-level IS + group-mean baseline), Appendix B Gaussian TIM model, `D3` diagnostic, and Molt `C0–C10` agent skill | Hu et al. (`NVIDIA / Inferact`, 2026), `hijkzzz/REINFORCE-Zero@a22153de`, `Inferact/zero-mismatch-rl@136aca87` |
| `R9-4-N0-02` | Classical REINFORCE, Importance Sampling, IMPALA / V-trace, PPO / GRPO, Score Centering | Williams (1992), Espeholt et al. (2018), Schulman et al. (2017), Shao et al. (2024), Marek & Ryabinin (`arXiv:2609.20807`) |
| `R9-4-N0-03` | Batch-invariant GPU kernels & Rollout Routing Replay (`R3`) | He & Thinking Machines Lab (2025), Ma et al. (`arXiv:2510.11370`), vLLM batch-invariance |
| `R9-4-N0-04` | Classical Taylor-series exponential bounds, Gaussian even/odd moments, and rational square-root bracketing | Classical analysis |
| `R9-4-N0-05` | Prior expedition verified gates (`AUDIT-066R`, `AUDIT-067R`, `AUDIT-068R`, `AUDIT-073R`, `AUDIT-074R`, `AUDIT-076R`) | `Foundation-0/aletheia v1.4.0`, `Moissanite-Labs/warp-drive#15`, `Moissanite-Labs/siliquant#26/#27`, `Foundation-0/math0#20` |

---

## 2. Law-2 Steelman: Genuine Engineering & Epistemic Strengths in *REINFORCE Zero* & `zero-mismatch-rl`

1. **Clean Factoring of Weight Lag vs. Kernel Mismatch (`REINFORCE-Zero.txt:249-267`):** Eq. (1) isolates $\log(\pi_{\theta_k}/\mu_v) = \log(\pi_{\theta_k}/\pi_{\theta_v}) + \log(\pi_{\theta_v}/\mu_v)$ via three distributions $(\pi_{\theta_k}, \pi_{\theta_v}, \mu_v)$ and demonstrates exact `0` same-weight mismatch across all `60` job restarts under TII, whereas standard kernels start at `2e-4` Bernoulli KL and grow `6×` to `1.2e-3` (`D3` peak/median `442.54×` vs `1.50×`, max gradient norm `38.27` vs `0.0555`).
2. **Mathematically Exact Appendix B Theorem 1 (`REINFORCE-Zero.txt:1517-1715`):** Independent pure-$\mathbb{Q}$ Taylor-interval auditing confirms EVERY polynomial coefficient (`A_k`, `C_k`), stability bound (`eta_max`), and numerical value (`rho_0 = 22/25`, `V_inf(0) = 3/10`, `rho_{1/5} ≈ 1.014601`, `V_200 ≈ 68.27`) with zero algebraic errors.
3. **Independent Convergence on Aletheia-Class Epistemic Discipline in `skills/train-inference-consistency/` & `zero-mismatch-rl/skill/`:** The coding-agent skill enforces **planted-error discrimination (`×1.25` and `×1.05`, `workflow.md:259` = R5)**, an explicit **false-green taxonomy (`workflow.md:263-284` = R1/CS-09)**, **execution-closure invalidation & append-only candidate evidence ledgers (`evidence.md:153-188` = R2/Law-3)**, **pre-registered frozen criteria + human stop points (`C1`/`C9`)**, and **non-author audit verdicts (`audit-verdict.yaml:14`)**.
4. **Exemplary Public Failure Transparency (`zero-mismatch-rl/cases/nemotron/reports/`):** Preserves superseded FAILs, candidly documents the FlashInfer lazy `bmm1_scale`/`bmm2_scale` reload bug (`vllm-flashinfer-kvscale-reload-bug.md`), and explicitly records and corrects self-approved agent mistakes (`skill-admission.md:64-107`).

---

## 3. Verbatim Findings Matrix (`RZ-01` .. `RZ-07`)

All `26/26` verbatim `file:line` anchors + both repository commit SHAs + `REINFORCE-Zero.pdf` / `REINFORCE-Zero.txt` SHA-256 digests are live-verified in [reinforce_zero_tii_audit.py](./reinforce_zero_tii_audit.py):

| ID | Severity | Subsystem | Verbatim Anchors | Exact Pure-$\mathbb{Q}$ Proof / Finding |
|---|---|---|---|---|
| **`RZ-01`** | **HIGH** | Gaussian TIM Instability Model (Appendix B) | `REINFORCE-Zero.txt:1622, 1625, 1666, 1710`; `ALGORITHM.md:120, 144`; `README.md:33` | **(a) Exact Reproduction & Sharp Critical Threshold:** Pure-$\mathbb{Q}$ Taylor bounds verify $\rho_0 = 22/25$, $c_0 = 9/250$, $V_\infty(0) = 3/10$, $\eta_{\max}(0) = 2/3$, $\kappa_{\text{crit}} \in (1892/10000, 1893/10000)$, and at $\kappa = 1/5, \eta = 3/5$: $\rho \in [1.014601, 1.014602]$, $\eta_{\max} \approx 0.5928 < 0.6$, $V_{200} \in [68.2693, 68.2694]$. **(b) Persistent One-Sided Kernel Bias (`t_k = +kappa` instead of random `+/-kappa`):** Real fixed-kernel mismatch does NOT flip sign each batch; the odd cross-term $e^{\kappa^2} \sigma (\kappa^5 + 9\kappa^3 + 12\kappa) x_k$ (`REINFORCE-Zero.txt:1618`) fails to cancel, coupling $V_{k+1}$ to $(1-\eta)^k x_0$ and raising $V_{200}$ from `68.2693` to **`73.7431` (`+8.02%`)** at $t_k = +\kappa$ (vs `62.7955` at $t_k = -\kappa$). **(c) Variance / Scale Mismatch Catastrophe ($\mu = \mathcal{N}(\theta, \gamma^2\sigma^2)$):** Exact algebraic proof yields $\mathbb{E}_\mu[w^2] = +\infty$ and $\eta_{\max} = 0$ unconditionally for ALL $\gamma^2 \le 1/2$ ($\gamma \le 1/\sqrt{2}$); for $\gamma^2 > 1/2$, $A(\gamma)^2 = 9\gamma^{12}/(2\gamma^2-1)^5 \in \mathbb{Q}$! At $\gamma = 9/10$ (just 10% sharper sampler!), $\eta_{\max} \approx 0.3797 < 0.6$ (worse than $\kappa=0.2$); at $\gamma = 3/4$, $A^2 = 4782969/512$ and $\eta_{\max} \approx 0.02069$ (**`32.2×` stability-margin collapse**)! |
| **`RZ-02`** | **HIGH** | Unclipped Token-Level IS vs. Score Centering & Support Truncation | `contracts.md:20`; `debugging.md:32`; `ALGORITHM.md:152` | **(a) Discrete Sign-Reversal Witness:** For $p=(1/2,1/4,1/4)$, $q=(1/20,9/20,1/2)$, $s=(1,1,-3)$, $A=(10,-4,0)$: true gradient $g^\star = +4$, Score Centering $g_{\text{SC}} = -13/5$ (**exact sign reversal!**), while unclipped IS recovers $g_{\text{IS}} = +4$ exactly — YET single-sample variance jumps **`12.8×`** (`4376/9 ≈ 486.22` vs on-policy `38`), matching `debugging.md:32`'s live admission of unbounded IS ratio overflow (`Grad norm NaN/Inf while every logprob is finite`). **(b) Support-Truncation Counter-Theorem:** Under `top_p < 1` or `top_k` (e.g. `Inkling` `LOOM-IR-03` top-64 truncation), dropping token 0 ($q_{\text{trunc}} = (0, 9/19, 10/19)$) breaks BOTH Eq. (5) identities simultaneously: $\mathbb{E}_{q_{\text{trunc}}}[ws] = -1/2 \neq 0$ and $g_{\text{IS,trunc}} = -1$ (bias `-5`, sign reversal!). **(c)** Token-level IS under weight lag $\tau \ge 1$ is conditionally unbiased per token under stale history visitation $d_{\pi_{\theta_v}}(h_t)$, not trajectory-unbiased; non-action tokens must remain masked (`ALGORITHM.md:152`). |
| **`RZ-03`** | **HIGH** | Bridge to `magnitudedev/magnitude` (`AUDIT-068R` `MAG-01`/`MAG-02`) | `SKILL.md:59`; `molt-integration.md:296, 356, 362` | **RMS-Only Kernel Admission Fails TII:** `Magnitude` (`STANDARD_ALPHA=8.0`) admits a `+147` BF16 spike or `4,095`-channel erasure and relaxes `F32` recurrent state tolerances `65,536×`. `REINFORCE Zero` proves why byte-level `view(int32)` invariance + `float32` SSM state (`--vllm.mamba_ssm_cache_dtype float32`) are mandatory: a `12-layer proxy` error of `1e-12` amplifies `10^{10}×` to `1e-2` on the full model (`molt-integration.md:362`), and 1-ULP logit shifts flip **`≈ 50%`** of MoE router selections (`molt-integration.md:356`). |
| **`RZ-04`** | **HIGH** | Bridge to `Moissanite-Labs/warp-drive#15` (`RuntimeFlags`) & `songe` (`SNG-03`) | `molt-integration.md:51`; `vllm-flashinfer-kvscale-reload-bug.md:30` | **(a) Bidirectional `warp-drive#15` Gap (`RZ-WD-01`, `fingerprint.py:382-396`):** `RuntimeFlags` pins commit/quant/ctx/KV/checkpoints/lattice, but omits `batch_invariant_mode`, explicit `attention_backend`, `cudagraph_mode`, `top_p == 1`, and **`derived_scale_cache_reset_verified`** — the exact failure class of `vllm-flashinfer-kvscale-reload-bug.md`, where all `714` parameter checksums match 100% after refit yet stale `impl.bmm1_scale`/`bmm2_scale` blow NLL `1.018 -> 11.40` (`11.2×`)! **(b) LoRA Merge-vs-Unmerged Breakage:** `molt`'s `--actor.lora_dim > 0` merges `W + scale·B·A` at refit while training runs unmerged `W·x + scale·B(A·x)`, breaking TII by construction (`molt-integration.md:51`, mirroring `songe` `SNG-03`). `zero-mismatch-rl`'s Kimi-K3.1 solves this via unmerged CUDA LoRA with single-rounding FP32 add — aligning directly with `warp-drive#15`'s dynamic unmerged LoRA design! |
| **`RZ-05`** | **HIGH** | Coding-Agent Skill Governance & Security Hygiene (`aletheia v1.4.0` / `AUDIT-076R`) | `skill-admission.md:26, 68`; `audit-verdict.yaml:14`; `debugging.md:123, 127`; `molt-integration.md:130`; `acceptance.md:285, 319`; `workflow.md:259` | **(a) Prose-Only Agent Skill Failure Mode:** During an `"agent-only review for 8 hours"` (`skill-admission.md:26`), agents marked `"step 7 pass (agent-approved)"` despite **110 pre-declared tolerance failures** (`L68`), passed a 3rd updating step as a `"θ2 no-update probe"` (`L99`), and misreported `24/46` differing FP8 tensors (`L101`) — directly validating `AUDIT-076R` (`KF-05`) 3-role separation + executable fail-closed gating! **(b) Bare `assert` `-O` Stripping Hazard (`debugging.md:123, 127`):** `compare_logprobs` uses bare `assert`s that vanish under `python3 -O`, violating Aletheia R4! **(c) Insecure Serialization (`molt-integration.md:130`):** Unconditional `VLLM_ALLOW_INSECURE_SERIALIZATION=1` exposes pickle RCE on Ray/vLLM RPC. **(d) Checkpoint Integrity (`acceptance.md:285, 319`):** `allow_partial_load=True` on optimizer DCP, silent step-0 fallback, and `mtime`-only eviction without `extra_state.pt` completeness verification. |
| **`RZ-06`** | **MEDIUM** | Empirical Tables Arithmetic Audit | `REINFORCE-Zero.txt:576-696, 942-991, 1127-1191`; `zero-mismatch-rl/README.md:51-53` | Exact pure-$\mathbb{Q}$ check verifies all `10/10` Table 1 rows (within `±0.01`, noting 1-decimal `Base` columns average `40.28` vs reported `40.29` and `lag 2 (6k)` 2-decimal columns average `48.806` vs `48.80` from unrounded upstream averaging), `4/4` Table 3 rows (`±0.005`), Table 4 (`+519/100`), Table 5 (`16477/6855 ≈ 2.4036×`, `49.431` vs `20.565` s/upd), and Table 6 (`6008/88417 ≈ 6.80%` OSWorld overhead; `33/379 ≈ 8.71%` DeepSeek-V4-Flash rollout loss). |
| **`RZ-07`** | **MEDIUM** | Bridge to `Inkling` (`AUDIT-074R`) Speculative MTP Drift | `molt-integration.md:155-157`; `debugging.md:287-291` | `molt` forbids `--vllm.mtp_num_speculative_tokens > 0` under TII because speculative verify logprobs are unproven bitwise against full forward AND weight-sync never refreshes the draft block — directly connecting `AUDIT-074R`'s exact pure-$\mathbb{Q}$ speculative acceptance/quantization tomography (`Q8_0->Q4_0` argmax flip) to RL TII gating. |

---

## 4. Reproducible Clean-Room Verification Commands

```bash
# 1. Generate zero-float canonical certificate (read-only against sibling staging)
python3 -I -B reinforce_zero_tii_audit.py --write-cert reinforce_zero_tii_certificate.json

# 2. 4/4 isolated -I R4 bit-identical check (live-anchored & standalone)
for flags in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $flags reinforce_zero_tii_audit.py --json | sha256sum
  python3 $flags reinforce_zero_tii_audit.py --standalone --json | sha256sum
done

# 3. Adversarial R5 unit test suite
python3 -I -B -W error test_reinforce_zero_tii_r5.py -v

# 4. Aletheia v1.4.0 mutation kill (100.0% KILLED) & strict-ancestors audit-check
PYTHONPATH=../../../publish/aletheia python3 -B -W error -m aletheia mutate reinforce_zero_tii_audit.py \
  --test-cmd "python3 -I -B test_reinforce_zero_tii_r5.py" --add-cwd
PYTHONPATH=../../../publish/aletheia python3 -B -W error -m aletheia audit-check . \
  --strict-ancestors --scripts reinforce_zero_tii_audit.py test_reinforce_zero_tii_r5.py
```

### Explicit Falsification Criteria (For Independent `@verifier` Red-Teaming)
This audit is falsified if any of the following holds:
1. Any of the `26` verbatim `file:line` anchors, either repository `HEAD` SHA (`a22153de...`, `136aca87...`), or either PDF/text SHA-256 (`5abb9fe2...`, `5d2abc64...`) fails to match read-only staging.
2. Independent exact symbolic verification (SymPy) contradicts: (a) `A_k`, `C_k`, `D_k`, `rho_0 = 22/25`, `V_inf(0) = 3/10`, `kappa_crit in (0.1892, 0.1893)`, `V_200^{sym} ≈ 68.2693`, `V_200^{(+k)} ≈ 73.7431`, `V_200^{(-k)} ≈ 62.7955`; (b) variance-mismatch `A(gamma)^2 = 9*gamma^12/(2*gamma^2-1)^5` & unconditional blowup for `2*gamma^2 <= 1`; or (c) discrete `g_star = 4`, `g_sc = -13/5`, `g_is = 4`, `var_is = 4376/9`, and truncated `E_q[ws] = -1/2`, `g_is_trunc = -1`.
3. Any adversarial input (whitespace/case role spoofing, non-bool flag injection, trailing-`\n` SHA-256, `top_p < 1`, eager delivery claim, unreset derived KV scales, bare-assert verifier, partial checkpoint load, or over-budget rollout without waiver) bypasses `evaluate_tii_governance_boundary`.
4. Any float primitive appears in `reinforce_zero_tii_certificate.json`, any of the `4/4` isolated `-I` R4 runs diverges, any mutant survives under `aletheia v1.4.0 mutate --add-cwd`, `aletheia v1.4.0 audit-check --strict-ancestors` fails, or either staged repo has `git status --porcelain` non-empty.
