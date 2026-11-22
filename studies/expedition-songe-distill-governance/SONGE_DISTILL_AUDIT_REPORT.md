# Wave 2 Round 8 Arm R8-2 (`AUDIT-073`): Deep Security, Mathematical, & Governed-Iteration Audit of `sous-labs/songe`

- **Audit Target (Strictly Read-Only, `0` external writes):** `sous-labs/songe` @ `5b7b13768e1ac67e7e3284043ec51f24394a740f` (`2026-11-21`, `Support text-only Qwen3.5 in GGUF-to-MLX conversion (#41)`, Apache-2.0, `Songe 0.1.0a14`)
- **Cross-Pollination Targets:** `Moissanite-Labs/warp-drive` (`#12`/`#13`/`#15`), `Moissanite-Labs/hillclimb#4`, `magnitudedev/magnitude` (`AUDIT-068R` / `siliquant#26`)
- **Novelty Classification:** **`N1`** (engineering synthesis, exact pure-$\mathbb{Q}$ Mercator-interval disproof of asymmetric clipped forward KL + Bregman-normalized repair, exact pure-$\mathbb{Q}$ bootstrap-degeneracy analysis bridged to `AUDIT-068R` Ville supermartingale, and fail-closed governance gate; zero unverified `N2` claims)
- **Local Executable Artifacts:**
  - Oracle & Cross-Pollination Bridge: [songe_distill_governance_audit.py](./songe_distill_governance_audit.py)
  - Adversarial R5 Test Suite: [test_songe_governance_r5.py](./test_songe_governance_r5.py)
  - Zero-Float Canonical Certificate: [songe_governance_certificate.json](./songe_governance_certificate.json)

---

## 1. Law-4 Prior-Art Quarantine (`N0`)

All upstream components belong strictly to their respective authors and are quarantined as `N0`:

| ID | Prior Art Component | Upstream Source / Citation |
|---|---|---|
| `R8-2-N0-01` | Hindsight on-policy self-distillation (OPSD/SDFT) local idle-compute LoRA architecture, Quick Dreams vs Deep Dreams | `sous-labs/songe` `DESIGN.md`, `src/songe/backends/objective.py`, `src/songe/sleep/{gate.py, evaluate.py, judged.py, worker.py}` (citing OPSD arXiv:2601.18734, SDFT arXiv:2601.19897) |
| `R8-2-N0-02` | Classical Bregman divergence normalization $d(p, q) = p \ln(p/q) - p + q \ge 0$ & Gibbs' inequality | Classical convex analysis / Bregman (1967) |
| `R8-2-N0-03` | Mercator series rational logarithm bounds $\ln\frac{1+u}{1-u} = 2\sum_{k\ge 0} \frac{u^{2k+1}}{2k+1}$ | Classical analysis |
| `R8-2-N0-04` | Anytime-valid uniform-Beta mixture paired sign supermartingale (Ville's inequality) | `magnitudedev/magnitude` (`AUDIT-068R` / `siliquant#26`) |
| `R8-2-N0-05` | Stage 1–4 checkpoint SHA-256 pinning, loopback Bearer auth, delimiter fence sanitization, multi-bank flush | `Moissanite-Labs/warp-drive` (`#12`, `#13`, `#15`) |
| `R8-2-N0-06` | Multiplicity-safe bounded optimization & held-out outside-anchor ratification | `Moissanite-Labs/hillclimb#4` |

---

## 2. Law-2 Steelman: Genuine Engineering Strengths in `sous-labs/songe`

Before listing defects, five concrete hardening choices in `sous-labs/songe` are genuinely strong:

1. **Zero Execution of User Tools During Idle Dreams (`src/songe/practice/checks.py:97-109`):** Practice scenes are validated statically via `ast.parse` and `json.loads`; user shell/code tools are never re-executed while idle.
2. **Safe Model Deserialization & Local-Only Loading (`src/songe/backends/torch.py:177, 199, 218`; `src/songe/backends/training.py:102`; `src/songe/artifacts/worker.py:17, 23`):** Consumes `trust_remote_code=False`, `local_files_only=True`, and `weights_only=True` consistently, and `steps.py:346-362` disables remote JSON-Schema `$ref` fetching.
3. **Private Filesystem & Secure Deletion (`src/songe/storage.py:10-25, 108-126`; `src/songe/log.py:362, 727-786`):** Enforces `0o700`/`0o600` permissions with symlink refusal in `private_tree`, atomic `os.replace` + directory `fsync`, SQLite `0o600`, and `PRAGMA secure_delete=ON` + `wal_checkpoint(TRUNCATE)` + `VACUUM` on `forget()`.
4. **Dual-Order Blind Judging & Exact-Tail Top-$k$ KL (`src/songe/sleep/judged.py:140-150`; `src/songe/backends/objective.py:29-37`):** Evaluates candidate vs incumbent in both AB/BA orders to neutralize position bias, retains an exact aggregate tail bucket when `top_k > 0`, and clips gradient norms on both MLX (`training.py:216`) and PyTorch (`torch.py:659`).
5. **Optimistic CAS Version Swaps (`src/songe/log.py:507-536`):** Protects `current`/`previous` pointer commits with `BEGIN IMMEDIATE` + `expected`/`generation` checks.

---

## 3. Verbatim Findings Matrix (`SNG-01` .. `SNG-08`)

Every finding is pinned to verbatim `file:line` anchors at commit `5b7b13768e1ac67e7e3284043ec51f24394a740f` (`21/21` anchors live-verified) and proven in exact pure-$\mathbb{Q}$ arithmetic by [songe_distill_governance_audit.py](./songe_distill_governance_audit.py):

| ID | Severity | Subsystem | Verbatim `file:line` Anchors | Finding & Exact Pure-$\mathbb{Q}$ Proof |
|---|---|---|---|---|
| **`SNG-01`** | **CRITICAL** | Distillation Objective (`OPSD` Forward KL) | `src/songe/backends/objective.py:38-42`; `src/songe/backends/reference.py:36-38`; `src/songe/config.py:115` (`vocab_clip = 1.0`, unvalidated in `config.py:241-334`) | **Asymmetric Upper-Only Clipping of Signed Forward-KL Terms Causes Anti-Teacher Gradient Reversal at Default `vocab_clip = 1.0` & Violates Gibbs' Inequality for `clip < 1/e`.** Computing $\sum_v \min(p_v \ln(p_v/q_v), \tau)$ caps ONLY positive missed-token terms while leaving negative terms ($q_v > p_v$) untouched. **(a) Default $\tau = 1$ gradient reversal:** For $P=(1/2,1/2)$, $Q=(1/16,15/16)$, $Q'=(1/32,31/32)$, token 0 is already clipped at $1$ ($\frac{1}{2}\ln 8 > 1$), so moving **further from $P$** strictly lowers Songe's loss ($L(Q') < L(Q)$ proven via exact Mercator enclosures!). Exact saturated softmax gradient at $Q=(1/64,63/64)$ is $\partial L/\partial z_0 = +p_1 q_0 = +1/128 > 0$, actively driving $q_0 \to 0$ (away from the hindsight teacher!). **(b) Global Gibbs violation ($\tau = 1/4$):** $L_{\text{clip}=1/4}(P \| (1/32, 31/32)) < 0 = L(P \| P)$. **(c) Exact Bregman repair:** Clipping the non-negative Bregman integrand $d_v = p_v \ln(p_v/q_v) - p_v + q_v \ge 0$ preserves Gibbs' inequality globally for all $\tau > 0$ AND flips the saturated gradient to $\partial L_{\text{Breg}}/\partial z_0 = -(q_1 - p_1) q_0 = -31/4096 < 0$, pulling $q_0$ back toward $p_0$. |
| **`SNG-02`** | **HIGH** | Statistical Acceptance Gate (`Dreams`) | `src/songe/sleep/gate.py:51-86, 125-160`; `src/songe/practice/pool.py:83-96`; `src/songe/sleep/worker.py:97-99, 630-631` | **Single-Moment Bootstrap Degeneracy (`n = 1` Accepts at `p = 50%`!), Broken Conversation Clustering, & Uncorrected Multi-Scale FWER.** Under default `learning = "dreams"`, `test_minimum` drops to `1` (`pool.py:87`) and `gate.decide()` (`gate.py:64`) abandons conversation clustering and `min_heldout` whenever `judged` is non-empty. For ANY $k \ge 1$ unanimous wins `[+1]*k`, every bootstrap draw equals `1` (zero variance, `margin = ulp(1.0)`), so `gate.decide()` accepts on **$k=1$ single win (`p = 1/2`)**! Across `K = 2` candidate scales in `choose_scale` (`wake_scales = (1.0, 0.5)`, `gate.py:142`) with no multiplicity correction, exact null FWER at $k=1$ is **`3/4 = 75%`**. Closed by `hardened_clustered_ville_gate` (independent conversation clustering + exact two-sided Bonferroni Ville supermartingale $M_n(s) \ge 2K/\alpha$: requires $n \ge 9$ independent conversation wins at $K=2, \alpha=1/20$, $M_9(9) = 1023/10 \ge 80 > 511/9 = M_8(8)$). |
| **`SNG-03`** | **HIGH** | Fused Serving Verification | `DESIGN.md:82, 86`; `src/songe/sleep/worker.py:1040-1076` (specifically `L1072-1075`) | **Fused Quantized Serving Artifact Never Re-Judged on Candidate Outputs (Violates `DESIGN.md:82`).** After fusing a BF16 LoRA adapter into a 4-bit quantized serving model (`mlx-fused` / `gguf-full`), `worker.py:1073-1075` copies the **pre-fusion adapter's judged win/loss labels verbatim** onto the fused evaluation rows without generating or judging any output from the fused model. Because `gate.decide()` gates on `judged` outcomes under Dreams, 4-bit fusion degradation of learned tool behavior silently passes using stale pre-fusion `win` labels! |
| **`SNG-04`** | **HIGH** | Trace-to-Prompt & Distillation Injection | `src/songe/reading/rules.py:155-198`; `src/songe/quick.py:86-93, 123, 168-171, 225-227`; `src/songe/proxy.py:92-105, 464-471`; `src/songe/sleep/prompts.py:132-139` | **1-Shot Persistent System-Prompt Poisoning (`Quick Dream`) + Hindsight `<observations>` Tag Breakout (`Deep Dream`).** *(a)* Any user message containing a sentence matching `RULE_START` + `LASTING` (e.g., pasted untrusted issue text or echoed prompt injection) is captured verbatim by `rule_sentence()` (`rules.py:181`), bypasses `min_sessions` (`quick.py:123`) and `consolidate()` (`quick.py:168`), and is injected into the `system` message of every future coding-agent session (`proxy.py:471`); additionally `quick.review()` (`quick.py:226`) fails OPEN on unusable model answers. *(b)* `sleep/prompts.py:134-136` wraps raw decoded tool outputs in `<observations>...</observations>` with zero escaping of `</observations>`, enabling direct delimiter breakout into the frozen hindsight teacher during LoRA distillation. |
| **`SNG-05`** | **HIGH** | Local Control API & Auth Boundary | `src/songe/api.py:544-563, 593, 659-693, 824-898`; `src/songe/proxy.py:620-646` | **Unauthenticated Destructive Control API (`forget`, `undo`, `dream`, `PATCH /api/settings`) + Open `installation_id` Disclosure.** `api.py:663` checks `x-songe-installation` ONLY if sent (`if identity is not None`), enforcing presence solely on `shutdown` (`api.py:689-693`) — leaving `forget`, `undo`, `dream`, `model`, `cancel`, `remove_lesson`, and `PATCH /api/settings` callable with **zero auth header**. Moreover `GET /api/state?service=1` (`api.py:593`) discloses `installation_id` openly on loopback without a Bearer capability (enabling any prompt-injected local agent shell tool to wipe/poison Songe), and `/` / `/next` (`proxy.py:643-644`) skip `guard(request)`. |
| **`SNG-06`** | **MEDIUM** | Weight Provenance & Cache Pinning | `src/songe/schedule.py:239-250`; `src/songe/sleep/evaluate.py:187-190, 210-212` | **Stat-Only `base_fingerprint` (Empty for Single-File GGUF, Ignores Tokenizer & Weight Bytes).** `schedule.py:244-249` hashes only `(name, st_size, st_mtime_ns)` for `config.json` and `*.safetensors` inside `if path.is_dir():`. Single-file `.gguf` models yield `files = []` (identical fingerprint for ANY two GGUF models at the same path!), tokenizer/template files are excluded, and in-place weight edits preserving size/mtime evade detection. `ReferenceCache` (`evaluate.py:189`) truncates `fingerprint[:24]` (96 bits) without `O_NOFOLLOW`. |
| **`SNG-07`** | **MEDIUM** | Data Pipeline Privacy / Secret Hygiene | `src/songe/log.py:1, 422-451`; `src/songe/proxy.py:589-598`; `DESIGN.md:140` | **Zero Body-Level Secret Redaction in SQLite Experience Store.** While HTTP headers are omitted, `Store.record()` (`log.py:444-445`) persists raw `json.dumps(request)` and `json.dumps(response)` with zero redaction of `.env` dumps, `Bearer` tokens, `ghp_`/`sk-`/`AKIA` keys, or private keys — persisting secrets in plaintext SQLite and exposing them to hindsight prompts and LoRA distillation. |
| **`SNG-08`** | **MEDIUM** | Judge Parsing, Supply Chain, & Determinism | `src/songe/quick.py:755-770`; `src/songe/backends/install.py:171-177`; `src/songe/upgrade.py:252-259`; `src/songe/backends/mlx.py:287`; `src/songe/sleep/evaluate.py:308` | **Regex Judge Fallback Hazard, Unpinned `pip install` Provisioning, & Stochastic Health-Eval Mismatch.** *(a)* `quick.py:767` falls back to `r"\b(A|B|both|neither)\b"`, where ordinary English `"A ..."` falsely parses as verdict `"A"`. *(b)* `backends/install.py:172-176` & `upgrade.py:253` run unpinned `pip install` without `--require-hashes`. *(c)* `evaluate.py:308` samples health checks stochastically at `temp=0.8, top_p=0.95` (`mlx.py:287`, which also keeps `top_p=0.95` alongside `temp=0.0` in deterministic mode — `scry#4` truncation hazard). |

---

## 4. Three-Way Cross-Pollination Matrix (`N1` Synthesis)

1. **`sous-labs/songe` $\leftrightarrow$ `Moissanite-Labs/warp-drive` (`#12`/`#13`/`#15`):**
   - Transfers Songe's safe non-executing AST practice validator (`practice/checks.py`) and dual-order blind judging (`judged.py`) while closing `SNG-03` (mandatory post-fusion re-judging of exact served artifact), `SNG-04` (explicit approval for system-prompt rule promotion + `<observations>` fence escaping), `SNG-05` (Bearer capability auth on all loopback control routes), `SNG-06` (full content SHA-256 `CheckpointFingerprint` covering GGUF + tokenizer), `SNG-07` (body-level secret redaction before persistence), and `SNG-08c` (`temp=0, top_p=1` deterministic evaluation).
2. **`sous-labs/songe` $\leftrightarrow$ `magnitudedev/magnitude` (`AUDIT-068R`) + `Moissanite-Labs/hillclimb#4`:**
   - Replaces Songe's degenerate single-moment bootstrap (`gate.py:53-86`, `p_null = 50%` / `75%` FWER across 2 scales) with `hardened_clustered_ville_gate`: independent conversation clustering + exact pure-$\mathbb{Q}$ two-sided Bonferroni Ville supermartingale $M_n(s) \ge 2K/\alpha$ + post-fusion ratification.
   - Replaces Songe's gradient-reversing asymmetric clipped KL (`objective.py:39-42`) with Bregman-normalized clipped KL (`bregman_clipped_kl_interval`), preserving strict properness and monotone teacher-tracking gradients across all $\tau > 0$.

---

## 5. Reproducible Clean-Room Verification Commands

```bash
# 1. Generate canonical zero-float certificate (read-only against sibling checkout)
python3 -I -B songe_distill_governance_audit.py --write-cert songe_governance_certificate.json --json

# 2. 4/4 isolated -I R4 bit-identical check (live-anchored & standalone)
for flags in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $flags songe_distill_governance_audit.py --json | sha256sum
  python3 $flags songe_distill_governance_audit.py --standalone --json | sha256sum
done

# 3. Adversarial R5 unit test suite
python3 -I -B -W error test_songe_governance_r5.py -v

# 4. Aletheia v1.4.0 mutation kill (target: 100.0% KILLED) & strict-ancestors audit-check
PYTHONPATH=../../../publish/aletheia python3 -B -W error -m aletheia mutate songe_distill_governance_audit.py \
  --test-cmd "python3 -I -B test_songe_governance_r5.py" --add-cwd
PYTHONPATH=../../../publish/aletheia python3 -B -W error -m aletheia audit-check . \
  --strict-ancestors --scripts songe_distill_governance_audit.py test_songe_governance_r5.py
```

### Explicit Falsification Criteria (For Independent `@verifier` Red-Teaming)
This audit is falsified if any of the following holds:
1. Any of the 21 verbatim `file:line` anchors fails to match `sous-labs/songe @ 5b7b13768e1ac67e7e3284043ec51f24394a740f`.
2. Independent exact symbolic evaluation (e.g. SymPy) contradicts: (a) `songe_clipped_kl(P, (1/32, 31/32), clip=1) < songe_clipped_kl(P, (1/16, 15/16), clip=1)` for $P=(1/2, 1/2)$, (b) `songe_clipped_kl(P, (1/32, 31/32), clip=1/4) < 0`, (c) `bregman_clipped_kl(P, (1/128, 127/128), clip=1) > bregman_clipped_kl(P, (1/64, 63/64), clip=1) > 0`, or (d) exact saturated gradients `+1/128` vs `-31/4096`.
3. Running Songe's unmodified `gate.decide()` on 1 unanimous judged win fails to accept, or `hardened_clustered_ville_gate` accepts `< 9` independent wins at `K = 2, alpha = 1/20`.
4. Any float primitive appears anywhere in `songe_governance_certificate.json`, or any of the 4 isolated `-I` R4 runs diverges in SHA-256.
5. Any mutant of `songe_distill_governance_audit.py` under `aletheia v1.4.0 mutate --add-cwd` survives (`survived > 0`), `aletheia v1.4.0 audit-check --strict-ancestors` fails, or `git status --porcelain` inside `repos/songe` is non-empty.
