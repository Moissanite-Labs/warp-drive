# Law-1 / Law-2b Portal Extraction of `Moissanite-Labs/siliconcordat#5` (+ `#15`/`#16`/`#18`) & Pure-$\mathbb{Q}$ Two-Zone Airlock Contracts (`AUDIT-104R4`)

> **Status:** Independently `VERIFIED` across 3 model families (`GLM 5.3` + `Claude Code` + `verifier`; `AUDIT-104R4`, `honest_novelty_tier: N0` over known-art primitives with `N1` pure-$\mathbb{Q}$ certifier/audit hardening; human review required before merge).  
> **Discipline:** 100% pure Python 3 stdlib (`int` / `fractions.Fraction`), zero IEEE-754 floats (enforced recursively by `reject_floats`), zero bare `assert`s, zero external writes, LF-only.

## 1. File Inventory (Byte-Identical Frozen Artifacts)

| File | SHA-256 | Role |
|---|---|---|
| [`siliconcordat_d5_oracle.py`](siliconcordat_d5_oracle.py) | `6a2c00e19fe6762dcc36aadd825d8928d72d1d41b5563fef4ac8ba1a4671dd64` | Portal defect scanner, Reply 9.1 exact rational blowup refutation, 3 Two-Zone Law-2b pure-$\mathbb{Q}$ invariants (A/B/C), fail-closed semantic certifier |
| [`siliconcordat_d5_audit.py`](siliconcordat_d5_audit.py) | `7c9bec337d0dc62d5a73a9d2f5a82812ef23182fe3f2b34501967664f69b0c48` | Dual-mode CLI (`--standalone` 100% offline fixture replay vs. `--live` pinned portal recount with strict-type gate & provenance checks) |
| [`test_siliconcordat_d5_r5.py`](test_siliconcordat_d5_r5.py) | `428b0e75d053e18c9130dd47b9d201bc49c038fe9815246bda00d222a33a4487` | Hand-computed known-answer mini-portal live-path + `100.0%` R5 (`197/197`) & full-AST `BoolOp` (`197/197`) kill suite (`10` test methods) |
| [`siliconcordat_d5_certificate.json`](siliconcordat_d5_certificate.json) | `9718f9c7208b439b7e2d96c4234ce921c9a46495ec3e5f08c34351297e50d59f` | Pinned `--live` canonical certificate recounting `siliconcordat#5` (`32` entries, `16` defects; inner `payload_sha256: f1c33328...`, inner `certificate_sha256: 78e6bbcc...`) |
| [`SILICONCORDAT_D5_PORTAL_REPORT.md`](SILICONCORDAT_D5_PORTAL_REPORT.md) | `3f99bbc7135016ba1f4dc70b07802571d27aa3d17f306e4c89cb6afa108580c9` | Complete Law-1/Law-2b extraction matrix, Reply 9.1 refutation, Invariants A/B/C, and `AUDIT-104R4` verification receipts |

## 2. Highlights & Honest Scope Boundaries

1. **Primary-Source Extraction & Pseudocode Falsification (`siliconcordat#5` filtered via `#15`/`#16`/`#18`):**
   - Recounted `16` concrete defects across `32` entries (`3,891` markdown lines): `4` `symp_matrix` scalar overwrites, `2` uninitialized `mov cr3, rax` inline-asm triple faults, `2` fake FPGA magic writes, `7` `hash(sum)` collision bugs, and `1` exact rational blowup in Reply 9.1 (`adaptive_decay_pressure` multiplier $= -98001/2000 = -49.0005 < 0$ at calm equilibrium $T = 0$, fixed via bounded decay in `[19/20, 1/1]`).
2. **Three Executable Pure-$\mathbb{Q}$ Law-2b Invariants:**
   - **Invariant A (Zone A Feasibility-First Anti-Homogenization Gate):** Filters strictly to feasible candidates before computing exact pairwise spread $D_{\text{cohort}}^2$, distinct vector count $U$, and Rényi-2 diversity $D_2$ (`epistemic_tag: "UNVERIFIED_HYPOTHESIS"` — Zone A deliberation can never self-promote to `VERIFIED`).
   - **Invariant B (Resource-Bounded Monotone Ratchet + Edge-Snap & `#16` Calibration Gap Proof):** Proves norm-only gating falsely rejects a unit permutation (`drift_sq = 44/1`, behavioral $R^2 = 1/1$) while falsely accepting a readout sign flip (`drift_sq = 8/1`, behavioral $R^2 = -19/5 = -3.8000$), enforcing spend-locked non-refundable budget + monotone behavioral floor (`5`-step witness trace, `2` commits, `3` fail-closed Edge-Snaps).
   - **Invariant C (Airlock `M03`/`M05` -> Zone B Blinded Splicer `LOCK` Validator):** Enforces exact `splice.json` (`0.1.0`) key schemas, canonical reduced `_parse_frac_str`, all `4` `#18` §5 hard invariants (Zero Lockfile Mutation, normalized whitespace-around-dot & `importlib` One-Way Visibility, Immutable Core SHA-256 parity, Clean Ejection), bounded syntactic `_UNSAFE_CMD_RE` denylist (note: syntactic denylist, not an OS sandbox), and Blinded Airlock Non-Interference (`AIRLOCK_ZONE_A_LEAKAGE_BREACH`).

## 3. Exact Offline Reproduction (3-Mode Isolated `-I` R4 Parity)

From this directory (Python 3 standard library only, zero external packages, zero network calls):

```bash
# 1. Offline standalone verification (3-mode bit-identical 7ad6c996..., matching live payload_sha256 f1c33328...):
python3 -I -B siliconcordat_d5_audit.py --standalone --json | sha256sum
python3 -I -O -B siliconcordat_d5_audit.py --standalone --json | sha256sum
python3 -I -B -W error siliconcordat_d5_audit.py --standalone --json | sha256sum

# 2. Assertion-free R5 known-answer, boundary & mutation-killing suite (10/10 OK):
python3 -I -O -B -W error test_siliconcordat_d5_r5.py
```

**Offline vs. Live Certificate Provenance:** `--standalone --json` and `test_siliconcordat_d5_r5.py` run 100% offline from any fresh clone with identical `payload_sha256` (`f1c33328c822d864a000c2a269b5bb080852d11e8dd65906d25467818868d402`). [`siliconcordat_d5_certificate.json`](siliconcordat_d5_certificate.json) (`9718f9c7...`, inner `certificate_sha256: 78e6bbcc...`) is the pinned `--live` certificate generated against read-only captures of `siliconcordat#5` (`discussion_5_raw.json` `e5c2b543...`, `discussion_5_full.md` `7cd8d8b7...`).

**External Verification Receipts:** `10/10` R5 tests OK (`-I -O -B -W error`); `aletheia v2.0.0 mutate --max-mutants 0`: **`197/197`** (`177` oracle + `20` audit, `100.0%`) KILLED (`0` survivors, `truncated=False`); full-AST `BoolOp` sweep **`197/197` (`100.0%`)** KILLED (`0` survivors); `aletheia v2.0.0 audit-check --strict-ancestors --safety-scan PASS` (`0` defects, `0` leaks, `0` safety findings); 3-family independently `VERIFIED` (`GLM 5.3` + `Claude Code` + `verifier`).
