# Expedition Study: *REINFORCE Zero* (`NVIDIA / Inferact`) & `zero-mismatch-rl` TII Governance Bridge (`AUDIT-081R`)

- **Audit Status:** `AUDIT-081R` **`VERIFIED`** (`exact+anchor`, **`N1`**, `0` unresolved defects, `26/26` `100.0%` R5 mutation kill, `0` floats in JSON certificate, `0` external writes)
- **Read-Only External Targets Audited:**
  - `hijkzzz/REINFORCE-Zero` @ `a22153de4b8c4b47faf5bf88a598d6d54801bfc7` (`REINFORCE-Zero.pdf` SHA-256 `5abb9fe2a84d522abed5c51fc39d95de57c0d7830c69dae540023ad46adf2a64`)
  - `Inferact/zero-mismatch-rl` @ `136aca87d8158adae94b5a272fa4a8a6d5cd6939`
- **Cross-Pollination Targets:** `Moissanite-Labs/warp-drive#15` (Stage-1 `RuntimeFlags` & derived-scale cache invalidation), `magnitudedev/magnitude` (`AUDIT-068R`), `loom-fun/unsloth-Inkling-2-Mini-loom` (`AUDIT-074R`), `sous-labs/songe` (`AUDIT-073R`), and `Foundation-0/aletheia v1.4.0` / LangChain Knowledge Factory (`AUDIT-076R`).
- **Scope & Isolation:** Zero-dependency standalone study (pure Python 3 stdlib, zero floats); makes zero modifications to `src/warp_modeld/`, `blueprints/`, `tests/`, `.github/`, or existing studies.

## Files

- [reinforce_zero_tii_audit.py](./reinforce_zero_tii_audit.py) — Exact pure-$\mathbb{Q}$ (`int`/`Fraction`) Taylor-interval verifier for NVIDIA's Appendix B Gaussian TIM instability theorem + persistent one-sided bias & variance/scale mismatch extensions + discrete-token Score Centering vs. unclipped IS & support-truncation counter-theorems + fail-closed TII execution-closure & coding-agent skill governance gate (`--standalone` mode requires no external clones).
- [test_reinforce_zero_tii_r5.py](./test_reinforce_zero_tii_r5.py) — Assertion-free adversarial R5 & regression test suite (`8/8` tests, `26/26` `100.0%` R5 mutation kill).
- [reinforce_zero_tii_certificate.json](./reinforce_zero_tii_certificate.json) — Sealed canonical zero-float certificate generated against the pinned read-only `REINFORCE-Zero` and `zero-mismatch-rl` checkouts (`26/26` verbatim `file:line` anchors + commit/PDF/text SHA-256s verified).
- [REINFORCE_ZERO_TII_AUDIT_REPORT.md](./REINFORCE_ZERO_TII_AUDIT_REPORT.md) — Full Law-2 Steelman, Law-4 `N0`/`N1` quarantine, `RZ-01..RZ-07` findings matrix, and falsification criteria.

## Standalone Quickstart (Zero External Clones Required)

Run from `studies/expedition-reinforce-zero-tii/`:

```bash
# 1. Run standalone pure-Q oracle (deterministic, zero floats)
python3 -I -B reinforce_zero_tii_audit.py --standalone

# 2. Verify 4-mode isolated -I R4 bit-identical standalone JSON output
for flags in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $flags reinforce_zero_tii_audit.py --standalone --json | sha256sum
done

# 3. Run adversarial R5 unit test suite under strict isolated flags
python3 -I -B -W error test_reinforce_zero_tii_r5.py -v
```

*(Note: Running `reinforce_zero_tii_audit.py` without `--standalone` auto-detects a local read-only staging checkout if present and otherwise falls back cleanly to `standalone_no_repo` mode; pass `--staging-dir <path>` to re-verify all `26/26` live repository anchors.)*
