# Expedition Trust-Boundary & Cross-Org Verifier Study (`AUDIT-062R` + `AUDIT-065`)

Standalone, zero-dependency, **non-importing** dual-checker verification suite for `Moissanite-Labs/warp-drive` (addressing Issues `#3` and `#7`). Neither verifier imports `warp_modeld`, `weft`, `exo`, or any third-party package; both run purely on Python 3 stdlib across all 4 isolated interpreter modes (`-I -B`, `-I -O -B`, `-I -B -W error`, `-I -O -B -W error`) with bit-identical canonical JSON output.

- **Honest Novelty Classification:** `N1` (clean-room non-importing dual-checker validators, live-reproduced runtime/sandbox/cross-org findings, and hardened gates; zero inflated `N2` claim).
- **Law-4 `N0` Prior-Art Quarantine:** Existing `siliconcordat/{warp, weft, mde, exo}` and `Moissanite-Labs/warp-drive` 4-stage verifier contracts, Linux `Landlock` / `seccomp-bpf` / `bubblewrap` / `systemd` / `mkosi` / `btrfs` / UKI mechanisms, and RFC 2104 HMAC-SHA256 hash-chained ledgers are explicitly credited as prior art (`N0`) and never claimed new.

## Contents

| File | Audit | Role |
|---|---|---|
| [`warp_drive_runtime_audit.py`](./warp_drive_runtime_audit.py) | `AUDIT-062R` | Non-importing runtime, sandbox, verifier, canary, ledger, RPC, and fingerprint trust-boundary gate suite (`21` hardened gates; `0` floats in JSON certs) |
| [`test_warp_drive_runtime_r5.py`](./test_warp_drive_runtime_r5.py) | `AUDIT-062R` | R5 adversarial test suite (`34/34` `100.0%` mutants killed + `28/28` red-team bypasses blocked) |
| [`warp_drive_runtime_certificate.json`](./warp_drive_runtime_certificate.json) | `AUDIT-062R` | Sealed pre-hardening baseline receipt anchored to `Moissanite-Labs/warp-drive@e3899d3e` |
| [`WARP_DRIVE_RUNTIME_SANDBOX_REPORT.md`](./WARP_DRIVE_RUNTIME_SANDBOX_REPORT.md) | `AUDIT-062R` | Full adversarial runtime & sandbox audit report (`WD-SANDBOX-01` .. `WD-FP-01`) |
| [`weft_cross_audit_gate.py`](./weft_cross_audit_gate.py) | `AUDIT-065` | Zero-float cross-org contract unifier (`siliconcordat/{warp,weft,mde,exo}` & `Moissanite-Labs/{warp-drive,weft,weft-loom,scry,tokenpage}`; closes `WD-X01`..`WD-X08`) |
| [`test_weft_cross_audit_r5.py`](./test_weft_cross_audit_r5.py) | `AUDIT-065` | R5 mutation-killing suite (`88/88` `100.0%` mutants killed, `12/12` R3 negative controls) |
| [`weft_cross_audit_certificate.json`](./weft_cross_audit_certificate.json) | `AUDIT-065` | Sealed pre-hardening 10-checkout ecosystem receipt anchored to `e3899d3e` |
| [`WEFT_CROSS_AUDIT_REPORT.md`](./WEFT_CROSS_AUDIT_REPORT.md) | `AUDIT-065` | Full cross-org drift & blueprint hardening report (`WD-X01`..`WD-X08`) |

## Quickstart (100% Standalone, Zero External Dependencies)

Run from `studies/expedition-trust-boundary-verifier/`:

```bash
# 1. Verify bit-identical 4-mode isolated R4 determinism on both standalone verifiers
for flags in "-I -B" "-I -O -B" "-I -B -W error" "-I -O -B -W error"; do
  python3 $flags warp_drive_runtime_audit.py --standalone --json | sha256sum
  python3 $flags weft_cross_audit_gate.py --standalone --json | sha256sum
done

# 2. Run both standalone R5 adversarial test suites
python3 -I -B -W error test_warp_drive_runtime_r5.py
python3 -I -B -W error test_weft_cross_audit_r5.py
```

To run the full upstream `warp-modeld` unit and hardening regression suite from the repository root:

```bash
PYTHONPATH=src python3 -B -W error -m unittest discover -s tests -v
```
