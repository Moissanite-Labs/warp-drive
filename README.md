# warp

`warp` is the Layer 3 operating system layer of the Siliconcordat stack.
It isolates AI agent tools inside Linux sandboxes, verifies local model adapters before they touch GPU memory, and gives Linux hosts single-reboot disk recovery.
It is built for operators running local open-weight models and coding agents who want hard system limits instead of prompt-only rules.

## Position in the Siliconcordat Stack

| Layer | Repository | Role |
| --- | --- | --- |
| L5 Improved MCP | `siliconcordat/mde` | Structured tool protocol and code editing seams |
| L4 Harness | `siliconcordat/exo` | Agent loop, memory log, and human approval gate |
| L3 OS | `siliconcordat/warp` | Sandboxed execution, verified model loading, and OS recovery |
| L2 Model | `siliconcordat/weft` | Open-weight adapters and deterministic adapter compilers |
| L1 Hardware | `siliconcordat/loom` | Hardware architecture research and theory |

## What Warp Provides

- **Verified model gatekeeper (`warp-modeld`):** A zero-dependency Python 3 standard-library service sitting between L4 `exo` and L2 `llama-server`. It checks model fingerprints, lineage hashes, runtime flags, optional L5 `zone-manifest/v0.1` bank-tag pins, exact integer math certificates (including native `siliconcordat/weft` manifest ingestion), and system-owned canary tests before activating any adapter.
- **Instant safe rollback:** Base weights stay on read-only storage. A kill switch sets adapter scales to zero, flushes slot key-value (KV) caches and hybrid attention or state-space recurrent states, and writes a hash-chained signed receipt to an append-only JSONL ledger.
- **Mandatory tool sandboxes:** Declarative `Landlock`, `seccomp`, and `bubblewrap` blueprints confine agent tools inside an empty network namespace with read-only access to verifier canaries and base weights.
- **Recoverable Linux images (`mkosi` + `btrfs` + UKI):** Declarative Arch Linux profiles (`vmtest`, `compute-rtx3080`, `client-omarchy`) pair read-only `btrfs` root snapshots with archived Unified Kernel Images (UKI) for single-reboot recovery.

## Repository Layout

| Path | Contents |
| --- | --- |
| `src/warp_modeld/` | Four-stage fail-closed verifier (`fingerprint.py`, `certificate.py`, `canary.py`, `llama_client.py`, `ledger.py`, `verifier.py`, `server.py`, `cli.py`) |
| `schemas/` | Adapter bundle JSON schema (`adapter-bundle.schema.json`), verifier-owned canary suite (`verifier-canaries.json`), and daemon config template (`modeld-config.example.json`) |
| `blueprints/mkosi/` | Base Arch `btrfs` + UKI config (zero `sudo`), post-install and ancestor mode-hardening scripts, and `vmtest`, `compute-rtx3080`, and `client-omarchy` profiles |
| `blueprints/systemd/` | Hardened service units for `llama-server` (`--lora-init-without-apply`), `warp-modeld`, and pre-upgrade checkpoints |
| `blueprints/sandbox/` | `Landlock` rules, default-deny `seccomp` filter, and fail-closed `bubblewrap` tool executor (`WARP_TOOL_EXECUTOR_REQUIRED=1`) |
| `blueprints/recovery/` | `btrfs` snapshot and archived UKI checkpoint/rollback helper (`warp-recovery.sh`) |
| `tests/` | Unit, end-to-end Unix socket daemon, blueprint validation, and adversarial tests against a local HTTP mock of `llama-server` |

## Running Tests and CLI Checks

Requires Python 3.11 or newer with no external runtime packages:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Verify a signed ledger file, archive and reseed a damaged ledger explicitly, run a division-free certificate check, or probe an installed `llama-server` binary:

```bash
PYTHONPATH=src python3 -m warp_modeld.cli verify-ledger --ledger <ledger.jsonl> --key-file <ledger.key>
PYTHONPATH=src python3 -m warp_modeld.cli repair-ledger --ledger <ledger.jsonl> --archive-dir <archive> --key-file <ledger.key> --confirm <phrase>
PYTHONPATH=src python3 -m warp_modeld.cli check-certificate --cert <cert.json> --bounds <bounds.json>
WARP_LIVE_LLAMA_TEST=1 PYTHONPATH=src python3 -m unittest tests/test_live_llama_smoke.py -v
```

## Three-Machine Deployment Model

`warp` separates human control from experimental Linux compute so a failing driver or model test cannot break a primary workstation:

1. **Clean macOS Base Hub (64 GiB unified memory):** Runs stock macOS with zero OS changes. Holds human keys, source policies, and approval prompts. Can run read-only user-space `llama-server` on demand for 27B model checks.
2. **RTX 3080 Compute Host (8 GiB VRAM, 32 GiB RAM):** Runs a reversible dual-boot `warp` Linux image alongside Windows 11. Serves 4B to 8B open-weight models with multiple adapters and compiles adapters on CPU.
3. **Omarchy Linux Client (lightweight x64 laptop):** Runs the desktop shell, L4 `exo`, L5 `mde`, and local sandboxes on a dedicated test laptop (or inside a VM on shared hardware), sending large model requests over a private link to the compute host.

## Verification Boundary

- **Verified locally now:** All four `warp-modeld` verification stages, Unix socket RPC server and CLI subprocesses, adversarial rejection tests (forged certificates, stale lineage, runtime-flag drift, forged adapter-supplied canaries, canary failures, hybrid recurrent-state flush on rollback, and ledger tampering), plus blueprint JSON invariant and `bash -n` syntax checks.
- **Requires Linux target hardware (not yet executed):** Building and booting `mkosi` disk images in QEMU, flashing dual-boot `compute-rtx3080` or `client-omarchy` laptops, and live CUDA `llama-server` multi-adapter benchmarks.

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md) explains the zero-trust inference boundary, the four verification stages, the three-machine layout, and recovery rules.
- [PLAN.md](PLAN.md) lists milestones, acceptance gates, and non-goals.

## License

Code in this repository is licensed under the Apache License 2.0 ([LICENSE](LICENSE)).
Documentation is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).
