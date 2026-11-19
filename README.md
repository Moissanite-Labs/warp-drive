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

- **Verified model gatekeeper (`warp-modeld`):** A local service sitting between L4 `exo` and L2 `llama-server`. It checks model fingerprints, lineage hashes, runtime flags, exact integer math certificates, and system-owned canary tests before activating any adapter.
- **Instant safe rollback:** Base weights stay on read-only storage. A kill switch sets adapter scales to zero, flushes slot key-value (KV) caches and hybrid recurrent states, and writes a signed receipt to an append-only ledger.
- **Mandatory tool sandboxes:** Agent tools run inside unprivileged Linux namespaces (`bubblewrap`), filesystem restrictions (`Landlock`), and system-call filters (`seccomp`). Protected test files and ledger sockets stay unreadable or read-only to tools.
- **Recoverable Linux images (`mkosi` + `btrfs` + UKI):** Declarative image configs produce Arch Linux images with read-only `btrfs` root snapshots and archived Unified Kernel Images (UKI) for single-reboot recovery.

## Three-Machine Deployment Model

`warp` separates human control from experimental Linux compute so a failing driver or model test cannot break a primary workstation:

1. **Clean macOS Base Hub (64 GiB unified memory):** Runs stock macOS with zero OS changes. Holds human keys, source policies, and approval prompts. Can run read-only user-space `llama-server` on demand for 27B model checks.
2. **RTX 3080 Compute Host (8 GiB VRAM, 32 GiB RAM):** Runs a reversible dual-boot `warp` Linux image alongside Windows 11. Serves 4B to 8B open-weight models with multiple adapters and compiles adapters on CPU.
3. **Omarchy Linux Client (lightweight x64 laptop):** Runs the desktop shell, L4 `exo`, L5 `mde`, and local sandboxes on a dedicated test laptop (or inside a VM on shared hardware), sending large model requests over a private link to the compute host.

## Project Status

- **Current stage:** Foundation documentation and architecture (`ARCHITECTURE.md`, `PLAN.md`).
- **Next stage:** `warp-modeld` daemon implementation, adversarial test suite, and `mkosi` / `systemd` / sandbox blueprints.
- **Verification boundary:** Bare-metal `mkosi` flashing and hardware GPU runs require dedicated Linux target hardware and are tracked separately from local unit and mock-server tests.

## Documents

- [ARCHITECTURE.md](ARCHITECTURE.md) explains the zero-trust inference boundary, the four verification stages, the three-machine layout, and recovery rules.
- [PLAN.md](PLAN.md) lists milestones, acceptance gates, and non-goals.

## License

Code in this repository is licensed under the Apache License 2.0 ([LICENSE](LICENSE)).
Documentation is licensed under Creative Commons Attribution 4.0 International (CC BY 4.0).
