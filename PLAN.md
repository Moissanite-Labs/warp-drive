# Warp Initial Plan

`warp` delivers the Layer 3 operating system foundation for the Siliconcordat stack in five milestones.
Each milestone has a falsifiable check and an explicit boundary between what is verified locally on macOS or mock hosts versus what requires Linux bare-metal hardware.

## Milestone 0: Foundation and Architecture

- Initialize `siliconcordat/warp` with Apache-2.0 code license, CC BY 4.0 documentation license, `README.md`, `ARCHITECTURE.md`, and `PLAN.md`.
- Publish the full initial plan as an issue on `siliconcordat/warp` so downstream layers (`mde`, `exo`, `weft`, `loom`) can verify interface assumptions.
- Gate: Every markdown file and issue body passes the prose and duplicate-reference checks cleanly with zero private or local host paths.

## Milestone 1: `warp-modeld` Core Daemon and Adversarial Tests

Build `warp-modeld` as a zero-dependency Python 3 standard-library package (`src/warp_modeld/`) with an automated test suite (`tests/`):

1. **Stage 1 (`fingerprint.py`):** Verify the 4-layer checkpoint fingerprint (`layout_sha256`, tensor/GGUF digest, config/tokenizer/template digest, Plane 1 `source.lineage` with zero contested heads) plus the 5th runtime-flag digest (`llama-server` commit, quant, context size, KV quant, checkpoint flags). Fail closed before any GPU or HTTP call.
2. **Stage 2 (`certificate.py`):** Implement division-free exact integer `FixedRadixCertificate` verification (`<1ms` on CPU) for single adapters and composed multi-adapter stacks. Reject forged bounds, overflow inputs, non-integers, and joint-bound breaches.
3. **Stage 3 (`canary.py`, `llama_client.py`):** Orchestrate shadow-loaded adapters against `llama-server` (`--lora-init-without-apply`, `POST /lora-adapters`, per-request `"lora"` array). Load canaries exclusively from OS-owned read-only files and reject any adapter-supplied canary payload.
4. **Stage 4 (`ledger.py`, `verifier.py`, `server.py`):** Implement constant-time kill switch, explicit KV and hybrid attention/SSM recurrent-state slot erase (`GET /slots`, `POST /slots/{id}?action=erase`), fail-closed handling if a flush fails, and append-only hash-chained signed JSONL receipts (`mount`, `reject`, `rollback`) exposed over a local Unix socket.
5. **Adversarial verification (`tests/`):** Run a realistic local HTTP mock of `llama-server` that tracks per-slot KV and hybrid DeltaNet recurrent state, proving rejection of forged certificates, stale lineage, runtime-flag drift, forged adapter-supplied canaries, canary failures, ledger tampering, and stale recurrent-state leakage on rollback.

## Milestone 2: Reproducible OS, Systemd, Sandbox, and Recovery Blueprints

Ship declarative configuration blueprints under `blueprints/` with automated static and syntax tests:

- `blueprints/mkosi/`: Base Arch Linux `btrfs` + UKI configuration and three target profiles (`vmtest`, `compute-rtx3080`, `client-omarchy`).
- `blueprints/systemd/`: Hardened service units for `warp-llama-server.service` (localhost-only, `--lora-init-without-apply`, read-only weights), `warp-modeld.service` (Unix socket control, read-only verifier canaries, append-only ledger directory), and `warp-recovery-checkpoint.service`.
- `blueprints/sandbox/`: Declarative `Landlock` filesystem policy, default-deny `seccomp` profile, and fail-closed `bubblewrap` tool executor wrapper (`WARP_TOOL_EXECUTOR_REQUIRED=1`, empty network namespace, scrubbed environment).
- `blueprints/recovery/`: `btrfs` read-only snapshot and archived UKI checkpoint/rollback script preserving persistent subvolumes.
- Gate: All JSON policies parse against strict invariants, shell scripts pass `bash -n`, and unit configs enforce read-only oracle paths, fail-closed executor flags, and `--lora-init-without-apply`.

## Milestone 3: Live `llama-server` and QEMU Acceptance

- Exercise `warp-modeld` against a real local `llama-server` binary (read-only user-space test with a small GGUF checkpoint) to verify HTTP payload shapes, `--lora-init-without-apply` startup, and slot erasure behavior end to end.
- Build the `mkosi` `vmtest` profile on Linux and verify boot, `bubblewrap`/`Landlock`/`seccomp` containment, read-only model mounts, and a two-reboot `btrfs` + UKI rollback cycle inside QEMU/KVM before touching bare-metal disks.

## Milestone 4: Three-Machine Hardware Bring-Up

- **RTX 3080 Compute Host (8 GiB VRAM, 32 GiB RAM):** Shrink the Windows 11 NVMe partition non-destructively, install the `compute-rtx3080` `warp` dual-boot profile with CUDA and `llama-server`, and verify 4B to 8B multi-adapter serving (`corpus`, `weft-eido`, `formal-verification`) inside the 8 GiB VRAM ceiling.
- **Omarchy Linux Client:** Flash `client-omarchy` onto a dedicated spare laptop (never overwriting a live production workstation) and verify remote authenticated inference calls to the compute host while keeping tool sandboxes and exact-byte approvals local.
- **Clean macOS Hub:** Keep stock macOS untouched as the human authority seat, receiving only signed evidence bundles and ledger heads from Linux nodes.

## Non-Goals

- Modifying macOS system files, installing experimental macOS kernel extensions, or running untrusted agent sandboxes on the Mac hub.
- Running 27B checkpoints inside 8 GiB VRAM on the laptop compute host (27B validation runs only as on-demand read-only user-space `llama-server` on the 64 GiB Mac hub).
- Weakening fail-closed sandbox, canary, or rollback rules for convenience.
