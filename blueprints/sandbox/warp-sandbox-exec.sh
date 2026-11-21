#!/usr/bin/env bash
set -euo pipefail

# Mandatory fail-closed bubblewrap tool executor for siliconcordat/warp.
# Enforces empty network namespace (Zone A default), read-only verifier/model mounts,
# and zero access to warp-modeld control sockets or signing keys.

if [[ "${WARP_TOOL_EXECUTOR_REQUIRED:-1}" != "1" ]]; then
    echo "ERR_SANDBOX_POLICY: WARP_TOOL_EXECUTOR_REQUIRED must remain 1" >&2
    exit 126
fi

if [[ $# -lt 2 ]]; then
    echo "Usage: $0 <ephemeral-worktree-dir> <command> [args...]" >&2
    exit 2
fi

WORKTREE="$1"
shift

if ! WORKTREE_REAL="$(realpath -e -- "${WORKTREE}" 2>/dev/null)" || [[ ! -d "${WORKTREE_REAL}" ]]; then
    echo "ERR_SANDBOX_WORKTREE: worktree directory does not exist: ${WORKTREE}" >&2
    exit 126
fi

if [[ "${WORKTREE_REAL}" == "/" ]]; then
    echo "ERR_SANDBOX_WORKTREE: refusing root directory as worktree" >&2
    exit 126
fi

for denied in \
    /run/warp-modeld \
    /var/lib/warp-ledger \
    /etc/warp/keys \
    /etc/warp \
    /var/lib/warp/models \
    /var/lib/warp/snapshots \
    /boot \
    /efi; do
    if [[ "${WORKTREE_REAL}" == "${denied}" || "${WORKTREE_REAL}" == "${denied}/"* || "${denied}" == "${WORKTREE_REAL}/"* ]]; then
        echo "ERR_SANDBOX_WORKTREE: worktree overlaps protected host path (${denied}): ${WORKTREE_REAL}" >&2
        exit 126
    fi
done

# Pin trusted system bubblewrap path instead of honoring untrusted PATH lookup.
BWRAP_BIN=""
for candidate in /usr/bin/bwrap /bin/bwrap; do
    if [[ -x "${candidate}" ]]; then
        resolved_bwrap="$(realpath -e -- "${candidate}" 2>/dev/null || true)"
        if [[ "${resolved_bwrap}" == "/usr/bin/bwrap" || "${resolved_bwrap}" == "/bin/bwrap" ]]; then
            BWRAP_BIN="${resolved_bwrap}"
            break
        fi
    fi
done
if [[ -z "${BWRAP_BIN}" ]]; then
    echo "ERR_SANDBOX_UNAVAILABLE: trusted bubblewrap (/usr/bin/bwrap) is required; refusing unsandboxed execution" >&2
    exit 126
fi

BWRAP_ARGS=(
    --unshare-all
    --unshare-net
    --die-with-parent
    --new-session
    --clearenv
    --setenv PATH "/usr/local/bin:/usr/bin:/bin"
    --setenv LANG "C.UTF-8"
    --setenv SOURCE_DATE_EPOCH "${SOURCE_DATE_EPOCH:-1700000000}"
    --setenv WARP_SANDBOXED "1"
    --ro-bind /usr /usr
    --ro-bind /bin /bin
    --ro-bind /lib /lib
    --proc /proc
    --dev /dev
    --tmpfs /tmp
    --bind "${WORKTREE_REAL}" /workspace
    --chdir /workspace
)

if [[ -d /lib64 ]]; then
    BWRAP_ARGS+=(--ro-bind /lib64 /lib64)
fi

# Protected verifier suites and base weights stay strictly read-only if present.
if [[ -d /etc/warp/canaries ]]; then
    BWRAP_ARGS+=(--ro-bind /etc/warp/canaries /etc/warp/canaries)
fi
if [[ -d /var/lib/warp/models ]]; then
    BWRAP_ARGS+=(--ro-bind /var/lib/warp/models /var/lib/warp/models)
fi

# Fail closed if a seccomp BPF filter is required or configured but unreadable.
SECCOMP_BPF="${WARP_SECCOMP_BPF_PATH:-}"
if [[ "${WARP_REQUIRE_SECCOMP_BPF:-0}" == "1" && -z "${SECCOMP_BPF}" ]]; then
    echo "ERR_SANDBOX_SECCOMP: WARP_REQUIRE_SECCOMP_BPF=1 requires WARP_SECCOMP_BPF_PATH" >&2
    exit 126
fi
if [[ -n "${SECCOMP_BPF}" ]]; then
    if [[ ! -r "${SECCOMP_BPF}" || ! -f "${SECCOMP_BPF}" ]]; then
        echo "ERR_SANDBOX_SECCOMP: compiled seccomp BPF filter missing or unreadable: ${SECCOMP_BPF}" >&2
        exit 126
    fi
    exec 9<"${SECCOMP_BPF}"
    BWRAP_ARGS+=(--seccomp 9)
fi

exec "${BWRAP_BIN}" "${BWRAP_ARGS[@]}" -- "$@"
