#!/usr/bin/env bash
set -euo pipefail

# Single-reboot btrfs root snapshot + archived UKI recovery helper for siliconcordat/warp.
# Preserves persistent subvolumes (@models, @store, @ledger, @egress, @sysd, @home) untouched.

SNAPSHOT_ROOT="${WARP_SNAPSHOT_ROOT:-/var/lib/warp/snapshots}"
EFI_LINUX_DIR="${WARP_EFI_LINUX_DIR:-/efi/EFI/Linux}"
ACTIVE_UKI="${WARP_ACTIVE_UKI:-${EFI_LINUX_DIR}/warp-current.efi}"
ROOT_SUBVOL="${WARP_ROOT_SUBVOL:-/}"
BTRFS_TOPLEVEL_MOUNT="${WARP_BTRFS_TOPLEVEL_MOUNT:-}"
ACTIVE_ROOT_SUBVOL_NAME="${WARP_ACTIVE_ROOT_SUBVOL_NAME:-@}"

usage() {
    echo "Usage: $0 <checkpoint <label> | list | stage-rollback <checkpoint-id>>" >&2
    exit 2
}

cmd_checkpoint() {
    local label="${1:-}"
    if [[ -z "${label}" || ! "${label}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "ERR_RECOVERY_LABEL: label must match [a-zA-Z0-9._-]+" >&2
        exit 2
    fi

    local stamp
    stamp="$(date -u +%Y%m%dT%H%M%SZ)"
    local ckpt_id="${stamp}-${label}"
    local snap_dir="${SNAPSHOT_ROOT}/${ckpt_id}"
    local archived_uki="${EFI_LINUX_DIR}/warp-rollback-${ckpt_id}.efi"

    if ! command -v btrfs >/dev/null 2>&1; then
        echo "ERR_RECOVERY_TOOL: btrfs-progs is required" >&2
        exit 126
    fi
    if [[ ! -f "${ACTIVE_UKI}" ]]; then
        echo "ERR_RECOVERY_UKI: active UKI missing at ${ACTIVE_UKI}" >&2
        exit 126
    fi

    mkdir -p "${SNAPSHOT_ROOT}"
    btrfs subvolume snapshot -r "${ROOT_SUBVOL}" "${snap_dir}"
    cp --preserve=timestamps "${ACTIVE_UKI}" "${archived_uki}"
    sha256sum "${archived_uki}" > "${SNAPSHOT_ROOT}/${ckpt_id}.uki.sha256"
    printf 'checkpoint_id=%s\nsnapshot_dir=%s\narchived_uki=%s\nactive_root_subvol=%s\n' \
        "${ckpt_id}" "${snap_dir}" "${archived_uki}" "${ACTIVE_ROOT_SUBVOL_NAME}" \
        > "${SNAPSHOT_ROOT}/${ckpt_id}.meta"
    echo "checkpoint_created=${ckpt_id}"
}

cmd_list() {
    if [[ ! -d "${SNAPSHOT_ROOT}" ]]; then
        echo "no checkpoints found"
        return 0
    fi
    find "${SNAPSHOT_ROOT}" -maxdepth 1 -name '*.uki.sha256' -print | sort
}

cmd_stage_rollback() {
    local ckpt_id="${1:-}"
    if [[ -z "${ckpt_id}" || ! "${ckpt_id}" =~ ^[a-zA-Z0-9._-]+$ ]]; then
        echo "ERR_RECOVERY_ID: invalid checkpoint id" >&2
        exit 2
    fi

    local manifest="${SNAPSHOT_ROOT}/${ckpt_id}.uki.sha256"
    local snap_dir="${SNAPSHOT_ROOT}/${ckpt_id}"
    if [[ ! -f "${manifest}" || ! -d "${snap_dir}" ]]; then
        echo "ERR_RECOVERY_MISSING: checkpoint ${ckpt_id} not found" >&2
        exit 1
    fi

    sha256sum -c "${manifest}"
    if ! command -v btrfs >/dev/null 2>&1; then
        echo "ERR_RECOVERY_TOOL: btrfs-progs is required to swap root subvolume" >&2
        exit 126
    fi
    if ! command -v bootctl >/dev/null 2>&1; then
        echo "ERR_RECOVERY_BOOTCTL: systemd bootctl is required to stage one-shot UKI entry" >&2
        exit 126
    fi

    # Fail closed unless the top-level btrfs volume (subvolid=5) is mounted so @ can be
    # swapped to a writable snapshot of ${snap_dir}; otherwise a UKI carrying
    # rootflags=subvol=@ would reboot right back into the un-reverted active root.
    if [[ -z "${BTRFS_TOPLEVEL_MOUNT}" || ! -d "${BTRFS_TOPLEVEL_MOUNT}/${ACTIVE_ROOT_SUBVOL_NAME}" ]]; then
        echo "ERR_RECOVERY_SUBVOL: WARP_BTRFS_TOPLEVEL_MOUNT must point to a mounted btrfs top-level volume containing ${ACTIVE_ROOT_SUBVOL_NAME}" >&2
        exit 126
    fi

    local active_subvol="${BTRFS_TOPLEVEL_MOUNT%/}/${ACTIVE_ROOT_SUBVOL_NAME}"
    local backup_subvol="${BTRFS_TOPLEVEL_MOUNT%/}/${ACTIVE_ROOT_SUBVOL_NAME}.pre-rollback-${ckpt_id}"
    if [[ -e "${backup_subvol}" ]]; then
        echo "ERR_RECOVERY_BACKUP_EXISTS: refusing to overwrite ${backup_subvol}" >&2
        exit 1
    fi

    mv "${active_subvol}" "${backup_subvol}"
    if ! btrfs subvolume snapshot "${snap_dir}" "${active_subvol}"; then
        mv "${backup_subvol}" "${active_subvol}"
        echo "ERR_RECOVERY_SUBVOL_SWAP: failed to materialize rollback snapshot for ${ACTIVE_ROOT_SUBVOL_NAME}" >&2
        exit 1
    fi

    bootctl set-oneshot "warp-rollback-${ckpt_id}.efi"
    echo "rollback_staged=${ckpt_id}"
}

if [[ $# -lt 1 ]]; then
    usage
fi

case "$1" in
    checkpoint)
        shift
        cmd_checkpoint "${1:-}"
        ;;
    list)
        cmd_list
        ;;
    stage-rollback)
        shift
        cmd_stage_rollback "${1:-}"
        ;;
    *)
        usage
        ;;
esac
