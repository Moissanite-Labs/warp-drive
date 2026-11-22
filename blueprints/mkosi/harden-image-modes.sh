#!/usr/bin/env bash
set -euo pipefail

# Normalize root-controlled policy, verifier, model, and unit ancestor paths during mkosi image build.
# Prevents writable ancestor directories from swapping trusted verifier files or model weights.

umask 022
ROOT="${WARP_IMAGE_ROOT:-}"

normalize_ancestor() {
    local target="${ROOT%/}$1"
    if [[ ! -e "${target}" && ! -L "${target}" ]]; then
        return 0
    fi
    if [[ "$(id -u)" -eq 0 ]]; then
        chown root:root "${target}"
    fi
    chmod go-w "${target}"
}

normalize_tree() {
    local target="${ROOT%/}$1"
    if [[ ! -e "${target}" && ! -L "${target}" ]]; then
        return 0
    fi
    if [[ "$(id -u)" -eq 0 ]]; then
        find "${target}" -xdev \( -type d -o -type f \) -exec chown root:root {} +
    fi
    find "${target}" -xdev \( -type d -o -type f \) -exec chmod go-w {} +
}

for ancestor in \
    /etc \
    /etc/warp \
    /etc/profile.d \
    /var \
    /var/lib \
    /var/lib/warp \
    /usr \
    /usr/lib \
    /usr/lib/systemd \
    /usr/lib/systemd/system \
    /usr/local \
    /usr/local/bin; do
    normalize_ancestor "${ancestor}"
done

for tree in \
    /etc/warp/canaries \
    /var/lib/warp/models \
    /usr/lib/systemd/system; do
    normalize_tree "${tree}"
done
