#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this uninstaller as root (for example: sudo ./scripts/uninstall-helper.sh)." >&2
    exit 1
fi

TARGET_HELPER="/usr/local/libexec/iobroker-wireguard-s2s-helper"
SUDOERS_FILE="/etc/sudoers.d/iobroker-wireguard-s2s"

rm -f "$SUDOERS_FILE"
rm -f "$TARGET_HELPER"
echo "Removed the helper and sudo policy. Managed interfaces and state files were left intact."
