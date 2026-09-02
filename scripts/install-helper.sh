#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this installer as root (for example: sudo ./scripts/install-helper.sh)." >&2
    exit 1
fi

SCRIPT_DIRECTORY=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_DIRECTORY=$(dirname -- "$SCRIPT_DIRECTORY")
SOURCE_HELPER="$PROJECT_DIRECTORY/helper/iobroker-wireguard-s2s-helper.js"
TARGET_DIRECTORY="/usr/local/libexec"
TARGET_HELPER="$TARGET_DIRECTORY/iobroker-wireguard-s2s-helper"
SUDOERS_FILE="/etc/sudoers.d/iobroker-wireguard-s2s"
IOBROKER_SERVICE_USER=${IOBROKER_SERVICE_USER:-iobroker}

case "$IOBROKER_SERVICE_USER" in
    *[!A-Za-z0-9_-]*|'')
        echo "Invalid IOBROKER_SERVICE_USER." >&2
        exit 1
        ;;
esac

if ! id "$IOBROKER_SERVICE_USER" >/dev/null 2>&1; then
    echo "The service user '$IOBROKER_SERVICE_USER' does not exist." >&2
    exit 1
fi

for program in node wg ip sysctl sudo visudo; do
    if ! command -v "$program" >/dev/null 2>&1; then
        echo "Required command '$program' is not installed." >&2
        exit 1
    fi
done

node --check "$SOURCE_HELPER"
install -d -o root -g root -m 0755 "$TARGET_DIRECTORY"
install -o root -g root -m 0755 "$SOURCE_HELPER" "$TARGET_HELPER"

TEMPORARY_SUDOERS=$(mktemp /tmp/iobroker-wireguard-s2s.sudoers.XXXXXX)
trap 'rm -f "$TEMPORARY_SUDOERS"' EXIT HUP INT TERM
printf '%s ALL=(root) NOPASSWD: %s\n' "$IOBROKER_SERVICE_USER" "$TARGET_HELPER" > "$TEMPORARY_SUDOERS"
chmod 0440 "$TEMPORARY_SUDOERS"
visudo -cf "$TEMPORARY_SUDOERS"
install -o root -g root -m 0440 "$TEMPORARY_SUDOERS" "$SUDOERS_FILE"
visudo -cf "$SUDOERS_FILE"

echo "Installed $TARGET_HELPER and a sudo policy for $IOBROKER_SERVICE_USER."
