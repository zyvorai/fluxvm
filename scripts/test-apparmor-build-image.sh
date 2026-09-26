#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Smoke: `fluxctl build-image` under the *enforced* AppArmor profile shipped
# in deploy/apparmor/fluxvm (zyvorai/fluxvm#107).
#
# Installs the profile, places fluxctl at /usr/local/bin/fluxctl (the path
# the profile attaches to), then runs scripts/test-image-customize.sh so the
# full guestkit path (qemu-nbd, mount, chroot, packages) is exercised while
# confined.
#
# Usage (root):
#   sudo ./scripts/test-apparmor-build-image.sh --image /path/to/base.qcow2
#
# Env:
#   FLUXVM_BIN   source binary to install as /usr/local/bin/fluxctl
#                (default: target/release/fluxctl or PATH)
#   TEST_PACKAGE / TEST_SERVICE  forwarded to test-image-customize.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
PROFILE_SRC="${PROJECT_DIR}/deploy/apparmor/fluxvm"
IMAGE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --image) IMAGE="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

[ "$(uname -s)" = "Linux" ] || { echo "Linux + AppArmor required" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo)" >&2; exit 1; }
[ -n "$IMAGE" ] && [ -f "$IMAGE" ] || { echo "--image is required and must exist" >&2; exit 1; }
[ -f "$PROFILE_SRC" ] || { echo "missing profile: $PROFILE_SRC" >&2; exit 1; }
command -v apparmor_parser >/dev/null 2>&1 || { echo "apparmor_parser not found" >&2; exit 1; }
[ -d /etc/apparmor.d ] || { echo "/etc/apparmor.d missing — AppArmor not available" >&2; exit 1; }

SRC_BIN="${FLUXVM_BIN:-}"
if [ -z "$SRC_BIN" ]; then
    if [ -x "${PROJECT_DIR}/target/release/fluxctl" ]; then
        SRC_BIN="${PROJECT_DIR}/target/release/fluxctl"
    elif command -v fluxctl >/dev/null 2>&1; then
        SRC_BIN="$(command -v fluxctl)"
    else
        echo "fluxctl not found; build release or set FLUXVM_BIN" >&2
        exit 1
    fi
fi
[ -x "$SRC_BIN" ] || { echo "FLUXVM_BIN not executable: $SRC_BIN" >&2; exit 1; }

echo "=== installing fluxctl to /usr/local/bin (AppArmor attach path) ==="
if [ "$(readlink -f "$SRC_BIN")" = "$(readlink -f /usr/local/bin/fluxctl 2>/dev/null || true)" ]; then
    echo "  already at /usr/local/bin/fluxctl"
else
    install -m 0755 "$SRC_BIN" /usr/local/bin/fluxctl
fi

echo "=== loading enforced AppArmor profile ==="
# Validate before replace so a bad profile never leaves the host half-updated.
apparmor_parser -Q "$PROFILE_SRC"
install -m 0644 "$PROFILE_SRC" /etc/apparmor.d/fluxvm
apparmor_parser -r /etc/apparmor.d/fluxvm

if command -v aa-status >/dev/null 2>&1; then
    aa-status 2>/dev/null | grep -E 'fluxctl' || true
fi
# Enforce mode: profile must not list complain
if aa-status --enforced 2>/dev/null | grep -qx 'fluxctl'; then
    echo "  fluxctl is enforced"
elif aa-status 2>/dev/null | grep -q 'fluxctl (enforce)'; then
    echo "  fluxctl is enforced"
else
    # Fallback probe: /proc/self/attr after aa-exec
    MODE="$(aa-exec -p fluxctl -- cat /proc/self/attr/current 2>/dev/null || true)"
    echo "  current label probe: ${MODE:-<unknown>}"
    case "$MODE" in
        *'(complain)'*)
            echo "ERROR: fluxctl profile is in complain mode; want enforce" >&2
            exit 1
            ;;
        *fluxctl*)
            echo "  fluxctl confinement active"
            ;;
        *)
            echo "WARNING: could not confirm enforce via aa-status; continuing" >&2
            ;;
    esac
fi

echo "=== build-image under enforced profile (spec under /tmp) ==="
export FLUXVM_BIN=/usr/local/bin/fluxctl
# Clear recent denials for this profile so a post-run scan is meaningful.
dmesg -C 2>/dev/null || true
"${SCRIPT_DIR}/test-image-customize.sh" --image "$IMAGE"

echo "=== checking kernel log for fluxctl AppArmor DENIED ==="
if dmesg 2>/dev/null | grep -E 'apparmor="DENIED".*profile="fluxctl"' | tee /tmp/fluxvm-apparmor-denied.txt | grep -q .; then
    echo "FAIL: AppArmor DENIED events for profile fluxctl during build-image:" >&2
    cat /tmp/fluxvm-apparmor-denied.txt >&2
    exit 1
fi
echo "  no DENIED events for fluxctl"
echo "PASS: AppArmor-enforced build-image smoke"
