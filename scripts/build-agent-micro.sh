#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Build the agent-micro image: Debian 13's arm64 cloud image (partitions and EFI boot kept, so the vz backend boots it like
# debian-13) with the static fluxvm-guest-agent installed and enabled, and cloud-init limited to the NoCloud seed.
#
#   sudo scripts/build-agent-micro.sh [OUT_DIR]
#
# Runs on Linux (loop devices); on a Mac, run it in a Linux VM. Environment:
#   AGENT_BIN  static aarch64 agent (default target/aarch64-unknown-linux-musl/release/fluxvm-guest-agent; build it with
#              GUEST_AGENT_TARGET=aarch64-unknown-linux-musl scripts/build-guest-agent-static.sh)
#   BASE       a Debian 13 arm64 disk.raw to start from (default: download and verify the current one)
#   TRIM=1     on an arm64 builder, purge packages a sandbox does not need (chroot)
# Output: OUT_DIR/agent-micro-arm64.raw and its .sha256. Register it on the Mac with
#   fluxctl catalog add agent-micro --source /path/agent-micro-arm64.raw --format raw
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="${1:-${PROJECT_DIR}/out}"
AGENT="${AGENT_BIN:-${CARGO_TARGET_DIR:-${PROJECT_DIR}/target}/aarch64-unknown-linux-musl/release/fluxvm-guest-agent}"
UNIT="${PROJECT_DIR}/systemd/fluxvm-guest-agent.service"
DEBIAN_URL="https://cloud.debian.org/images/cloud/trixie/latest"
DEBIAN_FILE="debian-13-generic-arm64.tar.xz"
OUT="${OUT_DIR}/agent-micro-arm64.raw"

[ "$(uname -s)" = "Linux" ] || { echo "run on Linux (needs loop devices); on a Mac, inside a Linux VM" >&2; exit 2; }
[ "$(id -u)" = "0" ] || { echo "run as root (loop mount)" >&2; exit 2; }
[ -x "$AGENT" ] || { echo "agent binary not found: $AGENT" >&2; exit 2; }
[ -f "$UNIT" ] || { echo "unit file not found: $UNIT" >&2; exit 2; }
case "$(file -b "$AGENT")" in
  *aarch64*static*) ;;
  *) echo "need a static aarch64 agent, got: $(file -b "$AGENT")" >&2; exit 2 ;;
esac
for tool in losetup mount blkid sha256sum sha512sum tar curl file; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

mkdir -p "$OUT_DIR"
WORK="$(mktemp -d)"
MNT="${WORK}/root"
LOOP=""
cleanup() {
  for m in dev/pts dev proc sys; do mountpoint -q "${MNT}/${m}" 2>/dev/null && umount "${MNT}/${m}" || true; done
  mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" || true
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
  rm -rf "$WORK"
}
trap cleanup EXIT

if [ -z "${BASE:-}" ]; then
  echo "==> downloading ${DEBIAN_FILE}"
  curl -fsSL -o "${WORK}/${DEBIAN_FILE}" "${DEBIAN_URL}/${DEBIAN_FILE}"
  curl -fsSL -o "${WORK}/SHA512SUMS" "${DEBIAN_URL}/SHA512SUMS"
  (cd "$WORK" && grep " ${DEBIAN_FILE}\$" SHA512SUMS | sha512sum -c -)
  tar -C "$WORK" -xJf "${WORK}/${DEBIAN_FILE}" disk.raw
  BASE="${WORK}/disk.raw"
fi
cp --sparse=always "$BASE" "$OUT"

echo "==> installing the guest agent"
LOOP="$(losetup -Pf --show "$OUT")"
udevadm settle 2>/dev/null || sleep 1
ROOT=""
best=0
for part in "${LOOP}"p*; do
  [ "$(blkid -o value -s TYPE "$part" 2>/dev/null)" = "ext4" ] || continue
  size=$(blockdev --getsize64 "$part")
  if [ "$size" -gt "$best" ]; then best=$size; ROOT=$part; fi
done
[ -n "$ROOT" ] || { echo "no ext4 root partition in $BASE" >&2; exit 1; }
mkdir -p "$MNT"
mount "$ROOT" "$MNT"

install -D -m755 "$AGENT" "${MNT}/usr/local/bin/fluxvm-guest-agent"
install -D -m644 "$UNIT" "${MNT}/etc/systemd/system/fluxvm-guest-agent.service"
# The token arrives through cloud-init (write_files); the agent reads it once at start.
install -d "${MNT}/etc/systemd/system/fluxvm-guest-agent.service.d"
cat > "${MNT}/etc/systemd/system/fluxvm-guest-agent.service.d/10-after-cloud-init.conf" <<'EOF'
[Unit]
After=cloud-init.service
Wants=cloud-init.service
EOF
install -d "${MNT}/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/fluxvm-guest-agent.service \
  "${MNT}/etc/systemd/system/multi-user.target.wants/fluxvm-guest-agent.service"

# FluxVM always attaches a NoCloud seed; probing other datasources only slows the boot.
install -d "${MNT}/etc/cloud/cloud.cfg.d"
printf 'datasource_list: [ NoCloud, None ]\n' > "${MNT}/etc/cloud/cloud.cfg.d/90-fluxvm-nocloud.cfg"

if [ "${TRIM:-0}" = "1" ]; then
  [ "$(uname -m)" = "aarch64" ] || { echo "TRIM=1 needs an arm64 builder (chroot)" >&2; exit 2; }
  echo "==> trimming packages"
  mount --bind /dev "${MNT}/dev"; mount -t proc proc "${MNT}/proc"; mount -t sysfs sys "${MNT}/sys"
  printf '#!/bin/sh\nexit 101\n' > "${MNT}/usr/sbin/policy-rc.d"; chmod +x "${MNT}/usr/sbin/policy-rc.d"
  chroot "$MNT" env DEBIAN_FRONTEND=noninteractive apt-get purge -y --auto-remove \
    unattended-upgrades reportbug installation-report man-db manpages 2>/dev/null || true
  chroot "$MNT" apt-get clean
  rm -f "${MNT}/usr/sbin/policy-rc.d"
  rm -rf "${MNT}"/var/lib/apt/lists/* "${MNT}"/usr/share/doc/* "${MNT}"/usr/share/man/*
  for m in sys proc dev; do umount "${MNT}/${m}"; done
fi

# First boot on the Mac must be a real first boot for cloud-init.
rm -rf "${MNT}/var/lib/cloud/instance" "${MNT}/var/lib/cloud/instances" "${MNT}/var/lib/cloud/data" "${MNT}/var/lib/cloud/sem"
rm -f "${MNT}/etc/fluxvm-guest-agent.token"
fstrim "$MNT" 2>/dev/null || true
umount "$MNT"
losetup -d "$LOOP"
LOOP=""

(cd "$OUT_DIR" && sha256sum "$(basename "$OUT")" > "$(basename "$OUT").sha256")
echo "built ${OUT}"
cat "${OUT}.sha256"
echo "register on the Mac: fluxctl catalog add agent-micro --source ${OUT} --format raw"
