#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Build a flat-ext4 guest root for the native (QEMU-free) KVM profile with
# Cloud-init and the static fluxvm-guest-agent installed and enabled:
#
#   sudo scripts/build-native-guest-image.sh BASE.ext4 OUT.raw [AGENT_BIN]
#
# BASE is a Debian/Ubuntu root that already has (or can apt-install) cloud-init:
#   - a flat ext4 (no partition table), or
#   - a partitioned cloud image (qcow2 or raw, e.g. Ubuntu's *-cloudimg-amd64.img),
#     from which the root partition is extracted into a flat ext4. This one-time
#     preparation step uses qemu-img and losetup; the resulting image and the
#     runtime profile need no QEMU.
# The base is never modified. Needs root (loop mount + chroot) and e2fsprogs;
# apt inside the chroot needs network only when cloud-init is missing.
# Note: a minimal rootfs without a dpkg database (Firecracker's quickstart
# image) cannot be used for the apt path; use a cloud image instead.
# Environment:
#   SIZE_MIB   grow the output to this size before installing (default 1536)
#   APT_MIRROR override the apt mirror (default: keep the image's sources)
set -euo pipefail

if [ "$(id -u)" != "0" ]; then
  echo "run as root (loop mount + chroot)" >&2
  exit 2
fi
[ "$#" -ge 2 ] || { echo "usage: $0 BASE.ext4 OUT.raw [AGENT_BIN]" >&2; exit 2; }

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BASE="$1"
OUT="$2"
AGENT="${3:-${CARGO_TARGET_DIR:-${PROJECT_DIR}/target}/x86_64-unknown-linux-musl/release/fluxvm-guest-agent}"
UNIT="${PROJECT_DIR}/systemd/fluxvm-guest-agent.service"
SIZE_MIB="${SIZE_MIB:-1536}"

[ -f "$BASE" ] || { echo "base image not found: $BASE" >&2; exit 2; }
[ -x "$AGENT" ] || { echo "agent binary not found: $AGENT (run scripts/build-guest-agent-static.sh)" >&2; exit 2; }
[ -f "$UNIT" ] || { echo "unit file not found: $UNIT" >&2; exit 2; }
if ldd "$AGENT" 2>&1 | grep -qiE "not a dynamic executable|statically linked"; then :; else
  echo "refusing dynamically linked agent (glibc mismatch in older guests): $AGENT" >&2
  exit 2
fi
for tool in e2fsck resize2fs mount chroot; do
  command -v "$tool" >/dev/null || { echo "missing tool: $tool" >&2; exit 2; }
done

MNT="$(mktemp -d)"
cleanup() {
  for m in dev/pts dev proc sys; do
    mountpoint -q "${MNT}/${m}" 2>/dev/null && umount "${MNT}/${m}" 2>/dev/null || true
  done
  mountpoint -q "$MNT" 2>/dev/null && umount "$MNT" 2>/dev/null || true
  rmdir "$MNT" 2>/dev/null || true
}
trap cleanup EXIT

is_flat_ext4() {
  [ "$(dd if="$1" bs=1 skip=1080 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "53ef" ]
}

RAW_TMP=""
LOOP=""
cleanup_extract() {
  [ -n "$LOOP" ] && losetup -d "$LOOP" 2>/dev/null || true
  [ -n "$RAW_TMP" ] && rm -f "$RAW_TMP" || true
}

if is_flat_ext4 "$BASE"; then
  cp --sparse=always "$BASE" "$OUT"
else
  for tool in qemu-img losetup blkid; do
    command -v "$tool" >/dev/null || { echo "missing tool for partitioned base: $tool" >&2; exit 2; }
  done
  trap cleanup_extract EXIT
  RAW_TMP="$(mktemp "${OUT}.raw.XXXXXX")"
  qemu-img convert -O raw "$BASE" "$RAW_TMP"
  LOOP="$(losetup -Pf --show "$RAW_TMP")"
  udevadm settle 2>/dev/null || sleep 1
  PART="$(blkid -t LABEL=cloudimg-rootfs -o device 2>/dev/null | grep "^${LOOP}p" | head -1 || true)"
  if [ -z "$PART" ]; then
    best=0
    for cand in "${LOOP}"p*; do
      [ "$(blkid -o value -s TYPE "$cand" 2>/dev/null)" = "ext4" ] || continue
      size=$(blockdev --getsize64 "$cand")
      if [ "$size" -gt "$best" ]; then best=$size; PART=$cand; fi
    done
  fi
  [ -n "$PART" ] || { echo "no ext4 root partition found in $BASE" >&2; exit 1; }
  echo "extracting root partition ${PART}"
  dd if="$PART" of="$OUT" bs=4M conv=sparse status=none
  cleanup_extract
  RAW_TMP=""
  LOOP=""
  trap - EXIT
fi
cur=$(( $(stat -c %s "$OUT") / 1048576 ))
if [ "$cur" -lt "$SIZE_MIB" ]; then
  truncate -s "${SIZE_MIB}M" "$OUT"
fi
e2fsck -fy "$OUT" >/dev/null 2>&1 || true
resize2fs "$OUT" >/dev/null 2>&1

mount -o loop "$OUT" "$MNT"
mount --bind /dev "${MNT}/dev"
mount -t proc proc "${MNT}/proc"
mount -t sysfs sys "${MNT}/sys"

# The disk has no EFI/boot partitions here; a fstab entry for one would hold
# boot for the mount timeout.
if [ -f "${MNT}/etc/fstab" ]; then
  sed -i -E '/^[^#]*[[:space:]]\/boot(\/efi)?[[:space:]]/d;/^LABEL=UEFI/d' "${MNT}/etc/fstab"
fi

# Network for apt inside the chroot (restored afterwards).
[ -e "${MNT}/etc/resolv.conf" ] && cp -a "${MNT}/etc/resolv.conf" "${MNT}/etc/resolv.conf.fluxvm-orig" || true
rm -f "${MNT}/etc/resolv.conf"
cp /etc/resolv.conf "${MNT}/etc/resolv.conf" 2>/dev/null || echo "nameserver 1.1.1.1" > "${MNT}/etc/resolv.conf"

if [ -n "${APT_MIRROR:-}" ]; then
  sed -i "s#http://[^ ]*ubuntu[^ ]*#${APT_MIRROR}#g" "${MNT}/etc/apt/sources.list" 2>/dev/null || true
fi

if ! chroot "$MNT" dpkg -s cloud-init >/dev/null 2>&1; then
  # A container-style chroot must not start services or wait on a policy.
  printf '#!/bin/sh\nexit 101\n' > "${MNT}/usr/sbin/policy-rc.d"
  chmod +x "${MNT}/usr/sbin/policy-rc.d"
  chroot "$MNT" env DEBIAN_FRONTEND=noninteractive apt-get update
  chroot "$MNT" env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends cloud-init
  rm -f "${MNT}/usr/sbin/policy-rc.d"
  chroot "$MNT" apt-get clean
  rm -rf "${MNT}"/var/lib/apt/lists/*
fi

# The native profile seeds NoCloud straight into the root disk; probing other
# datasources (EC2, GCE, ...) only adds boot delay in a microVM.
mkdir -p "${MNT}/etc/cloud/cloud.cfg.d"
cat > "${MNT}/etc/cloud/cloud.cfg.d/90-fluxvm-nocloud.cfg" <<'EOF'
datasource_list: [ NoCloud, None ]
datasource:
  NoCloud:
    fs_label: null
EOF
# Start clean so the seed injected at create time is treated as a first boot.
rm -rf "${MNT}/var/lib/cloud/instance" "${MNT}/var/lib/cloud/instances" "${MNT}/var/lib/cloud/data" "${MNT}/var/lib/cloud/sem"
rm -rf "${MNT}/var/log/cloud-init.log" "${MNT}/var/log/cloud-init-output.log"
chroot "$MNT" systemctl enable cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service >/dev/null 2>&1 || true

install -D -m755 "$AGENT" "${MNT}/usr/local/bin/fluxvm-guest-agent"
install -D -m644 "$UNIT" "${MNT}/etc/systemd/system/fluxvm-guest-agent.service"
mkdir -p "${MNT}/etc/systemd/system/multi-user.target.wants"
ln -sf /etc/systemd/system/fluxvm-guest-agent.service \
  "${MNT}/etc/systemd/system/multi-user.target.wants/fluxvm-guest-agent.service"

# Restore the image's own resolv.conf.
rm -f "${MNT}/etc/resolv.conf"
[ -e "${MNT}/etc/resolv.conf.fluxvm-orig" ] && mv "${MNT}/etc/resolv.conf.fluxvm-orig" "${MNT}/etc/resolv.conf" || true

cleanup
trap - EXIT
e2fsck -fy "$OUT" >/dev/null 2>&1 || true
echo "built ${OUT} (cloud-init + static fluxvm-guest-agent, ${SIZE_MIB} MiB)"
