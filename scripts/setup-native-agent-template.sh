#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Build the golden native-KVM guest template ONCE and register it, so a VM is
# `fluxctl vm-template create native-agent <name>` instead of a hand-built
# image and spec every time:
#
#   sudo scripts/setup-native-agent-template.sh
#
# Produces (idempotent; existing files are kept unless FORCE=1):
#   /var/lib/fluxvm/images/linux-agent.raw            golden root, read-only base
#   /var/lib/fluxvm/kernels/vmlinux-5.10.225-no-acpi  kernel with virtio-rng/vsock
#   vm-template "native-agent"                        from examples/fluxvm-native-agent.json
# Environment: BASE_IMG (cloud image path), KERNEL_URL, FORCE, FLUXVM_CONFIG,
# CARGO_TARGET_DIR (where the static agent is built).
set -euo pipefail

[ "$(id -u)" = "0" ] || { echo "run as root" >&2; exit 2; }
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGES=/var/lib/fluxvm/images
KERNELS=/var/lib/fluxvm/kernels
GOLDEN="${IMAGES}/linux-agent.raw"
KERNEL="${KERNELS}/vmlinux-5.10.225-no-acpi"
KERNEL_URL="${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.11/x86_64/vmlinux-5.10.225-no-acpi}"
BASE_URL="https://cloud-images.ubuntu.com/bionic/current/bionic-server-cloudimg-amd64.img"
BASE_IMG="${BASE_IMG:-${IMAGES}/.bionic-cloudimg.img}"
CONFIG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
FORCE="${FORCE:-0}"
AGENT="${CARGO_TARGET_DIR:-${PROJECT_DIR}/target}/x86_64-unknown-linux-musl/release/fluxvm-guest-agent"
install -d "$IMAGES" "$KERNELS"

if [ ! -x "$AGENT" ] || [ "$FORCE" = 1 ]; then
  echo "building the static guest agent as ${SUDO_USER:-root}"
  if [ -n "${SUDO_USER:-}" ]; then
    sudo -u "$SUDO_USER" -H bash -lc \
      "cd '$PROJECT_DIR' && ${CARGO_TARGET_DIR:+export CARGO_TARGET_DIR='$CARGO_TARGET_DIR' &&} scripts/build-guest-agent-static.sh"
  else
    (cd "$PROJECT_DIR" && scripts/build-guest-agent-static.sh)
  fi
fi

if [ ! -f "$KERNEL" ] || [ "$FORCE" = 1 ]; then
  echo "fetching kernel"
  curl -fsSL -o "${KERNEL}.tmp" "$KERNEL_URL"
  mv "${KERNEL}.tmp" "$KERNEL"
fi

if [ ! -f "$GOLDEN" ] || [ "$FORCE" = 1 ]; then
  [ -f "$BASE_IMG" ] || { echo "fetching base cloud image"; curl -fsSL -o "$BASE_IMG" "$BASE_URL"; }
  rm -f "${GOLDEN}.tmp"
  "${PROJECT_DIR}/scripts/build-native-guest-image.sh" "$BASE_IMG" "${GOLDEN}.tmp" "$AGENT"
  chmod 0444 "${GOLDEN}.tmp"
  mv -f "${GOLDEN}.tmp" "$GOLDEN"
  (cd "$IMAGES" && sha256sum linux-agent.raw > linux-agent.raw.sha256)
fi
echo "golden image: ${GOLDEN} sha256=$(cut -c1-16 "${GOLDEN}.sha256")"

fluxctl --config "$CONFIG" vm-template save native-agent \
  --spec "${PROJECT_DIR}/examples/fluxvm-native-agent.json" \
  --description "Native KVM Linux guest: Cloud-init, static guest agent, baked systemd-networkd config" \
  --replace
echo "ready: fluxctl --config ${CONFIG} vm-template create native-agent <vm-name>"
