#!/usr/bin/env bash
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
CARGO="${CARGO:-cargo}"

"$CARGO" build --release \
  -p fluxvm-container-agent \
  -p fluxvm-containerd-shim

install -D -m 0755 target/release/containerd-shim-fluxvm-v2 \
  "$PREFIX/bin/containerd-shim-fluxvm-v2"
install -D -m 0755 target/release/fluxvm-container-agent \
  "$PREFIX/libexec/fluxvm-container-agent"

cat <<MSG
Installed:
  $PREFIX/bin/containerd-shim-fluxvm-v2
  $PREFIX/libexec/fluxvm-container-agent

Set FLUXVM_CONTAINER_GUEST_IMAGE to a bootable FluxVM QEMU image that contains
and starts fluxvm-guest-agent, or place it at:
  /var/lib/fluxvm/images/secure-container.qcow2

FluxVM API default expected by the shim:
  http://127.0.0.1:7788
MSG
