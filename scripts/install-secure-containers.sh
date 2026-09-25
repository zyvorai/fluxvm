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

install -D -m 0644 deploy/containerd/env.example \
  "${PREFIX}/share/fluxvm/containerd-env.example" 2>/dev/null || true

cat <<MSG
Installed:
  $PREFIX/bin/containerd-shim-fluxvm-v2
  $PREFIX/libexec/fluxvm-container-agent

Set FLUXVM_CONTAINER_GUEST_IMAGE to a bootable FluxVM guest image that contains
and starts fluxvm-guest-agent, or place it at:
  /var/lib/fluxvm/images/secure-container.qcow2

VMM backend (optional):
  FLUXVM_CONTAINER_BACKEND=qemu|cloud-hypervisor|firecracker
  Firecracker also needs FLUXVM_CONTAINER_KERNEL=/path/to/vmlinux
  (or daemon config firecracker_kernel). See deploy/containerd/env.example.

FluxVM API default expected by the shim:
  http://127.0.0.1:7788
MSG
