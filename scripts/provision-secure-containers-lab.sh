#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Provision Secure Containers on a KVM lab host: build shim/agent/guest-agent,
# bake a guest image with fluxvm-guest-agent, install binaries, register
# containerd runtimes (system + k3s drop-in), apply RuntimeClass.
#
# 15-minute lab path:
#   1) fluxctl serve listening on :7788
#   2) sudo FLUXVM_SC_RESTART_K3S=1 ./scripts/provision-secure-containers-lab.sh
#   3) docs/secure-containers-flip-runtimeclass.md smoke Pod
#   4) FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/demo-secure-containers-wow.sh
#
# CNI notes (Cilium / Calico):
#   - Default production profile expects Pod CNI L2 (do not leave
#     FLUXVM_CONTAINER_CNI=0 on shared clusters).
#   - If sandbox create hangs on CNI DELETE/ADD, clean zombie sandboxes
#     (`ctr -n k8s.io sandboxes ls`) before retrying; prefer unique Pod names.
#   - hostNetwork smoke skips Pod CNI — useful for shim/agent debug only.
#   - Keep sandboxer=podsandbox (this shim has no Sandbox TTRPC service).
#
# Guest image: Ubuntu cloud + virt-customize is the lab bootstrap path when no
# image exists. Production token inject / customize goes through guestkit only
# (Fedora/btrfs roots supported) — never add a virt-customize fallback to
# fluxvm-image.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != Linux ]]; then
  echo "provision-secure-containers-lab: Linux/KVM only" >&2
  exit 1
fi

# shellcheck disable=SC1090
[[ -f "$HOME/.cargo/env" ]] && source "$HOME/.cargo/env"
export PATH="${HOME}/.cargo/bin:/usr/local/cargo/bin:${PATH}"

PREFIX="${PREFIX:-/usr/local}"
IMG_DIR="${FLUXVM_IMAGE_DIR:-/var/lib/fluxvm/images}"
GUEST_IMG="${FLUXVM_CONTAINER_GUEST_IMAGE:-$IMG_DIR/secure-container.qcow2}"
SIZE="${FLUXVM_SC_GUEST_SIZE:-8G}"

echo "== build shim + agents =="
cargo build --release \
  -p fluxvm-containerd-shim \
  -p fluxvm-container-agent \
  -p fluxvm-guest-agent

echo "== install host binaries =="
sudo install -D -m 0755 target/release/containerd-shim-fluxvm-v2 \
  "$PREFIX/bin/containerd-shim-fluxvm-v2"
sudo install -D -m 0755 target/release/fluxvm-container-agent \
  "$PREFIX/libexec/fluxvm-container-agent"
sudo install -D -m 0755 target/release/fluxvm-guest-agent \
  "$PREFIX/bin/fluxvm-guest-agent"

if [[ ! -f "$GUEST_IMG" || "${FLUXVM_SC_REBUILD_GUEST:-0}" == 1 ]]; then
  command -v virt-customize >/dev/null || { echo "virt-customize required" >&2; exit 1; }
  command -v qemu-img >/dev/null || { echo "qemu-img required" >&2; exit 1; }
  echo "== cloud image + virt-customize guest -> $GUEST_IMG =="
  sudo mkdir -p "$IMG_DIR"
  BASE="${FLUXVM_SC_CLOUD_BASE:-$IMG_DIR/ubuntu-24.04-sc-base.img}"
  if [[ ! -f "$BASE" ]]; then
    sudo curl -fsSL -o "$BASE" \
      https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img
  fi
  TMPIMG="$GUEST_IMG.tmp"
  sudo qemu-img convert -O qcow2 "$BASE" "$TMPIMG"
  sudo qemu-img resize "$TMPIMG" "$SIZE"
  export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"
  # Prefer offline customize; --install needs network and may fail under passt.
  sudo -E virt-customize -a "$TMPIMG" \
    --hostname fluxvm-sc \
    --mkdir /usr/local/bin \
    --upload "$ROOT/target/release/fluxvm-guest-agent:/usr/local/bin/fluxvm-guest-agent" \
    --chmod 0755:/usr/local/bin/fluxvm-guest-agent \
    --upload "$ROOT/systemd/fluxvm-guest-agent.service:/etc/systemd/system/fluxvm-guest-agent.service" \
    --run-command 'systemctl enable fluxvm-guest-agent.service || (mkdir -p /etc/systemd/system/multi-user.target.wants && ln -sf /etc/systemd/system/fluxvm-guest-agent.service /etc/systemd/system/multi-user.target.wants/fluxvm-guest-agent.service)'
  # Best-effort libseccomp (skip if network backend fails).
  sudo -E virt-customize -a "$TMPIMG" --install libseccomp2 || \
    echo "WARN: could not apt-install libseccomp2 into guest (install later / use image with it)"
  # Ensure CLONE_NEWUSER works when FLUXVM_CONTAINER_USERNS=1.
  sudo -E virt-customize -a "$TMPIMG" \
    --write '/etc/sysctl.d/99-fluxvm-userns.conf:user.max_user_namespaces = 15000
kernel.apparmor_restrict_unprivileged_userns = 0
' || echo "WARN: could not write userns sysctl into guest"
  sudo mv -f "$TMPIMG" "$GUEST_IMG"
  sudo chmod 644 "$GUEST_IMG"
else
  echo "== reuse existing guest image $GUEST_IMG =="
fi

echo "== system containerd runtime drop-in =="
SHIM_BIN="$PREFIX/bin/containerd-shim-fluxvm-v2"
if [[ -d /etc/containerd ]] || systemctl is-active containerd >/dev/null 2>&1; then
  sudo mkdir -p /etc/containerd /etc/containerd/conf.d
  if [[ ! -f /etc/containerd/config.toml ]]; then
    sudo tee /etc/containerd/config.toml >/dev/null <<TOML
version = 2
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.fluxvm]
  runtime_type = "io.containerd.fluxvm.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.fluxvm.options]
  BinaryName = "$SHIM_BIN"
TOML
  else
    sudo tee /etc/containerd/conf.d/fluxvm.toml >/dev/null <<TOML
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.fluxvm]
  runtime_type = "io.containerd.fluxvm.v2"
[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.fluxvm.options]
  BinaryName = "$SHIM_BIN"
TOML
  fi
  # Shim environment for guest image + userns
  sudo mkdir -p /etc/systemd/system/containerd.service.d
# Prefer Absolute BinaryName + USERNS; CNI on by default for supported profile.
# Set FLUXVM_CONTAINER_CNI=0 only for user-mode / hostNetwork debug labs.
  sudo tee /etc/systemd/system/containerd.service.d/fluxvm-sc.conf >/dev/null <<EOF
[Service]
Environment=FLUXVM_API_URL=http://127.0.0.1:7788
Environment=FLUXVM_CONTAINER_GUEST_IMAGE=$GUEST_IMG
Environment=FLUXVM_CONTAINER_AGENT_BINARY=$PREFIX/libexec/fluxvm-container-agent
Environment=FLUXVM_CONTAINER_USERNS=1
Environment=FLUXVM_CONTAINER_CNI=${FLUXVM_CONTAINER_CNI:-1}
EOF
  sudo systemctl daemon-reload
  sudo systemctl restart containerd || true
fi

echo "== k3s containerd fluxvm drop-in =="
K3S_D="/var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d"
if [[ -d /var/lib/rancher/k3s/agent/etc/containerd ]]; then
  sudo mkdir -p "$K3S_D"
  # Absolute BinaryName — k3s containerd PATH often omits /usr/local/bin, which
  # produces "can't find shim for sandbox" after a relative-name start fails.
  # Single drop-in (99-) wins over older fluxvm.toml copies.
  sudo rm -f "$K3S_D/fluxvm.toml"
  # Keep default sandboxer=podsandbox. sandboxer=shim requires the
  # containerd.runtime.sandbox.v1.Sandbox TTRPC service, which this shim does
  # not implement yet ("Sandbox service does not exist"). Absolute BinaryName
  # avoids "can't find shim for sandbox" when k3s PATH omits /usr/local/bin.
  sudo tee "$K3S_D/99-fluxvm.toml" >/dev/null <<TOML
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.fluxvm]
  runtime_type = "io.containerd.fluxvm.v2"
[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.fluxvm.options]
  BinaryName = "$SHIM_BIN"
TOML
  # k3s picks up containerd env via systemd for k3s service
  sudo mkdir -p /etc/systemd/system/k3s.service.d
  sudo tee /etc/systemd/system/k3s.service.d/fluxvm-sc.conf >/dev/null <<EOF
[Service]
Environment=FLUXVM_API_URL=http://127.0.0.1:7788
Environment=FLUXVM_CONTAINER_GUEST_IMAGE=$GUEST_IMG
Environment=FLUXVM_CONTAINER_AGENT_BINARY=$PREFIX/libexec/fluxvm-container-agent
Environment=FLUXVM_CONTAINER_USERNS=1
Environment=FLUXVM_CONTAINER_CNI=${FLUXVM_CONTAINER_CNI:-1}
Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF
  sudo systemctl daemon-reload
  # Prefer reload; full restart is disruptive — operator can restart k3s.
  if [[ "${FLUXVM_SC_RESTART_K3S:-0}" == 1 ]]; then
    sudo systemctl restart k3s
  else
    echo "NOTE: set FLUXVM_SC_RESTART_K3S=1 to restart k3s and load the fluxvm runtime"
  fi
fi

if command -v kubectl >/dev/null; then
  kubectl apply -f "$ROOT/deploy/containerd/runtimeclass.yaml" || true
fi

# Host virtiofsd is required for QEMU/CH shared folders.
if [[ -x /usr/libexec/virtiofsd && ! -e /usr/bin/virtiofsd ]]; then
  sudo ln -sf /usr/libexec/virtiofsd /usr/bin/virtiofsd
fi
command -v virtiofsd >/dev/null || echo "WARN: virtiofsd not on PATH"

echo "SECURE CONTAINERS LAB PROVISION: OK"
echo "  guest=$GUEST_IMG"
echo "  shim=$PREFIX/bin/containerd-shim-fluxvm-v2"
echo "  agent=$PREFIX/libexec/fluxvm-container-agent"
