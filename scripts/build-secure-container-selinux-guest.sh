#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Build a Fedora cloud guest with SELinux enforcing + fluxvm-guest-agent for
# Secure Containers mountLabel live gates.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMG_DIR="${FLUXVM_IMAGE_DIR:-/var/lib/fluxvm/images}"
OUT="${FLUXVM_SC_SELINUX_GUEST:-$IMG_DIR/secure-container-selinux.qcow2}"
BASE="${FLUXVM_SC_FEDORA_BASE:-$IMG_DIR/fedora-cloud-base.qcow2}"
SIZE="${FLUXVM_SC_SELINUX_GUEST_SIZE:-8G}"
AGENT="${FLUXVM_GUEST_AGENT_BIN:-$ROOT/target/release/fluxvm-guest-agent}"
ENSURE_SH="$ROOT/scripts/guest/fluxvm-selinux-ensure.sh"
ENSURE_UNIT="$ROOT/systemd/fluxvm-selinux-ensure.service"

[[ -x "$AGENT" ]] || { echo "build fluxvm-guest-agent first: $AGENT" >&2; exit 1; }
[[ -f "$ENSURE_SH" ]] || { echo "missing $ENSURE_SH" >&2; exit 1; }
[[ -f "$ENSURE_UNIT" ]] || { echo "missing $ENSURE_UNIT" >&2; exit 1; }
command -v virt-customize >/dev/null
command -v qemu-img >/dev/null
sudo mkdir -p "$IMG_DIR"

if [[ ! -f "$BASE" ]]; then
  echo "downloading Fedora Cloud base..."
  # Fedora 40 cloud qcow2
  sudo curl -fL --retry 3 -o "$BASE" \
    https://download.fedoraproject.org/pub/fedora/linux/releases/40/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-40-1.14.qcow2 \
    || sudo curl -fL --retry 3 -o "$BASE" \
    https://download.fedoraproject.org/pub/fedora/linux/releases/39/Cloud/x86_64/images/Fedora-Cloud-Base-Generic.x86_64-39-1.5.qcow2
fi

TMP="$OUT.tmp"
sudo qemu-img convert -O qcow2 "$BASE" "$TMP"
sudo qemu-img resize "$TMP" "$SIZE"
export LIBGUESTFS_BACKEND="${LIBGUESTFS_BACKEND:-direct}"
sudo -E virt-customize --no-network -a "$TMP" \
  --hostname fluxvm-sc-selinux \
  --mkdir /usr/local/bin \
  --mkdir /usr/local/libexec \
  --upload "$AGENT:/usr/local/bin/fluxvm-guest-agent" \
  --chmod 0755:/usr/local/bin/fluxvm-guest-agent \
  --upload "$ENSURE_SH:/usr/local/libexec/fluxvm-selinux-ensure.sh" \
  --chmod 0755:/usr/local/libexec/fluxvm-selinux-ensure.sh \
  --upload "$ENSURE_UNIT:/etc/systemd/system/fluxvm-selinux-ensure.service" \
  --upload "$ROOT/systemd/fluxvm-guest-agent.service:/etc/systemd/system/fluxvm-guest-agent.service" \
  --run-command 'mkdir -p /etc/systemd/system/multi-user.target.wants; ln -sf /etc/systemd/system/fluxvm-guest-agent.service /etc/systemd/system/multi-user.target.wants/fluxvm-guest-agent.service; ln -sf /etc/systemd/system/fluxvm-selinux-ensure.service /etc/systemd/system/multi-user.target.wants/fluxvm-selinux-ensure.service' \
  --run-command 'mkdir -p /etc/cloud; touch /etc/cloud/cloud-init.disabled' \
  --run-command 'if [ -f /etc/selinux/config ]; then sed -i "s/^SELINUX=.*/SELINUX=enforcing/" /etc/selinux/config; fi' \
  --run-command 'rm -f /.autorelabel' \
  --run-command 'test -x /usr/local/bin/fluxvm-guest-agent && test -x /usr/local/libexec/fluxvm-selinux-ensure.sh' \
  --run-command 'restorecon -F /usr/local/bin/fluxvm-guest-agent /usr/local/libexec/fluxvm-selinux-ensure.sh /etc/systemd/system/fluxvm-guest-agent.service /etc/systemd/system/fluxvm-selinux-ensure.service 2>/dev/null || (chcon -t bin_t /usr/local/bin/fluxvm-guest-agent; chcon -t bin_t /usr/local/libexec/fluxvm-selinux-ensure.sh) || true' \
  --selinux-relabel

sudo mv -f "$TMP" "$OUT"
sudo chmod 644 "$OUT"
echo "SELinux SC guest ready: $OUT"
