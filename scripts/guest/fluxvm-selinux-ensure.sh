#!/bin/bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Ensure selinuxfs is mounted, policy is loaded, and FluxVM guest-agent files
# have usable SELinux labels before fluxvm-guest-agent starts.
set -eu

if [[ -f /etc/selinux/config ]]; then
  # shellcheck disable=SC1091
  . /etc/selinux/config
fi

if [[ "${SELINUX:-}" == "disabled" ]]; then
  exit 0
fi

mkdir -p /sys/fs/selinux
if ! mountpoint -q /sys/fs/selinux 2>/dev/null; then
  mount -t selinuxfs selinuxfs /sys/fs/selinux 2>/dev/null || true
fi

if [[ ! -e /sys/fs/selinux/enforce ]]; then
  if command -v load_policy >/dev/null 2>&1; then
    load_policy -i 2>/dev/null || load_policy 2>/dev/null || true
  fi
fi

if [[ -e /sys/fs/selinux/enforce && "${SELINUX:-}" == "enforcing" ]]; then
  echo 1 >/sys/fs/selinux/enforce 2>/dev/null || true
elif command -v setenforce >/dev/null 2>&1 && [[ "${SELINUX:-}" == "enforcing" ]]; then
  setenforce 1 2>/dev/null || true
fi

# virt-customize / guestkit writes can leave unlabeled_t; under enforcing that
# blocks the guest-agent binary and its token from working (vsock listen).
if command -v restorecon >/dev/null 2>&1; then
  restorecon -F /usr/local/bin/fluxvm-guest-agent \
    /usr/local/libexec/fluxvm-selinux-ensure.sh \
    /etc/fluxvm-guest-agent.token \
    /etc/systemd/system/fluxvm-guest-agent.service \
    /etc/systemd/system/fluxvm-selinux-ensure.service \
    2>/dev/null || true
elif command -v chcon >/dev/null 2>&1; then
  chcon -t bin_t /usr/local/bin/fluxvm-guest-agent 2>/dev/null || true
  chcon -t etc_t /etc/fluxvm-guest-agent.token 2>/dev/null || true
fi

if command -v getenforce >/dev/null 2>&1; then
  getenforce || true
fi

exit 0
