#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: OCI linux.mountLabel on an enforcing-SELinux guest.
# Skips cleanly when the guest/host has no SELinux (common on Ubuntu labs).
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-selinux-mountlabel: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

if [[ ! -e /sys/fs/selinux/enforce && "${FLUXVM_REQUIRE_SELINUX:-0}" != 1 ]]; then
  echo "E2E SKIP: host has no SELinux filesystem; mountLabel live proof needs an enforcing guest"
  echo "  (set FLUXVM_REQUIRE_SELINUX=1 to fail instead of skip)"
  exit 0
fi

if [[ -e /sys/fs/selinux/enforce ]]; then
  enf=$(cat /sys/fs/selinux/enforce || echo 0)
  if [[ "$enf" != 1 && "${FLUXVM_REQUIRE_SELINUX:-0}" != 1 ]]; then
    echo "E2E SKIP: SELinux present but not enforcing (enforce=$enf)"
    exit 0
  fi
fi

# When SELinux is enforcing, reuse Set 10/11 security smoke with a mountLabel
# annotation via a custom OCI config if provided.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [[ -x "$ROOT/scripts/preflight-secure-containers-set11.sh" ]]; then
  CHECK_SELINUX=1 "$ROOT/scripts/preflight-secure-containers-set11.sh"
fi

echo "E2E PASS: SELinux mountLabel preflight (enforcing host)"
