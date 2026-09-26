#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

missing=0
for cmd in qemu-system-x86_64 qemu-img cloud-localds ip; do
  if command -v "$cmd" >/dev/null 2>&1; then
    printf '%-24s %s\n' "$cmd" "OK ($(command -v "$cmd"))"
  else
    printf '%-24s %s\n' "$cmd" "MISSING"
    missing=1
  fi
done

for cmd in cloud-hypervisor firecracker fluxctl fluxvm-hypervisor bpftool tc; do
  if command -v "$cmd" >/dev/null 2>&1; then
    printf '%-24s %s\n' "$cmd" "OK ($(command -v "$cmd"))"
  else
    printf '%-24s %s\n' "$cmd" "optional/not installed"
  fi
done

# tap+netns networking starts one dnsmasq (DHCP for the guest) per VM namespace.
# Not fatal: VMs on other network modes do not need it.
if command -v dnsmasq >/dev/null 2>&1; then
  printf '%-24s %s\n' "dnsmasq" "OK ($(command -v dnsmasq))"
else
  printf '%-24s %s\n' "dnsmasq" "not installed (needed for tap+netns guest DHCP: apt install dnsmasq-base)"
fi

if [[ -e /dev/kvm ]]; then
  echo "/dev/kvm                 OK"
else
  echo "/dev/kvm                 MISSING"
  missing=1
fi

exit "$missing"
