#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Real-host acceptance gate for the direct-kernel, flat-ext4 native profile.
# Requires a running FluxVM service configured with fluxvm_engine = "kvm".
set -euo pipefail

CONFIG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
CLI="${FLUXVM_BIN:-fluxctl}"
AGENT="${FLUXVM_AGENT:-0}"
# With FLUXVM_AGENT=1 the default is the golden template from
# scripts/setup-native-agent-template.sh (Cloud-init + agent + 5.10 kernel).
if [[ "$AGENT" == "1" ]]; then
  KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux-5.10.225-no-acpi}"
  ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/linux-agent.raw}"
else
  KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux}"
  ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/linux-rootfs.raw}"
fi

[[ -e /dev/kvm ]] || { echo "FAIL: /dev/kvm is unavailable" >&2; exit 2; }
[[ -f "$KERNEL" && -f "$ROOTFS" && -f "$CONFIG" ]] || {
  echo "FAIL: KERNEL, ROOTFS or FLUXVM_CONFIG does not exist" >&2; exit 2;
}
command -v "$CLI" >/dev/null || { echo "FAIL: fluxctl unavailable" >&2; exit 2; }
grep -Eq '^[[:space:]]*fluxvm_engine[[:space:]]*=[[:space:]]*"kvm"' "$CONFIG" || {
  echo "FAIL: set fluxvm_engine = \"kvm\" in $CONFIG" >&2; exit 2;
}
case "$ROOTFS" in *.raw|*.ext4) ;; *) echo "FAIL: use a .raw or .ext4 image" >&2; exit 2;; esac

tmp_dir="$(mktemp -d)"
vm_id=""
cleanup() {
  if [[ -n "$vm_id" ]]; then "$CLI" --config "$CONFIG" delete "$vm_id" >/dev/null 2>&1 || true; fi
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

KERNEL="$KERNEL" ROOTFS="$ROOTFS" AGENT="$AGENT" python3 - "$tmp_dir/spec.json" <<'PY'
import json, os, sys
spec = {
    "name": "native-kvm-acceptance", "backend": "flux-vm",
    "image": os.environ["ROOTFS"], "kernel": os.environ["KERNEL"],
    "vcpus": 1, "memory_mib": 512, "network": {"mode": "none"},
    "ttl_seconds": 600, "agent": {"enabled": os.environ["AGENT"] == "1"},
}
if os.environ["AGENT"] == "1":
    spec["cloud_init"] = {"hostname": "native-kvm-acceptance"}
with open(sys.argv[1], "w", encoding="utf-8") as f:
    json.dump(spec, f)
PY

response="$(timeout 120 "$CLI" --config "$CONFIG" create --spec "$tmp_dir/spec.json")" || {
  echo "FAIL: native VM create failed" >&2; exit 1;
}
vm_id="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
pid="$(printf '%s' "$response" | python3 -c 'import json,sys; print(json.load(sys.stdin)["pid"])')"
[[ "$pid" =~ ^[0-9]+$ && -r "/proc/$pid/cmdline" ]] || {
  echo "FAIL: create returned no live VMM pid" >&2; exit 1;
}
tr '\0' ' ' < "/proc/$pid/cmdline" | grep -q 'fluxvm-hypervisor' || {
  echo "FAIL: create did not launch fluxvm-hypervisor" >&2; exit 1;
}
if command -v pgrep >/dev/null && pgrep -P "$pid" -f 'qemu-system|qemu-nbd' >/dev/null; then
  echo "FAIL: QEMU process is a native VMM child" >&2; exit 1
fi
echo "PASS: native VMM running (pid=$pid, vm=$vm_id)"

if [[ "$AGENT" == "1" ]]; then
  ready=0
  for _ in $(seq 1 45); do
    if "$CLI" --config "$CONFIG" exec "$vm_id" -- true >/dev/null 2>&1; then
      ready=1; break
    fi
    sleep 2
  done
  [[ "$ready" == "1" ]] || { echo "FAIL: guest agent did not answer" >&2; exit 1; }
  echo "PASS: guest agent answered over vsock"
  configured=0
  for _ in $(seq 1 30); do
    if "$CLI" --config "$CONFIG" exec "$vm_id" -- hostname 2>/dev/null | python3 -c '
import json, sys
try:
    output = json.load(sys.stdin).get("stdout", "").strip()
except (ValueError, KeyError):
    output = ""
sys.exit(0 if output == "native-kvm-acceptance" else 1)
'; then
      configured=1; break
    fi
    sleep 2
  done
  [[ "$configured" == "1" ]] || { echo "FAIL: NoCloud hostname was not applied" >&2; exit 1; }
  echo "PASS: NoCloud hostname applied"
fi
