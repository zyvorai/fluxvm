#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Opt-in, root-only lab probe: does Cloud Hypervisor's own snapshot/restore
# mechanism work at all via the *plain* /v1/vms route (NOT a sandbox --
# create_sandbox always forces flux-vm for a client spec and only allows
# qemu/firecracker from an operator template, so a CloudHypervisor sandbox
# is unreachable and this is the closest thing to it). Own throwaway daemon,
# own port, network.mode=none.
set -euo pipefail

FLUXCTL="${FLUXCTL:-fluxctl}"
IMAGE="${IMAGE:?set IMAGE=/path/to/bootable/qcow2}"
KERNEL="${KERNEL:-}"
FIRMWARE="${FIRMWARE:-}"
PORT="${PORT:-17792}"
API="http://127.0.0.1:$PORT"

[[ $EUID -eq 0 ]] || { echo "FAIL: run as root" >&2; exit 2; }
[[ -e /dev/kvm && -f "$IMAGE" ]] || { echo "SKIP: KVM or image missing" >&2; exit 2; }

root="$(mktemp -d /var/tmp/fluxvm-ch-raw.XXXXXX)"
mkdir -p "$root/state" "$root/run"
daemon_pid=""
vm_id=""
fail=0
cleanup() {
  local rc=$?
  if [[ $rc -ne 0 || $fail -ne 0 ]]; then
    rm -rf /var/tmp/fluxvm-ch-raw-last; mkdir -p /var/tmp/fluxvm-ch-raw-last
    cp "$root/daemon.log" /var/tmp/fluxvm-ch-raw-last/ 2>/dev/null || true
    find "$root/state" -name '*.log' -exec cp {} /var/tmp/fluxvm-ch-raw-last/ \; 2>/dev/null || true
    echo "logs kept in /var/tmp/fluxvm-ch-raw-last"
  fi
  if [[ -n "$vm_id" ]]; then curl -fsS -m 30 -X DELETE "$API/v1/vms/$vm_id" >/dev/null 2>&1 || true; fi
  if [[ -n "$daemon_pid" ]]; then kill "$daemon_pid" 2>/dev/null || true; wait "$daemon_pid" 2>/dev/null || true; fi
  rm -rf "$root"
}
trap cleanup EXIT
check() { if "$@"; then :; else echo "FAIL: $*" >&2; fail=1; fi; }
jq_() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval(sys.argv[1]))' "$1"; }
has() { [[ "$1" == *"$2"* ]]; }
post() { curl -sS -m "${3:-180}" -X POST -H 'content-type: application/json' -d "$2" "$API$1"; }
guest() {
  local body out
  body="$(python3 -c 'import json,sys; print(json.dumps({"command": sys.argv[1]}))' "$1")"
  for _ in $(seq 1 30); do
    out="$(post "/v1/vms/$vm_id/agent" "$body" 60 | jq_ 'd["stdout"].strip() if d.get("result") == "exec" else exit(1)' 2>/dev/null)" && { printf '%s' "$out"; return 0; }
    sleep 1
  done
  return 1
}

cat > "$root/fluxvm.toml" <<EOF
listen = "127.0.0.1:$PORT"
state_dir = "$root/state"
run_dir = "$root/run"
EOF
[[ -n "$FIRMWARE" ]] && echo "cloud_hypervisor_firmware = \"$FIRMWARE\"" >> "$root/fluxvm.toml"
"$FLUXCTL" --config "$root/fluxvm.toml" serve > "$root/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 60); do curl -fsS -m 2 "$API/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -m 2 "$API/healthz" >/dev/null || { echo "FAIL: daemon unhealthy"; tail -30 "$root/daemon.log"; exit 1; }

spec="$(IMAGE="$IMAGE" KERNEL="$KERNEL" python3 -c '
import json, os
d = {"name": "ch-raw", "backend": "cloud-hypervisor", "image": os.environ["IMAGE"],
  "vcpus": 1, "memory_mib": 1024, "network": {"mode": "none"}, "ttl_seconds": 1800,
  "agent": {"enabled": True}}
if os.environ.get("KERNEL"):
    d["kernel"] = os.environ["KERNEL"]
print(json.dumps(d))')"
resp="$(post /v1/vms "$spec" 180)"
vm_id="$(printf '%s' "$resp" | jq_ 'd["id"]')" || { echo "FAIL: create: $resp"; exit 1; }
echo "vm $vm_id created"

ready=0
for _ in $(seq 1 60); do
  if [[ "$(guest 'echo ok' 2>/dev/null)" == ok ]]; then ready=1; break; fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "FAIL: guest agent never answered"; tail -40 "$root/daemon.log"; exit 1; }
echo "PASS: agent answers on cloud-hypervisor"

post "/v1/vms/$vm_id/snapshot" '{"tag":"manual"}' 120 >/dev/null
check [ "$(guest 'mkdir -p /work; echo y > /work/after-snap; sync; echo ok')" = ok ]
post "/v1/vms/$vm_id/stop" '{}' 60 >/dev/null
t0=$SECONDS
restore_resp="$(post "/v1/vms/$vm_id/restore" '{"tag":"manual"}' 300)"
echo "restore took $((SECONDS - t0))s: ${restore_resp:0:200}"
for _ in $(seq 1 60); do
  if [[ "$(guest 'echo ok' 2>/dev/null)" == ok ]]; then break; fi
  sleep 2
done
after="$(guest 'test -e /work/after-snap && echo present || echo absent')"
echo "restore route: after-snap $after"
check [ "$after" = absent ]

if [[ "$fail" == 0 ]]; then echo "PASS: cloud-hypervisor plain-VM snapshot/restore"; else echo "FAIL: see above"; exit 1; fi
