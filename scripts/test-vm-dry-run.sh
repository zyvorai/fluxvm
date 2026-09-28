#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Opt-in, root-only lab test: dry-run against a native-KVM VM sandbox reverts
# BOTH guest memory and disk. Starts its own throwaway daemon (own state dirs,
# own port); never touches the host's fluxvm service.
#
#   sudo env FLUXCTL=... FLUXVM_HYPERVISOR=... bash scripts/test-vm-dry-run.sh
set -euo pipefail

FLUXCTL="${FLUXCTL:-fluxctl}"
HYP="${FLUXVM_HYPERVISOR:-fluxvm-hypervisor}"
KERNEL="${KERNEL:-/var/lib/fluxvm/kernels/vmlinux-5.10.225-no-acpi}"
ROOTFS="${ROOTFS:-/var/lib/fluxvm/images/linux-agent.raw}"
PORT="${PORT:-17790}"
ROUNDS="${ROUNDS:-5}"
API="http://127.0.0.1:$PORT"

[[ $EUID -eq 0 ]] || { echo "FAIL: run as root (KVM + state dirs)" >&2; exit 2; }
[[ -e /dev/kvm && -f "$KERNEL" && -f "$ROOTFS" ]] || { echo "SKIP: KVM or golden template missing" >&2; exit 2; }

root="$(mktemp -d /var/tmp/fluxvm-dryrun.XXXXXX)"
mkdir -p "$root/state" "$root/run"
daemon_pid=""
vm_id=""
fail=0
rootfs_sum="$(sha256sum "$ROOTFS" | cut -d' ' -f1)"

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 || $fail -ne 0 ]]; then
    rm -rf /var/tmp/fluxvm-dryrun-last; mkdir -p /var/tmp/fluxvm-dryrun-last
    cp "$root/daemon.log" /var/tmp/fluxvm-dryrun-last/ 2>/dev/null || true
    find "$root/state" -name '*.log' -exec cp {} /var/tmp/fluxvm-dryrun-last/ \; 2>/dev/null || true
    echo "logs kept in /var/tmp/fluxvm-dryrun-last"
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
    out="$(post "/v1/sandboxes/$vm_id/process" "$body" 60 | jq_ 'd["stdout"].strip() if d.get("result") == "exec" else exit(1)' 2>/dev/null)" && { printf '%s' "$out"; return 0; }
    sleep 1
  done
  return 1
}

cat > "$root/fluxvm.toml" <<EOF
listen = "127.0.0.1:$PORT"
state_dir = "$root/state"
run_dir = "$root/run"
fluxvm_engine = "kvm"
fluxvm_kernel = "$KERNEL"
fluxvm_hypervisor_binary = "$HYP"
EOF
"$FLUXCTL" --config "$root/fluxvm.toml" serve > "$root/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 60); do curl -fsS -m 2 "$API/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -m 2 "$API/healthz" >/dev/null || { echo "FAIL: daemon unhealthy"; tail -30 "$root/daemon.log"; exit 1; }

spec="$(KERNEL="$KERNEL" ROOTFS="$ROOTFS" python3 -c '
import json, os
print(json.dumps({"name": "dry-run-live", "spec": {
    "name": "dry-run-live", "backend": "flux-vm", "image": os.environ["ROOTFS"],
    "kernel": os.environ["KERNEL"], "vcpus": 1, "memory_mib": 512,
    "network": {"mode": "none"}, "ttl_seconds": 1800,
    "agent": {"enabled": True}, "cloud_init": {"hostname": "dry-run-live"}}}))')"
resp="$(post /v1/sandboxes "$spec" 120)"
vm_id="$(printf '%s' "$resp" | jq_ 'd["id"]')" || { echo "FAIL: create: $resp"; exit 1; }
echo "sandbox $vm_id"

ready=0
for _ in $(seq 1 45); do
  if [[ "$(guest 'echo ok' 2>/dev/null)" == ok ]]; then ready=1; break; fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "FAIL: guest agent never answered"; tail -30 "$root/daemon.log"; exit 1; }
echo "PASS: agent answers"

guest 'mkdir -p /work && echo keep > /work/marker && printf 0 > /work/counter && (setsid sh -c "i=0; while :; do i=\$((i+1)); echo \$i > /work/c.tmp; mv /work/c.tmp /work/counter; sleep 1; done" >/dev/null 2>&1 </dev/null &) ; sleep 1; echo started' >/dev/null
post "/v1/sandboxes/$vm_id/baseline" '{"paths":["/work"]}' 60 >/dev/null

for round in $(seq 1 "$ROUNDS"); do
  c0="$(guest 'cat /work/counter')"
  report="$(post "/v1/sandboxes/$vm_id/dry-run" '{"command":"echo x > /work/new; rm /work/marker; sleep 10; cat /work/counter","paths":["/work"]}' 240)"
  [[ "$report" == *'"discarded"'* ]] || echo "raw: ${report:0:400}"
  discarded="$(printf '%s' "$report" | jq_ 'd.get("discarded")' 2>/dev/null || echo ERR)"
  via="$(printf '%s' "$report" | jq_ 'd.get("reverted_via")' 2>/dev/null || echo ERR)"
  added="$(printf '%s' "$report" | jq_ 'd["changes"]["added"]' 2>/dev/null || echo ERR)"
  deleted="$(printf '%s' "$report" | jq_ 'd["changes"]["deleted"]' 2>/dev/null || echo ERR)"
  inside="$(printf '%s' "$report" | jq_ 'd.get("stdout","").strip()' 2>/dev/null || echo ERR)"
  gone="$(guest 'test ! -e /work/new && test -e /work/marker && echo yes || echo no')"
  c1="$(guest 'cat /work/counter')"
  sleep 3
  c2="$(guest 'cat /work/counter')"
  state="$(curl -fsS "$API/v1/vms/$vm_id" | jq_ 'd.get("status")')"
  echo "round $round: discarded=$discarded via=$via added=$added deleted=$deleted c0=$c0 inside_end=$inside (rewound if c1 << inside_end) c1=$c1 c2=$c2 new_gone_marker_back=$gone status=$state"
  check [ "$discarded" = True ]
  check [ "$via" = snapshot ]
  check has "$added" /work/new
  check has "$deleted" /work/marker
  check [ "$gone" = yes ]
  check [ "$state" = running ]
  check [ "$c1" -le $((inside - 5)) ]
  check [ "$c2" -gt "$c1" ]
done

left="$(find "$root/state" -path '*/snapshots/dryrun-*' -maxdepth 6 2>/dev/null | wc -l)"
check [ "$left" = 0 ]
echo "dry-run snapshot dirs left: $left"

# The explicit restore route: snapshot, mutate, restore.
post "/v1/vms/$vm_id/snapshot" '{"tag":"manual"}' 120 >/dev/null
check [ "$(guest 'echo y > /work/after-snap; sync; echo ok')" = ok ]
t0=$SECONDS
post "/v1/vms/$vm_id/restore" '{"tag":"manual"}' 300 >/dev/null
echo "restore took $((SECONDS - t0))s"
after="$(guest 'test -e /work/after-snap && echo present || echo absent')"
echo "restore route: after-snap $after"
check [ "$after" = absent ]
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{"tag":"nope"}' "$API/v1/vms/$vm_id/restore")"
check [ "$code" = 404 ]

check [ "$(sha256sum "$ROOTFS" | cut -d' ' -f1)" = "$rootfs_sum" ]
if [[ "$fail" == 0 ]]; then echo "PASS: VM dry-run reverts memory and disk ($ROUNDS rounds)"; else echo "FAIL: see above"; exit 1; fi
