#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Opt-in, root-only lab test: VM sandbox dry-run and explicit snapshot/restore
# for a non-flux-vm backend (QEMU or Firecracker), reached through an
# operator template (client specs always force flux-vm). Starts its own
# throwaway daemon (own state dirs, own port, network.mode=none); never
# touches the host's fluxvm service or a real bridge.
#
#   sudo env FLUXCTL=... BACKEND=qemu IMAGE=/var/lib/fluxvm/images/foo.qcow2 \
#     bash scripts/test-vm-dry-run-multi.sh
set -euo pipefail

FLUXCTL="${FLUXCTL:-fluxctl}"
BACKEND="${BACKEND:?set BACKEND=qemu or firecracker}"
IMAGE="${IMAGE:?set IMAGE=/path/to/bootable/image}"
KERNEL="${KERNEL:-}"
PORT="${PORT:-17791}"
ROUNDS="${ROUNDS:-3}"
API="http://127.0.0.1:$PORT"

[[ $EUID -eq 0 ]] || { echo "FAIL: run as root (KVM + state dirs)" >&2; exit 2; }
[[ -e /dev/kvm && -f "$IMAGE" ]] || { echo "SKIP: KVM or image missing" >&2; exit 2; }
if [[ "$BACKEND" == firecracker && ! -f "$KERNEL" ]]; then
  echo "SKIP: firecracker needs KERNEL=" >&2; exit 2
fi

root="$(mktemp -d /var/tmp/fluxvm-dryrun-multi.XXXXXX)"
mkdir -p "$root/state" "$root/run" "$root/state/templates/t/"
daemon_pid=""
vm_id=""
fail=0

cleanup() {
  local rc=$?
  if [[ $rc -ne 0 || $fail -ne 0 ]]; then
    rm -rf /var/tmp/fluxvm-dryrun-multi-last; mkdir -p /var/tmp/fluxvm-dryrun-multi-last
    cp "$root/daemon.log" /var/tmp/fluxvm-dryrun-multi-last/ 2>/dev/null || true
    find "$root/state" -name '*.log' -exec cp {} /var/tmp/fluxvm-dryrun-multi-last/ \; 2>/dev/null || true
    echo "logs kept in /var/tmp/fluxvm-dryrun-multi-last"
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
EOF

kernel_json=""
[[ -n "$KERNEL" ]] && kernel_json=", \"kernel\": \"$KERNEL\""
cat > "$root/state/templates/t/spec.json" <<EOF
{"name": "t", "backend": "$BACKEND", "image": "$IMAGE", "vcpus": 1,
 "memory_mib": 1024, "network": {"mode": "none"}, "ttl_seconds": 1800,
 "agent": {"enabled": true}$kernel_json}
EOF

"$FLUXCTL" --config "$root/fluxvm.toml" serve > "$root/daemon.log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 60); do curl -fsS -m 2 "$API/healthz" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS -m 2 "$API/healthz" >/dev/null || { echo "FAIL: daemon unhealthy"; tail -30 "$root/daemon.log"; exit 1; }

resp="$(post /v1/sandboxes '{"template":"t"}' 180)"
vm_id="$(printf '%s' "$resp" | jq_ 'd["id"]')" || { echo "FAIL: create: $resp"; exit 1; }
backend_got="$(printf '%s' "$resp" | jq_ 'd["backend"]')"
echo "sandbox $vm_id backend=$backend_got"
check [ "$backend_got" = "$BACKEND" ]

ready=0
for _ in $(seq 1 60); do
  if [[ "$(guest 'echo ok' 2>/dev/null)" == ok ]]; then ready=1; break; fi
  sleep 2
done
[[ "$ready" == 1 ]] || { echo "FAIL: guest agent never answered"; tail -30 "$root/daemon.log"; exit 1; }
echo "PASS: agent answers on $BACKEND"

guest 'mkdir -p /work && echo keep > /work/marker' >/dev/null

for round in $(seq 1 "$ROUNDS"); do
  t0=$SECONDS
  report="$(post "/v1/sandboxes/$vm_id/dry-run" '{"command":"echo x > /work/new; rm /work/marker; echo done","paths":["/work"]}' 240)"
  dt=$((SECONDS - t0))
  echo "raw report: $report" >&2
  discarded="$(printf '%s' "$report" | jq_ 'd.get("discarded")' 2>/dev/null || echo ERR)"
  via="$(printf '%s' "$report" | jq_ 'd.get("reverted_via")' 2>/dev/null || echo ERR)"
  added="$(printf '%s' "$report" | jq_ 'd["changes"]["added"]' 2>/dev/null || echo ERR)"
  deleted="$(printf '%s' "$report" | jq_ 'd["changes"]["deleted"]' 2>/dev/null || echo ERR)"
  gone="$(guest 'test ! -e /work/new && test -e /work/marker && echo yes || echo no')"
  state="$(curl -fsS "$API/v1/vms/$vm_id" | jq_ 'd.get("status")')"
  echo "round $round (${dt}s): discarded=$discarded via=$via added=$added deleted=$deleted new_gone_marker_back=$gone status=$state"
  check [ "$discarded" = True ]
  check has "$added" /work/new
  check has "$deleted" /work/marker
  check [ "$gone" = yes ]
  check [ "$state" = running ]
done

left="$(find "$root/state" -path '*/snapshots/dryrun-*' -maxdepth 6 2>/dev/null | wc -l)"
check [ "$left" = 0 ]
echo "dry-run snapshot dirs left: $left"

# The explicit restore route on a *running* non-flux-vm VM must refuse (409),
# telling the caller to stop it first -- no silent relaunch behind their back.
code="$(curl -sS -o /dev/null -w '%{http_code}' -X POST -H 'content-type: application/json' -d '{"tag":"nope"}' "$API/v1/vms/$vm_id/restore")"
check [ "$code" = 409 ]
echo "restore-while-running correctly refused: $code"

# Stop, then use the explicit route: snapshot, mutate on the stopped image is
# not possible, so snapshot -> stop -> mutate isn't meaningful here; instead
# prove stop -> snapshot -> start -> mutate -> stop -> restore -> start.
post "/v1/vms/$vm_id/snapshot" '{"tag":"manual"}' 120 >/dev/null
check [ "$(guest 'echo y > /work/after-snap; sync; echo ok')" = ok ]
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

if [[ "$fail" == 0 ]]; then echo "PASS: $BACKEND VM sandbox dry-run + explicit restore route"; else echo "FAIL: see above"; exit 1; fi
