#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# S3 — live Policy Observer scrape proving Set 17 fluxvm_prhit directional counters.
#
# Requires: Network Fabric mode ebpf|cilium with fluxvm_tc (+ fluxvm_pod_ingress) installed,
#           a schema-compatible attached VM (or creates a disposable tap/netns one),
#           go toolchain to build tools/fluxvm-policy-observer (or FLUXVM_POLICY_OBSERVER bin).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${FLUXVM_API_URL:-http://127.0.0.1:7788}"
OUT_DIR="${FLUXVM_EVIDENCE_DIR:-$ROOT/docs/benchmarks/evidence}"
mkdir -p "$OUT_DIR"
TS="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$OUT_DIR/sc-live-s3-prhit-${TS}.txt"
LISTEN="${FLUXVM_S3_OBSERVER_LISTEN:-127.0.0.1:9091}"
PIN_ROOT="${FLUXVM_PIN_ROOT:-/sys/fs/bpf/fluxvm}"
META_ROOT="${FLUXVM_META_ROOT:-/run/fluxvm/ebpf/vms}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 2; }; }
need curl; need python3

OBSERVER_BIN="${FLUXVM_POLICY_OBSERVER:-}"
if [[ -z "$OBSERVER_BIN" ]]; then
  need go
  go build -o /tmp/fluxvm-policy-observer-s3 "$ROOT/tools/fluxvm-policy-observer/cmd/fluxvm-policy-observer"
  OBSERVER_BIN=/tmp/fluxvm-policy-observer-s3
fi

CREATED=0
VM_ID="${FLUXVM_S3_VM_ID:-}"
if [[ -z "$VM_ID" ]]; then
  [[ -f /usr/lib/fluxvm/bpf/fluxvm_pod_ingress.bpf.o ]] || {
    echo "missing /usr/lib/fluxvm/bpf/fluxvm_pod_ingress.bpf.o (build-ebpf + install)" >&2
    exit 2
  }
  BRIDGE="${FLUXVM_S3_BRIDGE:-vmbr0}"
  if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    sudo -n ip link add name "$BRIDGE" type bridge
    sudo -n ip link set "$BRIDGE" up
  fi
  SPEC=$(mktemp)
  cat > "$SPEC" <<JSON
{
  "name": "s3-prhit-${TS}",
  "backend": "qemu",
  "image": "${FLUXVM_S3_IMAGE:-/var/lib/fluxvm/images/alpine-test.qcow2}",
  "vcpus": 1,
  "memory_mib": 256,
  "network": {"mode":"tap","netns":true,"bridge":"$BRIDGE","mac":"06:00:ac:10:0b:33"},
  "pod_uid": "s3-prhit-${TS}",
  "ttl_seconds": 900
}
JSON
  OUT_CREATE=$(curl -sS -X POST "$API/v1/vms" -H 'content-type: application/json' --data-binary @"$SPEC")
  rm -f "$SPEC"
  VM_ID=$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("id",""))' <<<"$OUT_CREATE")
  [[ -n "$VM_ID" ]] || { echo "create failed: $OUT_CREATE" >&2; exit 1; }
  CREATED=1
  sleep 3
fi

cleanup() {
  [[ -n "${OBSERVER_PID:-}" ]] && sudo -n kill "$OBSERVER_PID" 2>/dev/null || true
  if [[ "$CREATED" == 1 && "${FLUXVM_S3_KEEP:-0}" != 1 ]]; then
    curl -sS -X DELETE "$API/v1/vms/$VM_ID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

# Apply schema_v2 directional pod policy (creates/uses fluxvm_prhit).
POLICY=$(mktemp)
cat > "$POLICY" <<'JSON'
{
  "schema_version": 2,
  "default_deny": true,
  "ingress_isolated": true,
  "egress_isolated": true,
  "rules": [
    {"direction":"egress","cidr":"10.0.0.0/8","protocol":"tcp","port_start":80,"port_end":80},
    {"direction":"ingress","cidr":"10.0.0.0/8","protocol":"tcp","port_start":8080,"port_end":8080}
  ]
}
JSON
HTTP=$(curl -sS -o /tmp/s3-pod-policy-resp.json -w '%{http_code}' \
  -X POST "$API/v1/vms/$VM_ID/network/pod-policy" \
  -H 'content-type: application/json' --data-binary @"$POLICY")
rm -f "$POLICY"
[[ "$HTTP" == "200" ]] || { echo "pod-policy failed http=$HTTP $(cat /tmp/s3-pod-policy-resp.json)" >&2; exit 1; }

sudo -n "$OBSERVER_BIN" --pin-root "$PIN_ROOT" --meta-root "$META_ROOT" --listen "$LISTEN" \
  >/tmp/fluxvm-s3-observer.log 2>&1 &
OBSERVER_PID=$!
for _ in $(seq 1 15); do
  curl -sf --max-time 1 "http://${LISTEN}/readyz" >/dev/null 2>&1 && break
  sleep 1
done
METRICS=$(curl -sf --max-time 5 "http://${LISTEN}/metrics")

{
  echo "FluxVM S3 live prhit scrape @ $TS"
  echo "vm=$VM_ID listen=$LISTEN"
  echo "=== network/status ==="
  curl -sS "$API/v1/vms/$VM_ID/network/status" || true
  echo
  echo "=== observer series ==="
  grep -E 'directional_counters|hook_attached|packets_total\{|rule_entries|dataplane_schema' <<<"$METRICS" || true
  echo
} | tee "$OUT"

if ! grep -E 'fluxvm_sentinel_policy_directional_counters\{[^}]*\} 1' <<<"$METRICS" >/dev/null; then
  echo "S3 FAIL: directional_counters!=1" | tee -a "$OUT" >&2
  exit 1
fi
if ! grep -E 'fluxvm_sentinel_policy_hook_attached\{[^}]*direction="egress"[^}]*\} 1' <<<"$METRICS" >/dev/null; then
  echo "S3 FAIL: egress hook not attached" | tee -a "$OUT" >&2
  exit 1
fi
if ! grep -E 'fluxvm_sentinel_policy_hook_attached\{[^}]*direction="ingress"[^}]*\} 1' <<<"$METRICS" >/dev/null; then
  echo "S3 FAIL: ingress hook not attached" | tee -a "$OUT" >&2
  exit 1
fi

echo "S3 PRHIT DIRECTIONAL SCRAPE: PASS" | tee -a "$OUT"
echo "wrote $OUT"
