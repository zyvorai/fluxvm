#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Hardware-gated GPU passthrough lifecycle check.
# Soft-skips when the host has no NVIDIA/AMD GPU, IOMMU, or vfio-pci.
#
# Env:
#   FLUXVM_URL   default http://127.0.0.1:8080
#   TOKEN        optional bearer token
#   GPU_BDF      optional; otherwise first free inventory entry
#   IMAGE        QEMU disk image path (required when a GPU is present)
#   SKIP_VM=1    inventory + preflight only (no create/reboot/delete)
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FLUXVM_URL="${FLUXVM_URL:-http://127.0.0.1:8080}"
AUTH=()
if [[ -n "${TOKEN:-}" ]]; then
  AUTH=(-H "Authorization: Bearer ${TOKEN}")
fi

curl_json() {
  local method="$1" path="$2"
  shift 2
  curl -fsS -X "$method" "${AUTH[@]}" -H "Content-Type: application/json" \
    "${FLUXVM_URL}${path}" "$@"
}

echo "== GPU preflight =="
if ! preflight="$(curl_json GET /v1/host/gpus/preflight 2>/dev/null)"; then
  echo "SKIP: FluxVM not reachable at ${FLUXVM_URL}"
  exit 0
fi
echo "$preflight" | python3 -m json.tool

gpu_count="$(echo "$preflight" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("gpu_count",0))')"
if [[ "$gpu_count" -eq 0 ]]; then
  echo "SKIP: no GPUs reported by /v1/host/gpus/preflight"
  exit 0
fi

echo "== GPU inventory =="
inventory="$(curl_json GET /v1/host/gpus)"
echo "$inventory" | python3 -m json.tool

BDF="${GPU_BDF:-}"
if [[ -z "$BDF" ]]; then
  BDF="$(echo "$inventory" | python3 -c '
import json,sys
items=json.load(sys.stdin).get("items",[])
for g in items:
    if not g.get("group_held"):
        print(g["bdf"]); break
')"
fi
if [[ -z "$BDF" ]]; then
  echo "SKIP: no free GPU in inventory"
  exit 0
fi
echo "Using BDF=${BDF}"

echo "== Bind whole IOMMU group =="
curl_json POST /v1/host/gpus/bind -d "{\"bdf\":\"${BDF}\",\"vram_gib\":24}" | python3 -m json.tool

if [[ "${SKIP_VM:-0}" == "1" ]]; then
  echo "== Release (restore_driver=false) =="
  curl_json POST /v1/host/gpus/release -d "{\"bdf\":\"${BDF}\",\"restore_driver\":false}" | python3 -m json.tool
  echo "OK: inventory/bind/release without VM"
  exit 0
fi

IMAGE="${IMAGE:-}"
if [[ -z "$IMAGE" || ! -f "$IMAGE" ]]; then
  echo "SKIP: IMAGE not set or missing; bind succeeded, releasing without VM lifecycle"
  curl_json POST /v1/host/gpus/release -d "{\"bdf\":\"${BDF}\",\"restore_driver\":false}" >/dev/null
  exit 0
fi

NAME="gpu-lifecycle-$$"
echo "== Create QEMU VM with vfio_devices =="
create="$(curl_json POST /v1/vms -d "{
  \"name\": \"${NAME}\",
  \"backend\": \"qemu\",
  \"image\": \"${IMAGE}\",
  \"vcpus\": 2,
  \"memory_mib\": 2048,
  \"network\": {\"mode\": \"none\"},
  \"vfio_devices\": [\"${BDF}\"]
}")"
VM_ID="$(echo "$create" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')"
echo "VM_ID=${VM_ID}"

cleanup() {
  curl -fsS -X DELETE "${AUTH[@]}" "${FLUXVM_URL}/v1/vms/${VM_ID}" >/dev/null 2>&1 || true
  curl_json POST /v1/host/gpus/release -d "{\"bdf\":\"${BDF}\",\"restore_driver\":false}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "== Stop / start (reboot) =="
curl_json POST "/v1/vms/${VM_ID}/stop" -d '{}' >/dev/null || true
sleep 2
curl_json POST "/v1/vms/${VM_ID}/start" -d '{}' | python3 -m json.tool >/dev/null

echo "== Delete VM =="
curl -fsS -X DELETE "${AUTH[@]}" "${FLUXVM_URL}/v1/vms/${VM_ID}" >/dev/null
trap - EXIT

echo "== Assert group not held, then release =="
sleep 1
after="$(curl_json GET /v1/host/gpus)"
held="$(echo "$after" | python3 -c "
import json,sys
bdf='${BDF}'
for g in json.load(sys.stdin).get('items',[]):
    if g['bdf']==bdf:
        print('yes' if g.get('group_held') else 'no'); break
else:
    print('missing')
")"
if [[ "$held" != "no" ]]; then
  echo "FAIL: GPU ${BDF} still held after VM delete (held=${held})"
  exit 1
fi
curl_json POST /v1/host/gpus/release -d "{\"bdf\":\"${BDF}\",\"restore_driver\":false}" | python3 -m json.tool
echo "OK: GPU lifecycle create/reboot/delete/release"
