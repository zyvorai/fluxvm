#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Live single-node check of storage=shared, adopt-mode receivers and the
# read-only serial log, against a running `fluxctl serve`:
#
#   1. QEMU VM on a shared raw disk (netns tap + guest agent); a second VM on
#      the same disk is refused while it runs.
#   2. Loopback live migration: receiver with the source record, activate,
#      migrate, finish (source), adopt (target). The guest's uptime must keep
#      counting across the move, and the disk and lock must survive.
#   3. Delete, then re-create on the same disk with shared_takeover=true.
#   4. Read-only serial bytes from a flux-vm and a Cloud Hypervisor VM.
#
#   FLUXVM_SHARED_IMAGE=/var/lib/fluxvm/images/linux-agent.raw \
#   FLUXVM_QEMU_KERNEL=/var/lib/fluxvm/kernels/bionic-vmlinuz-4.15 \
#   FLUXVM_QEMU_INITRD=/var/lib/fluxvm/kernels/bionic-initrd-4.15 \
#   FLUXVM_KERNEL=/var/lib/fluxvm/kernels/vmlinux \
#   ./scripts/test-live-adopt-smoke.sh
#
# Needs curl, python3, node >= 22 (WebSocket) and write access under
# FLUXVM_SHARED_DIR (default /var/lib/fluxvm/shared).

set -euo pipefail
CODE=; OUT=
if [[ "$(uname -s)" != "Linux" || ! -e /dev/kvm ]]; then
  echo "test-live-adopt-smoke: skipped (Linux/KVM required)"
  exit 0
fi
API=${FLUXVM_API:-http://127.0.0.1:7788}
SRC_IMAGE=${FLUXVM_SHARED_IMAGE:-/var/lib/fluxvm/images/linux-agent.raw}
# QEMU needs a bzImage (or a PVH ELF); the others take the microVM vmlinux.
QEMU_KERNEL=${FLUXVM_QEMU_KERNEL:-/var/lib/fluxvm/kernels/bionic-vmlinuz-4.15}
QEMU_INITRD=${FLUXVM_QEMU_INITRD:-/var/lib/fluxvm/kernels/bionic-initrd-4.15}
KERNEL=${FLUXVM_KERNEL:-/var/lib/fluxvm/kernels/vmlinux}
CH_KERNEL=${FLUXVM_CH_KERNEL:-${KERNEL}}
SHARED_DIR=${FLUXVM_SHARED_DIR:-/var/lib/fluxvm/shared}
SUDO=${SUDO-sudo}
AUTH=()
[[ -n "${FLUXVM_TOKEN:-}" ]] && AUTH=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fail() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "ok   $*"; }
api() { # method path [body] -> sets OUT (body) and CODE (HTTP status)
  local raw
  raw=$(curl -s -w '\n%{http_code}' -X "$1" "${API}$2" "${AUTH[@]}" \
    -H 'Content-Type: application/json' ${3:+-d "$3"})
  CODE=${raw##*$'\n'}
  OUT=${raw%$'\n'*}
}
jget() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(eval("d"+sys.argv[1]))' "$1"; }
mac() { printf '52:54:00:%02x:%02x:%02x' $((RANDOM % 256)) $((RANDOM % 256)) $((RANDOM % 256)); }
CREATED=()
cleanup() {
  for id in "${CREATED[@]}"; do api DELETE "/v1/vms/${id}" >/dev/null || true; done
  [[ -n "${RECV:-}" ]] && api DELETE "/v1/migration/receivers/${RECV}" >/dev/null || true
  ${SUDO} rm -f "${DISK:-/nonexistent}" "${DISK:-/nonexistent}.fluxvm-lock"
}
trap cleanup EXIT

wait_agent() { # id -> waits for the guest agent to answer
  for _ in $(seq 1 90); do
    api POST "/v1/vms/$1/agent" '{"command":"cat /proc/uptime","timeout_seconds":5}'; out=$OUT
    if [[ "$CODE" == 200 ]]; then printf '%s' "$out"; return 0; fi
    sleep 2
  done
  return 1
}
uptime_of() {
  printf '%s' "$1" | python3 -c '
import json, sys
def find(v):
    if isinstance(v, dict):
        if isinstance(v.get("stdout"), str):
            return v["stdout"]
        for x in v.values():
            r = find(x)
            if r is not None:
                return r
print(float(find(json.load(sys.stdin)).split()[0]))'
}

# --- 1. shared disk + lock ----------------------------------------------------
${SUDO} mkdir -p "${SHARED_DIR}"
DISK="${SHARED_DIR}/adopt-smoke-$$.raw"
${SUDO} cp --reflink=auto "${SRC_IMAGE}" "${DISK}"
${SUDO} chmod 0644 "${DISK}"
body=$(cat <<EOF
{"name":"adopt-smoke","backend":"qemu","image":"${DISK}","storage":"shared","vcpus":1,"memory_mib":1024,
 "network":{"mode":"tap","netns":true,"mac":"$(mac)"},"agent":{"enabled":true},
 "kernel":"${QEMU_KERNEL}","initrd":"${QEMU_INITRD}","kernel_args":"console=ttyS0 root=/dev/vda rw"}
EOF
)
api POST /v1/vms "$body"; out=$OUT; [[ "$CODE" == 201 ]] || fail "create shared VM: $CODE $out"
SRC=$(printf '%s' "$out" | jget '["id"]'); CREATED+=("$SRC")
[[ "$(printf '%s' "$out" | jget '["disk"]')" == "${DISK}" ]] || fail "shared disk was cloned"
[[ -f "${DISK}.fluxvm-lock" ]] || fail "no lock next to the shared disk"
ok "shared VM ${SRC} runs in place with a lock"
api POST /v1/vms "${body/adopt-smoke/adopt-smoke-dup}"; out=$OUT
[[ "$CODE" == 400 && "$out" == *"in use by VM"* ]] || fail "second VM on the same disk not refused: $CODE $out"
api GET /v1/vms
dup=$(printf '%s' "$OUT" | python3 -c 'import json,sys; print(" ".join(v["id"] for v in json.load(sys.stdin)["items"] if v["name"]=="adopt-smoke-dup"))')
for id in $dup; do api DELETE "/v1/vms/$id" >/dev/null; done
ok "second VM on the same disk refused"
up1=$(uptime_of "$(wait_agent "$SRC")") || fail "guest agent never answered"
ok "guest up ${up1}s"

# --- 2. loopback migration with adopt ------------------------------------------
api GET "/v1/vms/${SRC}"; record=$OUT
api POST /v1/migration/receivers "{\"record\":${record},\"listen_host\":\"127.0.0.1\",\"listen_port\":0}"; out=$OUT
[[ "$CODE" == 201 ]] || fail "adopt-mode receiver: $CODE $out"
RECV=$(printf '%s' "$out" | jget '["id"]'); TOKEN=$(printf '%s' "$out" | jget '["token"]')
URI=$(printf '%s' "$out" | jget '["uri"]')
api POST "/v1/migration/receivers/${RECV}/activate" "{\"token\":\"${TOKEN}\"}" >/dev/null
[[ "$CODE" == 200 ]] || fail "activate: $CODE"
api POST "/v1/migration/receivers/${RECV}/adopt" "{\"token\":\"${TOKEN}\"}"; out=$OUT
[[ "$CODE" == 409 ]] || fail "adopt before migration should be 409: $CODE $out"
ok "receiver ${RECV} armed at ${URI}; early adopt is 409"
api POST "/v1/vms/${SRC}/migration/start" "{\"destination\":\"${URI}\"}"; out=$OUT
[[ "$CODE" == 200 ]] || fail "migration start: $CODE $out"
for _ in $(seq 1 120); do
  api GET "/v1/vms/${SRC}/migration/status"
  phase=$(printf '%s' "$OUT" | jget '["phase"]')
  [[ "$phase" == completed ]] && break
  [[ "$phase" == failed || "$phase" == cancelled ]] && fail "migration ${phase}"
  sleep 1
done
[[ "$phase" == completed ]] || fail "migration did not complete (${phase})"
ok "migration completed"
api POST "/v1/vms/${SRC}/migration/finish"; out=$OUT; [[ "$CODE" == 200 ]] || fail "finish: $CODE $out"
CREATED=()
api POST "/v1/migration/receivers/${RECV}/adopt" "{\"token\":\"${TOKEN}\"}"; out=$OUT
[[ "$CODE" == 200 ]] || fail "adopt: $CODE $out"
DST=${RECV}; RECV=; CREATED+=("$DST")
[[ "$(printf '%s' "$out" | jget '["status"]')" == running ]] || fail "adopted VM not running"
[[ "$(printf '%s' "$out" | jget '["name"]')" == adopt-smoke ]] || fail "adopted VM lost its name"
api GET "/v1/vms/${SRC}" >/dev/null; [[ "$CODE" != 200 ]] || fail "source record still present"
[[ -f "${DISK}" ]] || fail "finish removed the shared disk"
python3 - "${DISK}.fluxvm-lock" "${DST}" <<'PY' || fail "lock does not name the adopted VM"
import json,sys; assert json.load(open(sys.argv[1]))["vm_id"]==sys.argv[2]
PY
up2=$(uptime_of "$(wait_agent "$DST")") || fail "guest agent silent after adopt"
python3 -c "import sys; sys.exit(0 if $up2 > $up1 else 1)" || fail "guest rebooted (uptime ${up1} -> ${up2})"
ok "adopted ${DST}: same guest (uptime ${up1}s -> ${up2}s), disk and lock kept"

# --- 3. delete + takeover re-create ----------------------------------------------
api DELETE "/v1/vms/${DST}" >/dev/null; CREATED=()
[[ -f "${DISK}" && ! -f "${DISK}.fluxvm-lock" ]] || fail "delete should keep the disk and drop the lock"
api POST "/v1/vms?shared_takeover=true" "$body"; out=$OUT; [[ "$CODE" == 201 ]] || fail "re-create: $CODE $out"
CREATED+=("$(printf '%s' "$out" | jget '["id"]')")
ok "re-created on the same disk (HA path)"

# --- 4. read-only serial for non-QEMU backends ------------------------------------
serial_bytes() { # id -> byte count read within 20 s
  node -e '
    const ws = new WebSocket(process.argv[1]); let n = 0;
    ws.binaryType = "arraybuffer";
    ws.onmessage = (e) => { n += e.data.byteLength ?? String(e.data).length; ws.send("ignored\n"); };
    ws.onerror = () => { console.log(-1); process.exit(0); };
    setTimeout(() => { console.log(n); process.exit(0); }, 20000);
  ' "${API/http/ws}/v1/vms/$1/serial"
}
for hv in flux-vm cloud-hypervisor; do
  k=${KERNEL}; [[ "$hv" == cloud-hypervisor ]] && k=${CH_KERNEL}
  api POST /v1/vms "{\"name\":\"serial-${hv}\",\"backend\":\"${hv}\",\"image\":\"${SRC_IMAGE}\",\"vcpus\":1,\"memory_mib\":512,\"kernel\":\"${k}\",\"network\":{\"mode\":\"none\"}}"; out=$OUT
  [[ "$CODE" == 201 ]] || fail "create ${hv}: $CODE $out"
  id=$(printf '%s' "$out" | jget '["id"]'); CREATED+=("$id")
  n=$(serial_bytes "$id")
  (( n > 0 )) || fail "no console bytes from ${hv} serial (${n})"
  ok "${hv} read-only serial streamed ${n} bytes"
done
echo "test-live-adopt-smoke: PASS"
