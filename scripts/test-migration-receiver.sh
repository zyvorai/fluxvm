#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Opt-in two-host QEMU pre-copy check. Without FLUXVM_MIGRATION_DEST this
# records the contract and exits 0. It does not cold-boot a guest.
#
#   FLUXVM_MIGRATION_DEST=tcp:10.0.0.9:49152 \
#   FLUXVM_MIGRATION_DISK=/mnt/rbd/vm/root.raw \
#   ./scripts/test-migration-receiver.sh

set -euo pipefail
if [[ "$(uname -s)" != "Linux" || ! -e /dev/kvm ]]; then
  echo "test-migration-receiver: skipped (Linux/KVM required for a live receiver)"
  exit 0
fi
if [[ -z "${FLUXVM_MIGRATION_DEST:-}" || -z "${FLUXVM_MIGRATION_DISK:-}" ]]; then
  echo "test-migration-receiver: skipped (set FLUXVM_MIGRATION_DEST and FLUXVM_MIGRATION_DISK)"
  echo "contract=POST /v1/migration/receivers then fluxctl migrate start <id> --destination <uri>"
  echo "refused=direct-datapath, firecracker, cloud-hypervisor status/cancel, in-tree hypervisor"
  exit 0
fi
API=${FLUXVM_API:-http://127.0.0.1:7788}
AUTH=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi
body=$(curl -sf -X POST "${API}/v1/migration/receivers" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"vcpus\":1,\"memory_mib\":128,\"disk\":\"${FLUXVM_MIGRATION_DISK}\",\"disk_format\":\"raw\",\"listen_port\":49152}")
echo "$body"
uri=$(printf '%s' "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["uri"])')
id=$(printf '%s' "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["id"])')
token=$(printf '%s' "$body" | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
echo "receiver_uri=${uri}"
curl -sf -X POST "${API}/v1/migration/receivers/${id}/activate" "${AUTH[@]}" \
  -H 'Content-Type: application/json' \
  -d "{\"token\":\"${token}\"}" >/dev/null
echo "activated=1"
echo "next=fluxctl migrate start <source-id> --destination ${uri}"
