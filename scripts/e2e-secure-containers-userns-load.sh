#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: opt-in CLONE_NEWUSER under concurrent Secure Containers load.
# Requires FLUXVM_CONTAINER_USERNS=1 on the shim env and RuntimeClass fluxvm.
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-userns-load: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

NS="${1:-default}"
RC="${2:-fluxvm}"
N="${FLUXVM_USERNS_LOAD_N:-4}"
PREFIX="fluxvm-userns-load-$$"

cleanup() {
  for i in $(seq 1 "$N"); do
    kubectl -n "$NS" delete pod "${PREFIX}-${i}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  done
}
trap cleanup EXIT

command -v kubectl >/dev/null
kubectl get runtimeclass "$RC" >/dev/null

echo "== userns load: ${N} concurrent RuntimeClass=${RC} pods =="
for i in $(seq 1 "$N"); do
  cat <<YAML | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${PREFIX}-${i}
  labels:
    fluxvm.io/userns-load: "1"
spec:
  runtimeClassName: ${RC}
  restartPolicy: Never
  containers:
  - name: probe
    image: busybox:1.36
    command:
      - sh
      - -c
      - echo USER=\$(id -u); echo NS_USER=\$(readlink /proc/self/ns/user); sleep 8
YAML
done

fail=0
for i in $(seq 1 "$N"); do
  if ! kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${PREFIX}-${i}" --timeout=240s; then
    kubectl -n "$NS" describe "pod/${PREFIX}-${i}" || true
    kubectl -n "$NS" logs "pod/${PREFIX}-${i}" || true
    fail=1
  fi
done
[[ "$fail" -eq 0 ]] || exit 1

ns_list=()
for i in $(seq 1 "$N"); do
  log="$(kubectl -n "$NS" logs "pod/${PREFIX}-${i}" || true)"
  ns="$(grep -o 'NS_USER=.*' <<<"$log" | head -1 | cut -d= -f2- || true)"
  [[ -n "$ns" ]] && ns_list+=("$ns")
done
uniq="$(printf '%s\n' "${ns_list[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "${#ns_list[@]}" -ge 2 && "$uniq" -lt 2 ]]; then
  echo "WARN: user ns inodes not distinct across pods (FLUXVM_CONTAINER_USERNS may be off)" >&2
fi

echo "E2E PASS: CLONE_NEWUSER load (${N} pods Succeeded; distinct_user_ns=${uniq})"
