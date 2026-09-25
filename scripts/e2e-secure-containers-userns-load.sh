#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: opt-in CLONE_NEWUSER under concurrent Secure Containers load.
# Requires FLUXVM_CONTAINER_USERNS=1 forwarded into the guest container-agent
# (see shim bootstrap_container_agent).
#
# Default mode is ctr (system containerd): spins N sequential fluxvm tasks and
# checks each printed a user-ns path. Cross-VM inode numbers often collide
# (each guest kernel allocates the same first userns inode), so distinctness
# across pods/VMs is opt-in via FLUXVM_USERNS_REQUIRE_DISTINCT=1 and is only
# meaningful for multi-container-in-one-VM layouts.
#
# Set FLUXVM_USERNS_MODE=k8s to use RuntimeClass pods instead.
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-userns-load: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

MODE="${FLUXVM_USERNS_MODE:-ctr}"
N="${FLUXVM_USERNS_LOAD_N:-3}"
REQUIRE_DISTINCT="${FLUXVM_USERNS_REQUIRE_DISTINCT:-0}"
RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
CTR="${CTR:-ctr}"
ADDR="${CONTAINERD_ADDRESS:-/run/containerd/containerd.sock}"

if [[ "$MODE" == k8s ]]; then
  NS="${1:-default}"
  RC="${2:-fluxvm}"
  PREFIX="fluxvm-userns-load-$$"
  cleanup() {
    for i in $(seq 1 "$N"); do
      kubectl -n "$NS" delete pod "${PREFIX}-${i}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    done
  }
  trap cleanup EXIT
  command -v kubectl >/dev/null
  kubectl get runtimeclass "$RC" >/dev/null
  echo "== userns load (k8s): ${N} concurrent RuntimeClass=${RC} pods (require_distinct=${REQUIRE_DISTINCT}) =="
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
    if ! kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${PREFIX}-${i}" --timeout=300s; then
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
else
  echo "== userns load (ctr): ${N} sequential ${RUNTIME} tasks (require_distinct=${REQUIRE_DISTINCT}) =="
  command -v containerd-shim-fluxvm-v2 >/dev/null
  curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null
  $CTR --address "$ADDR" images pull "$IMAGE" >/dev/null
  ns_list=()
  for i in $(seq 1 "$N"); do
    ID="fluxvm-userns-ctr-$$-$i"
    set +e
    # Write the ns path into the container rootfs (virtiofs share) so we do
    # not depend on ctr stdout, which can hang after a successful workload.
    timeout 120 $CTR --address "$ADDR" run --runtime "$RUNTIME" \
      "$IMAGE" "$ID" \
      /bin/sh -c "readlink /proc/self/ns/user > /ns-user.txt; true" \
      >/tmp/fluxvm-userns-ctr-$$-$i.log 2>&1
    rc=$?
    set -e
    $CTR --address "$ADDR" tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
    $CTR --address "$ADDR" tasks delete --force "$ID" >/dev/null 2>&1 || true
    SHARE="/run/fluxvm/containerd/default/${ID}/share/containers/${ID}/rootfs/ns-user.txt"
    ns=""
    if [[ -f "$SHARE" ]]; then
      ns="$(tr -d ' \n' <"$SHARE")"
    fi
    $CTR --address "$ADDR" containers delete "$ID" >/dev/null 2>&1 || true
    if [[ -z "$ns" ]]; then
      echo "FAIL: no NS_USER at $SHARE for $ID (ctr_rc=$rc)" >&2
      cat "/tmp/fluxvm-userns-ctr-$$-$i.log" >&2 || true
      exit 1
    fi
    echo "  $ID -> $ns"
    ns_list+=("$ns")
  done
fi

[[ "${#ns_list[@]}" -ge 1 ]] || { echo "FAIL: no user-ns samples" >&2; exit 1; }
uniq="$(printf '%s\n' "${ns_list[@]}" | sort -u | wc -l | tr -d ' ')"
if [[ "${#ns_list[@]}" -ge 2 && "$uniq" -lt 2 && "$REQUIRE_DISTINCT" == 1 ]]; then
  echo "FAIL: user ns inodes not distinct (got ${uniq}; only meaningful within one VM)" >&2
  printf '  %s\n' "${ns_list[@]}" >&2
  exit 1
fi

echo "E2E PASS: CLONE_NEWUSER load (${#ns_list[@]} samples; distinct_user_ns=${uniq}; mode=${MODE})"
