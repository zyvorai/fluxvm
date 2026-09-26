#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: opt-in CLONE_NEWUSER under concurrent Secure Containers load.
# Requires FLUXVM_CONTAINER_USERNS=1 forwarded into the guest container-agent
# (see shim bootstrap_container_agent).
#
# Modes:
#   ctr         — N sequential fluxvm tasks (one VM each). Cross-VM inode
#                 collision is expected; distinctness gate is off by default.
#   ctr-shared  — N tasks sharing io.containerd.runc.v2.group (one VM).
#                 FLUXVM_USERNS_REQUIRE_DISTINCT defaults to 1.
#   k8s         — RuntimeClass pods (one container each).
#   k8s-multi   — one RuntimeClass pod with N containers (same VM).
#                 FLUXVM_USERNS_REQUIRE_DISTINCT defaults to 1.
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-userns-load: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

MODE="${FLUXVM_USERNS_MODE:-ctr}"
N="${FLUXVM_USERNS_LOAD_N:-3}"
RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/sc-ctr-env.sh"
ADDR="${CONTAINERD_ADDRESS}"

case "$MODE" in
  ctr-shared|k8s-multi)
    REQUIRE_DISTINCT="${FLUXVM_USERNS_REQUIRE_DISTINCT:-1}"
    ;;
  *)
    REQUIRE_DISTINCT="${FLUXVM_USERNS_REQUIRE_DISTINCT:-0}"
    ;;
esac

if [[ "$MODE" == k8s || "$MODE" == k8s-multi ]]; then
  NS="${1:-default}"
  RC="${2:-fluxvm}"
  PREFIX="fluxvm-userns-load-$$"
  cleanup() {
    if [[ "$MODE" == k8s-multi ]]; then
      kubectl -n "$NS" delete pod "${PREFIX}-multi" --ignore-not-found --wait=false >/dev/null 2>&1 || true
    else
      for i in $(seq 1 "$N"); do
        kubectl -n "$NS" delete pod "${PREFIX}-${i}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
      done
    fi
  }
  trap cleanup EXIT
  command -v kubectl >/dev/null
  kubectl get runtimeclass "$RC" >/dev/null

  if [[ "$MODE" == k8s-multi ]]; then
    echo "== userns load (k8s-multi): 1 pod / ${N} containers RuntimeClass=${RC} (require_distinct=${REQUIRE_DISTINCT}) =="
    {
      echo "apiVersion: v1"
      echo "kind: Pod"
      echo "metadata:"
      echo "  name: ${PREFIX}-multi"
      echo "  labels:"
      echo "    fluxvm.io/userns-load: \"1\""
      echo "spec:"
      echo "  runtimeClassName: ${RC}"
      echo "  restartPolicy: Never"
      echo "  containers:"
      for i in $(seq 1 "$N"); do
        cat <<YAML
  - name: probe-${i}
    image: busybox:1.36
    command:
      - sh
      - -c
      - echo USER=\$(id -u); echo NS_USER=\$(readlink /proc/self/ns/user); sleep 12
YAML
      done
    } | kubectl -n "$NS" apply -f -
    if ! kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${PREFIX}-multi" --timeout=420s; then
      kubectl -n "$NS" describe "pod/${PREFIX}-multi" || true
      kubectl -n "$NS" logs "pod/${PREFIX}-multi" --all-containers=true || true
      exit 1
    fi
    ns_list=()
    for i in $(seq 1 "$N"); do
      log="$(kubectl -n "$NS" logs "pod/${PREFIX}-multi" -c "probe-${i}" || true)"
      ns="$(grep -o 'NS_USER=.*' <<<"$log" | head -1 | cut -d= -f2- || true)"
      [[ -n "$ns" ]] && ns_list+=("$ns")
      echo "  probe-${i} -> ${ns:-<missing>}"
    done
  else
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
  fi
elif [[ "$MODE" == ctr-shared ]]; then
  GROUP="fluxvm-userns-shared-$$"
  echo "== userns load (ctr-shared): ${N} tasks group=${GROUP} (require_distinct=${REQUIRE_DISTINCT}) =="
  command -v containerd-shim-fluxvm-v2 >/dev/null
  curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null
  $CTR --address "$ADDR" images pull "$IMAGE" >/dev/null
  ids=()
  cleanup() {
    for ID in "${ids[@]:-}"; do
      $CTR --address "$ADDR" tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
      $CTR --address "$ADDR" tasks delete --force "$ID" >/dev/null 2>&1 || true
      $CTR --address "$ADDR" containers delete "$ID" >/dev/null 2>&1 || true
    done
  }
  trap cleanup EXIT
  ns_list=()
  for i in $(seq 1 "$N"); do
    ID="fluxvm-userns-share-$$-$i"
    ids+=("$ID")
    set +e
    # Keep the first N-1 containers alive so the shared sandbox stays up.
    if [[ "$i" -lt "$N" ]]; then
      cmd='readlink /proc/self/ns/user > /ns-user.txt; sleep 90; true'
    else
      cmd='readlink /proc/self/ns/user > /ns-user.txt; true'
    fi
    timeout -k 5 180 $CTR --address "$ADDR" run --runtime "$RUNTIME" \
      --annotation "io.containerd.runc.v2.group=${GROUP}" \
      "$IMAGE" "$ID" \
      /bin/sh -c "$cmd" \
      >/tmp/fluxvm-userns-share-$$-$i.log 2>&1 &
    cpid=$!
    # Wait until ns-user.txt appears (or the process exits).
    SHARE="/run/fluxvm/containerd/default/${GROUP}/share/containers/${ID}/rootfs/ns-user.txt"
    for _ in $(seq 1 90); do
      if [[ -f "$SHARE" ]]; then
        break
      fi
      if ! kill -0 "$cpid" 2>/dev/null; then
        break
      fi
      sleep 2
    done
    set -e
    ns=""
    if [[ -f "$SHARE" ]]; then
      ns="$(tr -d ' \n' <"$SHARE")"
    fi
    if [[ -z "$ns" ]]; then
      echo "FAIL: no NS_USER at $SHARE for $ID" >&2
      cat "/tmp/fluxvm-userns-share-$$-$i.log" >&2 || true
      wait "$cpid" 2>/dev/null || true
      exit 1
    fi
    echo "  $ID -> $ns"
    ns_list+=("$ns")
    if [[ "$i" -eq "$N" ]]; then
      wait "$cpid" 2>/dev/null || true
    fi
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
    # -k: ctr/shim teardown can ignore the first SIGTERM (same as e2e-ctr).
    timeout -k 5 120 $CTR --address "$ADDR" run --runtime "$RUNTIME" \
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
