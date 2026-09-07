#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# MicroVM create → Running latency against a live k3s + fluxvm serve stack.
# Requires: kubectl (sudo if needed), fluxvm-microvm controller+node-agent,
#           host image, FLUXVM_TOKEN when auth is on.
#
#   BENCH_N=5 IMAGE=… ./scripts/bench-microvm.sh
#
set -euo pipefail

N="${BENCH_N:-5}"
NS="${MICROVM_BENCH_NS:-default}"
IMG="${IMAGE:-${MICROVM_SMOKE_IMAGE:-/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2}}"
KUBECTL="${KUBECTL:-kubectl}"
PREFIX="bench-mvm-$$"
TIMEOUT_S="${BENCH_TIMEOUT_S:-120}"

if [[ ! -f "$IMG" ]]; then
  IMG="$(ls /var/lib/fluxvm/images/*.qcow2 2>/dev/null | head -1 || true)"
fi
[[ -f "$IMG" ]] || { echo "bench-microvm: IMAGE not found" >&2; exit 1; }

if ! $KUBECTL get nodes >/dev/null 2>&1; then
  if sudo kubectl get nodes >/dev/null 2>&1; then
    KUBECTL="sudo kubectl"
  else
    echo "bench-microvm: kubectl cannot reach cluster" >&2
    exit 1
  fi
fi

echo "== FluxVM MicroVM benchmark (n=${N}, ns=${NS}, image=${IMG}) =="

ms_now() { date +%s%3N; }

wait_phase() {
  local name="$1" want="$2" deadline=$(( $(date +%s) + TIMEOUT_S ))
  while (( $(date +%s) < deadline )); do
    local phase
    phase="$($KUBECTL -n "$NS" get mvm "$name" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    if [[ "$phase" == "$want" ]]; then
      return 0
    fi
    if [[ "$phase" == "Failed" ]]; then
      echo "FAILED phase for $name" >&2
      $KUBECTL -n "$NS" describe mvm "$name" | tail -30 >&2 || true
      return 1
    fi
    sleep 0.25
  done
  echo "timeout waiting for $want on $name (last=$phase)" >&2
  return 1
}

create_one() {
  local name="$1"
  local t0 t_sched t_run
  t0=$(ms_now)
  cat <<YAML | $KUBECTL apply -f - >/dev/null
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVM
metadata:
  name: ${name}
  namespace: ${NS}
spec:
  backend: qemu
  image: ${IMG}
  vcpus: 1
  memoryMib: 1024
  networkMode: user
  ttlSeconds: 120
  persist: false
YAML
  wait_phase "$name" Scheduled
  t_sched=$(ms_now)
  wait_phase "$name" Running
  t_run=$(ms_now)
  echo "create ${name} scheduled_ms=$((t_sched - t0)) running_ms=$((t_run - t0))"
  $KUBECTL -n "$NS" delete mvm "$name" --wait=false >/dev/null 2>&1 || true
}

# drain leftovers
$KUBECTL -n "$NS" delete mvm -l 'app.kubernetes.io/part-of=fluxvm-microvm-bench' --ignore-not-found --wait=false >/dev/null 2>&1 || true
for ((i=1; i<=N; i++)); do
  $KUBECTL -n "$NS" delete mvm "${PREFIX}-${i}" --ignore-not-found --wait=false >/dev/null 2>&1 || true
done
sleep 2

sched_total=0
run_total=0
declare -a run_samples=()
for ((i=1; i<=N; i++)); do
  name="${PREFIX}-${i}"
  line=$(create_one "$name")
  echo "$line"
  s_ms=$(echo "$line" | sed -n 's/.*scheduled_ms=\([0-9]*\).*/\1/p')
  r_ms=$(echo "$line" | sed -n 's/.*running_ms=\([0-9]*\).*/\1/p')
  sched_total=$((sched_total + s_ms))
  run_total=$((run_total + r_ms))
  run_samples+=("$r_ms")
  # brief settle so DELETE doesn't fight the next create
  sleep 1
done

avg_sched=$((sched_total / N))
avg_run=$((run_total / N))

# p50 of running_ms
IFS=$'\n' sorted=($(printf '%s\n' "${run_samples[@]}" | sort -n))
mid=$(( (N - 1) / 2 ))
p50=${sorted[$mid]}

echo "--"
echo "avg_scheduled_ms=${avg_sched}"
echo "avg_running_ms=${avg_run}"
echo "p50_running_ms=${p50}"
echo "image=${IMG}"
echo "n=${N}"
