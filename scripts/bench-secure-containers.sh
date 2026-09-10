#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Secure Containers cold-boot latency benchmark: `ctr run` to a completed
# task against a live containerd + FluxVM + fluxvm-container-agent stack.
# Requires Linux + KVM + containerd with the fluxvm runtime registered (see
# scripts/install-secure-containers.sh / deploy/containerd/README.md).
#
# Each iteration uses a fresh `--group` value so every run cold-boots a new
# Pod VM (the default one-shim-per-invocation behavior of bare `ctr run`
# already does this) — this measures the P1 performance gap
# docs/secure-containers.md tracks: today there is no warm-pool reuse
# (see docs/secure-containers-set7r.md), so every Pod pays the full cold-boot
# cost. Re-run after that lands to compare cold-boot vs pool-claim latency.
#
#   BENCH_N=5 ./scripts/bench-secure-containers.sh
#
set -euo pipefail

N="${BENCH_N:-5}"
RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-secure-containers: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi
for cmd in ctr containerd-shim-fluxvm-v2; do
  command -v "$cmd" >/dev/null || { echo "bench-secure-containers: missing $cmd" >&2; exit 1; }
done
[[ -e /dev/kvm ]] || { echo "bench-secure-containers: /dev/kvm missing" >&2; exit 1; }
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null \
  || { echo "bench-secure-containers: FluxVM API unreachable" >&2; exit 1; }

echo "== FluxVM Secure Containers cold-boot benchmark (n=${N}, runtime=${RUNTIME}, image=${IMAGE}) =="
ctr images pull "$IMAGE" >/dev/null

run_one() {
  local t0 t1 ms id
  id="bench-secure-$$-$RANDOM"
  t0=$(date +%s%3N)
  if ! ctr run --rm --runtime "$RUNTIME" "$IMAGE" "$id" /bin/sh -c 'true' >/dev/null 2>&1; then
    echo "run failed for $id" >&2
    return 1
  fi
  t1=$(date +%s%3N)
  ms=$((t1 - t0))
  echo "run ${id} ${ms}ms"
}

total=0
ok=0
for ((i = 1; i <= N; i++)); do
  line=$(run_one) || continue
  echo "$line"
  ms=$(echo "$line" | awk '{print $3}' | tr -d ms)
  total=$((total + ms))
  ok=$((ok + 1))
done

if (( ok == 0 )); then
  echo "bench-secure-containers: every run failed" >&2
  exit 1
fi
avg=$((total / ok))
echo "--"
echo "avg_run_ms=${avg} (n=${ok}/${N})"
echo "image=${IMAGE}"
