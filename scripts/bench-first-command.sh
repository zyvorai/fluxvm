#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# First-command latency: time from API request start to the first successful
# guest-agent exec, for cold creates, warm-pool claims and forks. Uses the
# server-side `?ready=exec` flag, so `first_command_ms` is measured by the
# server from request receipt (not by curl). Prints p50/p95 as JSON.
#
#   N=10 IMAGE=/var/lib/fluxvm/images/base.raw POOL=bench FORK_SRC=<uuid> \
#     ./scripts/bench-first-command.sh
#
# Sections are skipped when their input is missing: warm claims need POOL
# (an existing pool with >= N ready members), forks need FORK_SRC (a running
# flux-vm VM; it is never deleted). Only VMs this script created are deleted.
set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-first-command: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi
[[ -e /dev/kvm ]] || { echo "bench-first-command: /dev/kvm missing (skipped)" >&2; exit 0; }

API="${FLUXVM_API:-http://127.0.0.1:7788}"
N="${N:-5}"
IMAGE="${IMAGE:-${FLUXVM_BENCH_IMAGE:-/var/lib/fluxvm/images/base.raw}}"
KERNEL="${KERNEL:-${FLUXVM_BENCH_KERNEL:-/var/lib/fluxvm/kernels/vmlinux}}"
MEM_MIB="${MEM_MIB:-256}"
POOL="${POOL:-}"
FORK_SRC="${FORK_SRC:-}"
PREFIX="firstcmd-$$"
AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi

curl -sf "${API}/readyz" "${AUTH_HDR[@]}" >/dev/null || {
  echo "bench-first-command: ${API}/readyz is not up" >&2
  exit 1
}

WORKDIR=$(mktemp -d)
CREATED_IDS=()
cleanup() {
  local id
  # Only ids this script created; never delete by pattern.
  for id in "${CREATED_IDS[@]}"; do
    curl -sf -X DELETE "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" >/dev/null 2>&1 || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

KERNEL_JSON="null"
if [[ -f "$KERNEL" ]]; then
  KERNEL_JSON=$(printf '%s' "$KERNEL" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read().rstrip("\n")))')
fi

# post <path> <json-body>: POST and print the response body (empty on failure).
post() {
  curl -sf -X POST "${API}$1" "${AUTH_HDR[@]}" -H 'Content-Type: application/json' -d "$2" || true
}

# record <section-file> <body>: append first_command_ms, track created ids.
record() {
  local file="$1" body="$2" id ms
  if ! printf '%s' "$body" | python3 -c '
import json, sys
d = json.load(sys.stdin)
ids = [i["id"] for i in d.get("items", [])] if "items" in d else [d.get("id")]
print("IDS " + " ".join(i for i in ids if i))
ms = d.get("first_command_ms")
if ms is not None:
    print("MS %d" % ms)
' >"$WORKDIR/rec.txt" 2>/dev/null; then
    echo "failed" >>"$file"
    return 0
  fi
  for id in $(awk '$1=="IDS" {for (i=2;i<=NF;i++) print $i}' "$WORKDIR/rec.txt"); do
    CREATED_IDS+=("$id")
  done
  ms=$(awk '$1=="MS" {print $2}' "$WORKDIR/rec.txt")
  if [[ -n "$ms" ]]; then echo "$ms" >>"$file"; else echo "failed" >>"$file"; fi
}

: >"$WORKDIR/cold.txt"
: >"$WORKDIR/warm.txt"
: >"$WORKDIR/fork.txt"

if [[ -f "$IMAGE" ]]; then
  for ((i = 1; i <= N; i++)); do
    name="${PREFIX}-cold-${i}"
    body=$(post "/v1/vms?ready=exec" "{\"name\":\"${name}\",\"backend\":\"flux-vm\",\"image\":\"${IMAGE}\",\"kernel\":${KERNEL_JSON},\"vcpus\":1,\"memory_mib\":${MEM_MIB}}")
    record "$WORKDIR/cold.txt" "$body"
  done
else
  echo "bench-first-command: IMAGE not found, skipping cold: $IMAGE" >&2
fi

if [[ -n "$POOL" ]]; then
  for ((i = 1; i <= N; i++)); do
    body=$(post "/v1/pools/${POOL}/claim?ready=exec" "{\"name\":\"${PREFIX}-warm-${i}\"}")
    record "$WORKDIR/warm.txt" "$body"
  done
else
  echo "bench-first-command: POOL unset, skipping warm claims" >&2
fi

if [[ -n "$FORK_SRC" ]]; then
  for ((i = 1; i <= N; i++)); do
    body=$(post "/v1/vms/${FORK_SRC}/fork?ready=exec" "{\"count\":1,\"namePrefix\":\"${PREFIX}-fork-${i}\"}")
    record "$WORKDIR/fork.txt" "$body"
  done
else
  echo "bench-first-command: FORK_SRC unset, skipping forks" >&2
fi

python3 - "$WORKDIR" "$N" <<'PY'
import json, sys

wd, n = sys.argv[1], int(sys.argv[2])


def pct(v, p):
    return v[min(len(v) - 1, int(round((len(v) - 1) * p / 100.0)))]


def summarize(name):
    vals, failed = [], 0
    for line in open(f"{wd}/{name}.txt"):
        line = line.strip()
        if line == "failed":
            failed += 1
        elif line:
            vals.append(int(line))
    vals.sort()
    out = {"requested": n, "ok": len(vals), "failed": failed}
    if vals:
        out.update(p50_ms=pct(vals, 50), p95_ms=pct(vals, 95), min_ms=vals[0], max_ms=vals[-1])
    return out


print(json.dumps({
    "metric": "first_command_ms",
    "cold_create": summarize("cold"),
    "warm_claim": summarize("warm"),
    "fork": summarize("fork"),
}, indent=2))
PY
