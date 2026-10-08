#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Time POST /v1/vms/{id}/fork for COUNT children of one running flux-vm VM,
# RUNS times, then delete the children (KEEP=1 keeps the last run's).
# Reports p50/p95 fork time per child ("ready": the API returns once every
# child is restored and running), memory per child from
# /proc/<pid>/smaps_rollup (Pss, Private_*, Rss; needs root to read) and
# disk bytes copied (filesystem 'used' delta across the fork while the
# children are alive, per child; a reflink clone should be near zero).
# Requires a running fluxctl serve and a running VM on the flux-vm backend.
# Linux + KVM. Exits 0 on other hosts so a baseline recorder can keep going.
#
#   VM=<uuid> COUNT=8 RUNS=5 API=http://127.0.0.1:7788 ./scripts/bench-fork.sh
#
# Record a baseline before a change and again after; compare the *_p50/_p95
# lines. FLUXVM_KVM_EAGER_RESTORE=1 on the daemon forces the old eager RAM
# copy, which gives the "before" numbers for the MAP_PRIVATE restore.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "bench-fork: Linux/KVM host required (skipped on $(uname -s))" >&2
  exit 0
fi
if [[ ! -e /dev/kvm ]]; then
  echo "bench-fork: /dev/kvm missing (skipped)" >&2
  exit 0
fi

API="${FLUXVM_API:-http://127.0.0.1:7788}"
VM="${VM:?set VM to the UUID of a running flux-vm VM}"
COUNT="${COUNT:-8}"
RUNS="${RUNS:-5}"
AUTH_HDR=()
if [[ -n "${FLUXVM_TOKEN:-}" ]]; then
  AUTH_HDR=(-H "Authorization: Bearer ${FLUXVM_TOKEN}")
fi

if ! curl -sf "${API}/readyz" "${AUTH_HDR[@]}" >/dev/null; then
  echo "bench-fork: ${API}/readyz is not up (skipped)" >&2
  exit 0
fi

# pct <p> <values...>: nearest-rank percentile.
pct() {
  local p=$1
  shift
  printf '%s\n' "$@" | sort -n | awk -v p="$p" '{a[NR]=$1} END {
    if (NR==0) {print "none"; exit}
    i=int((p/100)*NR); if (i < (p/100)*NR) i++; if (i<1) i=1; print a[i]}'
}

# json_field <python expr over d>; reads JSON on stdin, prints nothing on error.
json_field() {
  python3 -c "import json,sys
try:
    d=json.load(sys.stdin)
    print($1)
except Exception:
    pass" 2>/dev/null || true
}

used_bytes() {
  df --output=used -B1 "$1" 2>/dev/null | tail -1 | tr -d ' ' || echo 0
}

# smaps_sum <field> <pids...>: total kB across the pids.
smaps_sum() {
  local f=$1
  shift
  local t=0 v p
  for p in "$@"; do
    v=$(awk -v f="$f:" '$1==f {print $2}' "/proc/$p/smaps_rollup" 2>/dev/null || true)
    t=$((t + ${v:-0}))
  done
  echo "$t"
}

state_dir="${FLUXVM_STATE_DIR:-/var/lib/fluxvm}"
[[ -d "$state_dir" ]] || state_dir=/

per_child_ms=()
pss_kb=()
priv_kb=()
rss_kb=()
disk_b=()
last_ids=""
for ((run = 1; run <= RUNS; run++)); do
  before=$(used_bytes "$state_dir")
  t0=$(date +%s%3N)
  body=$(curl -sf -X POST "${API}/v1/vms/${VM}/fork" \
    "${AUTH_HDR[@]}" \
    -H 'Content-Type: application/json' \
    -d "{\"count\":${COUNT},\"namePrefix\":\"bench-fork-$RANDOM\"}" || true)
  t1=$(date +%s%3N)
  after=$(used_bytes "$state_dir")
  ms=$((t1 - t0))

  ids=$(printf '%s' "$body" | json_field '"\n".join(v["id"] for v in d.get("items", []))')
  pids=$(printf '%s' "$body" | json_field '" ".join(str(v["pid"]) for v in d.get("items", []) if v.get("pid"))')
  n=$(printf '%s\n' "$ids" | grep -c . || true)
  if [[ "$n" -ne "$COUNT" ]]; then
    echo "fork_error=run ${run}: ${body}" >&2
    exit 1
  fi
  per_child_ms+=($((ms / n)))
  disk_b+=($(((after - before) / n)))
  if [[ -n "$pids" ]]; then
    # shellcheck disable=SC2086
    pss_kb+=($(($(smaps_sum Pss $pids) / n)))
    # shellcheck disable=SC2086
    priv_kb+=($((($(smaps_sum Private_Clean $pids) + $(smaps_sum Private_Dirty $pids)) / n)))
    # shellcheck disable=SC2086
    rss_kb+=($(($(smaps_sum Rss $pids) / n)))
  fi
  echo "run=${run} fork_total_ms=${ms} per_child_ms=$((ms / n)) disk_bytes_per_child=${disk_b[${#disk_b[@]} - 1]}"

  if [[ "${KEEP:-0}" == "1" && "$run" -eq "$RUNS" ]]; then
    last_ids="$ids"
  else
    while read -r id; do
      [[ -n "$id" ]] && curl -sf -X DELETE "${API}/v1/vms/${id}" "${AUTH_HDR[@]}" >/dev/null || true
    done <<<"$ids"
  fi
done

echo "fork_count=${COUNT}"
echo "runs=${RUNS}"
echo "ready_ms_per_child_p50=$(pct 50 "${per_child_ms[@]}")"
echo "ready_ms_per_child_p95=$(pct 95 "${per_child_ms[@]}")"
if [[ "${#pss_kb[@]}" -gt 0 ]]; then
  echo "pss_kb_per_child_p50=$(pct 50 "${pss_kb[@]}")"
  echo "private_kb_per_child_p50=$(pct 50 "${priv_kb[@]}")"
  echo "rss_kb_per_child_p50=$(pct 50 "${rss_kb[@]}")"
else
  echo "memory=unavailable (child pids not in the response, or smaps_rollup unreadable: run as root)"
fi
echo "disk_bytes_copied_per_child_p50=$(pct 50 "${disk_b[@]}")"
if [[ -n "$last_ids" ]]; then
  echo "kept_children=$(printf '%s' "$last_ids" | tr '\n' ' ')"
fi
echo "note=ready time covers parent snapshot, ${COUNT} reflinked disks, ${COUNT} memory restores and the identity reset; not guest init. The disk delta is filesystem-wide and noisy on a busy host."
