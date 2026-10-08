#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Fault-injection test for crash-safe VM lifecycle: kills the daemon with
# SIGKILL in the middle of create, delete, snapshot and fork, restarts it, and
# proves the next start converges - no leaked taps, network namespaces, VMM
# processes, workspace directories or journal intents - and that the
# Idempotency-Key header replays instead of repeating.
#
# - create is killed at four points: right after the journal intent is
#   written, once the workspace exists, once the root disk exists, and once
#   the VMM process is running. After restart the half-made VM must be gone.
# - delete is killed as soon as its intent is journaled (the VM record is
#   about to be, or has just been, removed). After restart the delete must
#   have rolled forward: VM, workspace and VMM all gone.
# - snapshot is killed as soon as its intent is journaled. After restart no
#   journal intent may remain and the VM must still be running.
# - fork (optional, needs --fork-spec) is killed after its intent is
#   journaled. After restart the parent keeps running and no child or fork
#   snapshot remains.
# - Idempotency-Key: a retried create returns the same VM, the same key with
#   a different body is rejected (422), and the VM count does not grow.
#
# A kill that lands after the operation already finished is reported as a
# SKIP for that point (the race was lost), not a failure.
#
# Needs a Linux/KVM host, root, curl and python3. The daemon runs against a
# private state dir and port; it never touches /var/lib/fluxvm VMs.
#
# Usage:
#   sudo ./scripts/test-crash-recovery.sh [--image PATH] [--fork-spec FILE]
#                                         [--port N] [--keep]
#
# Env:
#   FLUXVM_BIN   path to the fluxctl binary (default: PATH or target/release)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

IMAGE=""
FORK_SPEC=""
PORT=17788
KEEP=0

while [ $# -gt 0 ]; do
    case "$1" in
        --image)     IMAGE="$2"; shift 2 ;;
        --fork-spec) FORK_SPEC="$2"; shift 2 ;;
        --port)      PORT="$2"; shift 2 ;;
        --keep)      KEEP=1; shift ;;
        -h|--help)
            sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

PASS=0
FAIL=0
SKIP=0
pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1" >&2; }
skip() { SKIP=$((SKIP + 1)); echo "  [SKIP] $1"; }
section() { echo ""; echo "=== $1 ==="; }

[ "$(uname -s)" = "Linux" ] || { echo "This test boots real VMs and requires a Linux/KVM host." >&2; exit 1; }
[ -e /dev/kvm ] || { echo "/dev/kvm missing - enable virtualization first." >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || { echo "Run as root (sudo) - VM and network setup need it." >&2; exit 1; }
command -v curl >/dev/null || { echo "curl is required." >&2; exit 1; }
command -v python3 >/dev/null || { echo "python3 is required." >&2; exit 1; }

EPH="${FLUXVM_BIN:-}"
if [ -z "$EPH" ]; then
    if command -v fluxctl >/dev/null 2>&1; then
        EPH="$(command -v fluxctl)"
    elif [ -x "${PROJECT_DIR}/target/release/fluxctl" ]; then
        EPH="${PROJECT_DIR}/target/release/fluxctl"
    else
        echo "fluxctl not found. Build it (cargo build --release -p fluxctl) or set FLUXVM_BIN." >&2
        exit 1
    fi
fi

if [ -z "$IMAGE" ]; then
    IMAGE="/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2"
    [ -f "$IMAGE" ] || { echo "No test image at ${IMAGE}; run scripts/test-lifecycle.sh once or pass --image." >&2; exit 1; }
fi

TMP="$(mktemp -d)"
STATE="${TMP}/state"
RUN="${TMP}/run"
CFG="${TMP}/fluxvm.toml"
LOG="${TMP}/daemon.log"
API="http://127.0.0.1:${PORT}"
DAEMON_PID=""
mkdir -p "$STATE" "$RUN"

cat > "$CFG" <<TOML
listen = "127.0.0.1:${PORT}"
state_dir = "${STATE}"
run_dir = "${RUN}"
reaper_interval_secs = 2
TOML

cleanup() {
    [ -n "$DAEMON_PID" ] && kill -9 "$DAEMON_PID" 2>/dev/null || true
    pkill -9 -f "${STATE}/instances" 2>/dev/null || true
    # Only namespaces this run created: anything that existed at start-up
    # (BASE_NETNS) belongs to someone else's VM and must never be deleted.
    for ns in $(type new_netns >/dev/null 2>&1 && new_netns || true); do
        ip netns del "$ns" 2>/dev/null || true
    done
    if [ "$KEEP" -eq 0 ]; then rm -rf "$TMP"; else echo "kept ${TMP}"; fi
}
trap cleanup EXIT

json_field() { python3 -c "import json,sys;v=json.load(sys.stdin).get('$1');print(v if v is not None else '')"; }

start_daemon() {
    "$EPH" --config "$CFG" serve >> "$LOG" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 1 100); do
        if curl -fsS "${API}/healthz" >/dev/null 2>&1; then return 0; fi
        sleep 0.2
    done
    echo "daemon did not become healthy; log:" >&2
    tail -30 "$LOG" >&2
    return 1
}

crash_daemon() {
    kill -9 "$DAEMON_PID" 2>/dev/null || true
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=""
}

vm_json() {
    # vm_json NAME [extra top-level JSON members, leading comma]
    cat <<JSON
{"name":"$1","backend":"qemu","image":"${IMAGE}","vcpus":1,"memory_mib":512,
 "network":{"mode":"tap","netns":true,"mac":"52:54:00:12:34:$(printf '%02x' $((RANDOM % 256)))"},
 "agent":{"enabled":true},"ttl_seconds":900${2:-}}
JSON
}

api() { curl -sS -m 600 "$@"; }
vm_count() { api "${API}/v1/vms" | python3 -c "import json,sys;d=json.load(sys.stdin);print(len(d['items'] if isinstance(d,dict) else d))"; }
vm_ids()   { api "${API}/v1/vms" | python3 -c "import json,sys;d=json.load(sys.stdin);d=d['items'] if isinstance(d,dict) else d;print('\n'.join(v['id'] for v in d))"; }

# --- leak detectors ---------------------------------------------------------

journal_clear()   { [ "$(journal_pending)" -eq 0 ]; }
journal_pending() { find "${STATE}/journal" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l; }
# Resources that already existed before this run (e.g. a real VM's eph-xxxxxxxx
# namespace and tapxxxxxxxx) are recorded once and excluded from every count and
# from cleanup; only what appears afterwards counts as ours.
all_netns() { ip netns list 2>/dev/null | awk '{print $1}' | grep -E '^eph-[0-9a-f]{8}$' | sort || true; }
all_taps()  { ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(eph|tap)[0-9a-f]{8}$' | sort || true; }
BASE_NETNS="$(all_netns)"
BASE_TAPS="$(all_taps)"
new_netns() { comm -13 <(printf '%s\n' "$BASE_NETNS") <(all_netns); }
new_taps()  { comm -13 <(printf '%s\n' "$BASE_TAPS") <(all_taps); }
stray_netns()     { new_netns | grep -c . || true; }
stray_taps()      { new_taps | grep -c . || true; }
stray_vmm()       { pgrep -f "${STATE}/instances" 2>/dev/null | wc -l; }
workspace_dirs()  { find "${STATE}/instances" -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l; }

wait_for() {
    # wait_for SECONDS COMMAND... - polls until COMMAND succeeds
    local secs="$1"; shift
    local end=$((SECONDS + secs))
    while [ "$SECONDS" -lt "$end" ]; do
        if "$@" >/dev/null 2>&1; then return 0; fi
        sleep 0.5
    done
    return 1
}

converged_empty() {
    [ "$(journal_pending)" -eq 0 ] && [ "$(stray_netns)" -eq 0 ] &&
        [ "$(stray_taps)" -eq 0 ] && [ "$(stray_vmm)" -eq 0 ] && [ "$(workspace_dirs)" -eq 0 ]
}

assert_converged_empty() {
    local label="$1"
    if wait_for 90 converged_empty; then
        pass "${label}: no leaked journal intents, netns, taps, VMM processes or workspaces"
    else
        fail "${label}: journal=$(journal_pending) netns=$(stray_netns) taps=$(stray_taps) vmm=$(stray_vmm) workspaces=$(workspace_dirs)"
    fi
    if [ "$(vm_count)" -eq 0 ]; then
        pass "${label}: no VM record left"
    else
        fail "${label}: $(vm_count) VM record(s) left"
    fi
}

# Waits (tight loop) for a journal intent of kind $1, optionally also for a
# stage condition, then SIGKILLs the daemon. Returns 1 if the operation already
# finished (curl exited) before the kill could land.
kill_when() {
    local kind="$1" stage="$2" curl_pid="$3"
    local end=$((SECONDS + 120))
    while [ "$SECONDS" -lt "$end" ]; do
        if ! kill -0 "$curl_pid" 2>/dev/null; then return 1; fi
        if compgen -G "${STATE}/journal/${kind}-*.json" >/dev/null; then
            case "$stage" in
                intent)    break ;;
                workspace) [ "$(workspace_dirs)" -gt 0 ] && break ;;
                disk)      find "${STATE}/instances" -maxdepth 2 -name 'root.*' 2>/dev/null | grep -q . && break ;;
                vmm)       [ "$(stray_vmm)" -gt 0 ] && break ;;
            esac
        fi
        sleep 0.02
    done
    crash_daemon
    return 0
}

start_daemon

# ---------------------------------------------------------------------------
section "Create killed mid-flight"
for stage in intent workspace disk vmm; do
    api -X POST "${API}/v1/vms" -H 'content-type: application/json' \
        -d "$(vm_json "crash-create-${stage}")" >/dev/null 2>&1 &
    CURL_PID=$!
    if kill_when create "$stage" "$CURL_PID"; then
        wait "$CURL_PID" 2>/dev/null || true
        echo "  killed daemon at create stage: ${stage}"
        start_daemon
        assert_converged_empty "create/${stage}"
    else
        wait "$CURL_PID" 2>/dev/null || true
        skip "create/${stage}: create finished before the kill landed"
        for id in $(vm_ids); do api -X DELETE "${API}/v1/vms/${id}" >/dev/null 2>&1 || true; done
        wait_for 60 converged_empty || true
    fi
done

# ---------------------------------------------------------------------------
section "Delete killed after its intent is journaled"
OUT=$(api -X POST "${API}/v1/vms" -H 'content-type: application/json' -d "$(vm_json crash-delete)")
DEL_ID=$(echo "$OUT" | json_field id)
if [ -z "$DEL_ID" ]; then
    fail "could not create the VM to delete: ${OUT}"
else
    api -X DELETE "${API}/v1/vms/${DEL_ID}" >/dev/null 2>&1 &
    CURL_PID=$!
    if kill_when delete intent "$CURL_PID"; then
        wait "$CURL_PID" 2>/dev/null || true
        start_daemon
        assert_converged_empty "delete"
    else
        wait "$CURL_PID" 2>/dev/null || true
        skip "delete: finished before the kill landed"
        wait_for 60 converged_empty || true
    fi
fi

# ---------------------------------------------------------------------------
section "Snapshot killed after its intent is journaled"
OUT=$(api -X POST "${API}/v1/vms" -H 'content-type: application/json' -d "$(vm_json crash-snapshot)")
SNAP_ID=$(echo "$OUT" | json_field id)
if [ -z "$SNAP_ID" ]; then
    fail "could not create the VM to snapshot: ${OUT}"
else
    api -X POST "${API}/v1/vms/${SNAP_ID}/snapshot" -H 'content-type: application/json' \
        -d '{"tag":"crash-snap"}' >/dev/null 2>&1 &
    CURL_PID=$!
    if kill_when snapshot intent "$CURL_PID"; then
        wait "$CURL_PID" 2>/dev/null || true
        start_daemon
        if wait_for 60 journal_clear; then
            pass "snapshot: no journal intent left after restart"
        else
            fail "snapshot: $(journal_pending) journal intent(s) left"
        fi
        STATUS=$(api "${API}/v1/vms/${SNAP_ID}" | json_field status)
        if [ "$STATUS" = "running" ]; then
            pass "snapshot: the VM is still running"
        else
            fail "snapshot: VM status is '${STATUS}', expected running"
        fi
    else
        wait "$CURL_PID" 2>/dev/null || true
        skip "snapshot: finished before the kill landed"
    fi
    api -X DELETE "${API}/v1/vms/${SNAP_ID}" >/dev/null 2>&1 || true
    assert_converged_empty "snapshot cleanup"
fi

# ---------------------------------------------------------------------------
section "Fork killed after its intent is journaled"
if [ -z "$FORK_SPEC" ]; then
    skip "fork: pass --fork-spec FILE (a flux-vm KVM-engine create spec with network.netns=true)"
else
    OUT=$(api -X POST "${API}/v1/vms" -H 'content-type: application/json' -d @"${FORK_SPEC}")
    FORK_ID=$(echo "$OUT" | json_field id)
    if [ -z "$FORK_ID" ]; then
        fail "could not create the fork parent: ${OUT}"
    else
        api -X POST "${API}/v1/vms/${FORK_ID}/fork" -H 'content-type: application/json' \
            -d '{"count":2}' >/dev/null 2>&1 &
        CURL_PID=$!
        if kill_when fork intent "$CURL_PID"; then
            wait "$CURL_PID" 2>/dev/null || true
            start_daemon
            wait_for 90 journal_clear || true
            COUNT=$(vm_count)
            if [ "$COUNT" -eq 1 ]; then
                pass "fork: only the parent remains (no half-made children)"
            else
                fail "fork: ${COUNT} VMs after recovery, expected 1"
            fi
            if [ -z "$(find "${STATE}/instances/${FORK_ID}/snapshots" -mindepth 1 -maxdepth 1 -name 'fork-*' 2>/dev/null)" ]; then
                pass "fork: no fork snapshot left on the parent"
            else
                fail "fork: a fork snapshot is still on the parent"
            fi
        else
            wait "$CURL_PID" 2>/dev/null || true
            skip "fork: finished before the kill landed"
        fi
        api -X DELETE "${API}/v1/vms/${FORK_ID}" >/dev/null 2>&1 || true
        for id in $(vm_ids); do api -X DELETE "${API}/v1/vms/${id}" >/dev/null 2>&1 || true; done
        assert_converged_empty "fork cleanup"
    fi
fi

# ---------------------------------------------------------------------------
section "Idempotency-Key"
KEY="crash-test-$(date +%s)-$$"
BODY="$(vm_json crash-idem)"
R1=$(api -X POST "${API}/v1/vms" -H 'content-type: application/json' -H "Idempotency-Key: ${KEY}" -d "$BODY")
R2=$(api -D "${TMP}/replay.hdr" -X POST "${API}/v1/vms" -H 'content-type: application/json' -H "Idempotency-Key: ${KEY}" -d "$BODY")
ID1=$(echo "$R1" | json_field id)
ID2=$(echo "$R2" | json_field id)
if [ -n "$ID1" ] && [ "$ID1" = "$ID2" ]; then
    pass "a retried create with the same key returned the same VM (${ID1})"
else
    fail "retried create returned a different VM: '${ID1}' vs '${ID2}'"
fi
grep -qi '^idempotent-replayed: true' "${TMP}/replay.hdr" \
    && pass "the retry was marked Idempotent-Replayed" \
    || fail "the retry was not marked Idempotent-Replayed"
if [ "$(vm_count)" -eq 1 ]; then
    pass "only one VM exists after the retry"
else
    fail "$(vm_count) VMs exist after the retry, expected 1"
fi
CODE=$(api -o /dev/null -w '%{http_code}' -X POST "${API}/v1/vms" -H 'content-type: application/json' \
    -H "Idempotency-Key: ${KEY}" -d "$(vm_json crash-idem-other)")
[ "$CODE" = "422" ] && pass "the same key with a different body was rejected (422)" \
    || fail "same key, different body returned ${CODE}, expected 422"

# The stored response must survive a daemon crash.
crash_daemon
start_daemon
R3=$(api -X POST "${API}/v1/vms" -H 'content-type: application/json' -H "Idempotency-Key: ${KEY}" -d "$BODY")
[ "$(echo "$R3" | json_field id)" = "$ID1" ] \
    && pass "the stored response was replayed after a daemon crash" \
    || fail "no replay after a daemon crash: ${R3}"

api -X DELETE "${API}/v1/vms/${ID1}" -H "Idempotency-Key: del-${KEY}" >/dev/null 2>&1 || true
CODE=$(api -o /dev/null -w '%{http_code}' -X DELETE "${API}/v1/vms/${ID1}" -H "Idempotency-Key: del-${KEY}")
case "$CODE" in
    2??) pass "a retried delete replayed its 2xx instead of returning 404" ;;
    *)   fail "retried delete returned ${CODE}" ;;
esac
assert_converged_empty "final"

echo ""
echo "Summary: ${PASS} passed, ${FAIL} failed, ${SKIP} skipped"
[ "$FAIL" -eq 0 ]
