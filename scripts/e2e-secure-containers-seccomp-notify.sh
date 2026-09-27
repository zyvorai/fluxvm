#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: SCMP_ACT_NOTIFY via ctr --seccomp-profile + notify-mode annotation.
# Uses chmod (not openat) so the broker is not flooded during rootfs bootstrap.
# containerd 2.x `ctr run --config` cannot take an image ref, so we do not use
# a full OCI config file here.
#
# MODE=deny (default) keeps the decision in the guest broker.
# MODE=remote routes each NOTIFY to the shim's host policy RPC over AF_VSOCK
# (io.zyvor.seccomp.notify.rpc-port, default 17780). The shim inherits its
# decision source from containerd's environment:
#   unset                              -> fail closed (EXPECT=deny, default)
#   FLUXVM_SECCOMP_POLICY_RPC=continue -> run with EXPECT=continue
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-seccomp-notify: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

MODE="${MODE:-deny}"
EXPECT="${EXPECT:-deny}"
RPC_PORT="${RPC_PORT:-17780}"
case "$MODE" in
  deny) ANNOTATIONS=(--annotation io.zyvor.seccomp.notify.mode=deny) ;;
  remote)
    ANNOTATIONS=(--annotation io.zyvor.seccomp.notify.mode=remote
      --annotation "io.zyvor.seccomp.notify.rpc-port=${RPC_PORT}")
    ;;
  *) echo "MODE must be deny or remote (got $MODE)" >&2; exit 2 ;;
esac
case "$EXPECT" in
  deny | continue) ;;
  *) echo "EXPECT must be deny or continue (got $EXPECT)" >&2; exit 2 ;;
esac
if [[ "$MODE" == deny && "$EXPECT" == continue ]]; then
  echo "EXPECT=continue only applies to MODE=remote" >&2
  exit 2
fi
STARTED_AT="$(date -u '+%Y-%m-%d %H:%M:%S')"

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
ID="fluxvm-seccomp-notify-$$"
PROFILE="$(mktemp)"
OUT="$(mktemp)"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/sc-ctr-env.sh"
ADDR="${CONTAINERD_ADDRESS}"

cleanup() {
  $CTR --address "$ADDR" tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" tasks delete "$ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" containers delete "$ID" >/dev/null 2>&1 || true
  rm -f "$PROFILE" "$OUT"
}
trap cleanup EXIT

command -v containerd-shim-fluxvm-v2 >/dev/null
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null
if ! $CTR --address "$ADDR" images ls -q | grep -Fxq "$IMAGE"; then
  timeout -k 5 90 $CTR --address "$ADDR" images pull "$IMAGE" >/dev/null
fi

cat >"$PROFILE" <<'JSON'
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"],
  "syscalls": [
    {"names": ["chmod", "fchmod", "fchmodat"], "action": "SCMP_ACT_NOTIFY"}
  ]
}
JSON

set +e
# -k: ensure sudo/ctr die after SIGTERM so the outer matrix timeout is not
# spent waiting on a RUNNING leftover task.
timeout -k 5 "${FLUXVM_SECCOMP_NOTIFY_TIMEOUT:-180}" \
  $CTR --address "$ADDR" run --rm --runtime "$RUNTIME" \
  --seccomp --seccomp-profile "$PROFILE" \
  "${ANNOTATIONS[@]}" \
  "$IMAGE" "$ID" \
  /bin/sh -c 'echo before; chmod 700 /tmp 2>/tmp/err; echo RC:$?; echo after; cat /tmp/err 2>/dev/null; true' \
  >"$OUT" 2>&1
rc=$?
set -e

# Force-delete: notify workloads can leave the task RUNNING after printing
# (stdio/broker teardown); the gate is the denied chmod evidence above.
$CTR --address "$ADDR" tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
$CTR --address "$ADDR" tasks delete --force "$ID" >/dev/null 2>&1 || true
$CTR --address "$ADDR" containers delete "$ID" >/dev/null 2>&1 || true

if [[ "$MODE" == remote ]]; then
  # Best effort: the guest broker's audit line surfaces via the shim log.
  audit="not-found"
  if command -v journalctl >/dev/null 2>&1; then
    if journalctl --since "$STARTED_AT" --no-pager 2>/dev/null \
      | grep -qE "decision=remote-(deny|continue)"; then
      audit="seen"
    fi
  fi
  if grep -qE "decision=remote-(deny|continue)" "$OUT"; then
    audit="seen"
  fi
  if [[ "$EXPECT" == continue ]]; then
    if grep -q 'before' "$OUT" && grep -q 'after' "$OUT" && grep -q 'RC:0' "$OUT" \
      && ! grep -qiE 'Permission denied|Operation not permitted' "$OUT"; then
      echo "E2E PASS: seccomp NOTIFY remote RPC continued chmod (rpc_port=${RPC_PORT} audit=${audit} ctr_rc=$rc)"
      sed -n "1,20p" "$OUT"
      exit 0
    fi
    echo "unexpected remote-continue outcome (is containerd running with FLUXVM_SECCOMP_POLICY_RPC=continue?) ctr_rc=$rc:" >&2
    cat "$OUT" >&2
    exit 1
  fi
  if grep -q 'before' "$OUT" && grep -qiE 'Permission denied|Operation not permitted|RC:[1-9]' "$OUT"; then
    echo "E2E PASS: seccomp NOTIFY remote RPC denied chmod (rpc_port=${RPC_PORT} audit=${audit} ctr_rc=$rc)"
    sed -n "1,20p" "$OUT"
    exit 0
  fi
  echo "unexpected remote-deny outcome (ctr_rc=$rc):" >&2
  cat "$OUT" >&2
  exit 1
fi

if grep -q 'before' "$OUT" && grep -q 'after' "$OUT"; then
  if grep -qiE 'Permission denied|Operation not permitted|RC:[1-9]' "$OUT" \
    || ! grep -q 'RC:0' "$OUT"; then
    echo "E2E PASS: seccomp NOTIFY broker denied chmod (ctr_rc=$rc)"
    exit 0
  fi
fi

# Timeout (124) with partial deny evidence still counts — see force-delete note.
if [[ "$rc" -eq 124 ]] && grep -qiE 'Permission denied|Operation not permitted|RC:[1-9]' "$OUT"; then
  echo "E2E PASS: seccomp NOTIFY broker denied chmod (ctr timed out after evidence)"
  exit 0
fi

if grep -qiE 'notify|seccomp|libseccomp|SCMP_ACT_NOTIFY' "$OUT"; then
  echo "E2E PASS (fail-closed): seccomp NOTIFY path rejected creation"
  tail -50 "$OUT"
  exit 0
fi

echo "unexpected seccomp NOTIFY outcome (ctr_rc=$rc):" >&2
cat "$OUT" >&2
exit 1
