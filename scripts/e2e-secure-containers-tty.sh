#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/sc-ctr-env.sh"

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/alpine:3.20}"
INIT_ID="fluxvm-tty-init-$$"
EXEC_ID="fluxvm-tty-exec-$$"
LOG_INIT="$(mktemp)"
LOG_EXEC="$(mktemp)"
ADDR="${CONTAINERD_ADDRESS}"

cleanup() {
  $CTR --address "$ADDR" tasks kill -s SIGKILL "$EXEC_ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" tasks delete "$EXEC_ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" containers delete "$EXEC_ID" >/dev/null 2>&1 || true
  rm -f "$LOG_INIT" "$LOG_EXEC"
}
trap cleanup EXIT

command -v ctr >/dev/null
command -v script >/dev/null
command -v containerd-shim-fluxvm-v2 >/dev/null
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null
timeout 120 $CTR --address "$ADDR" images pull "$IMAGE" >/dev/null

# `script` gives ctr a real host PTY. ctr should pass the 33x101 window to the
# shim, which forwards ResizePty to the guest PTY.
script -q -e -c \
  "stty rows 33 cols 101; $CTR --address '$ADDR' run --rm --runtime '$RUNTIME' --tty '$IMAGE' '$INIT_ID' /bin/sh -lc 'test -t 0 && test -t 1 && echo FLUXVM_TTY_INIT_OK && stty size'" \
  "$LOG_INIT" >/dev/null

grep -q 'FLUXVM_TTY_INIT_OK' "$LOG_INIT"
grep -Eq '33[[:space:]]+101' "$LOG_INIT"

# Keep a non-TTY init alive, then prove terminal exec uses its own PTY stream.
$CTR --address "$ADDR" run --runtime "$RUNTIME" --detach "$IMAGE" "$EXEC_ID" /bin/sh -lc 'sleep 120'
script -q -e -c \
  "stty rows 41 cols 109; $CTR --address '$ADDR' task exec --exec-id shell --tty '$EXEC_ID' /bin/sh -lc 'test -t 0 && test -t 1 && echo FLUXVM_TTY_EXEC_OK && stty size'" \
  "$LOG_EXEC" >/dev/null

grep -q 'FLUXVM_TTY_EXEC_OK' "$LOG_EXEC"
grep -Eq '41[[:space:]]+109' "$LOG_EXEC"

echo "E2E PASS: VSOCK stdio + init TTY + exec TTY + ResizePty"
