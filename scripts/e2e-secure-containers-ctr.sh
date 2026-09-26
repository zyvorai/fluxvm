#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live smoke: one `ctr run` through io.containerd.fluxvm.v2.
# `ctr run --rm` can hang on teardown after the guest exits; the gate is the
# guest stdout marker, not a clean ctr exit code.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/sc-ctr-env.sh"

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
ID="fluxvm-secure-smoke-$$"
ADDR="${CONTAINERD_ADDRESS}"
RUN_TIMEOUT="${FLUXVM_CTR_TIMEOUT:-120}"

cleanup() {
  $CTR --address "$ADDR" tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" tasks delete --force "$ID" >/dev/null 2>&1 || true
  $CTR --address "$ADDR" containers delete "$ID" >/dev/null 2>&1 || true
}
trap cleanup EXIT

command -v ctr >/dev/null
command -v containerd-shim-fluxvm-v2 >/dev/null
command -v fluxvm-container-agent >/dev/null || test -x "${FLUXVM_CONTAINER_AGENT_BINARY:-/usr/local/libexec/fluxvm-container-agent}"
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null

if ! $CTR --address "$ADDR" images ls -q | grep -Fxq "$IMAGE"; then
  timeout -k 5 90 $CTR --address "$ADDR" images pull "$IMAGE" >/dev/null
fi

OUT="$(mktemp)"
set +e
# -k: send SIGKILL shortly after SIGTERM so sudo/ctr cannot ignore teardown.
timeout -k 5 "$RUN_TIMEOUT" \
  $CTR --address "$ADDR" run --rm --runtime "$RUNTIME" "$IMAGE" "$ID" \
  /bin/sh -c 'echo fluxvm-secure-container-ok; exit 0' \
  >"$OUT" 2>&1
rc=$?
set -e

if grep -q 'fluxvm-secure-container-ok' "$OUT"; then
  echo "E2E PASS: $RUNTIME executed $IMAGE inside a FluxVM sandbox (ctr_rc=$rc)"
  rm -f "$OUT"
  exit 0
fi

echo "unexpected output (ctr_rc=$rc):" >&2
cat "$OUT" >&2
rm -f "$OUT"
exit 1
