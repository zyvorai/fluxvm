#!/usr/bin/env bash
set -euo pipefail

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
ID="fluxvm-secure-smoke-$$"
# Prefer sudo when the containerd socket is root-only (typical lab).
if [[ -z "${CTR:-}" ]]; then
  if [[ -S /run/containerd/containerd.sock && -w /run/containerd/containerd.sock ]]; then
    CTR=ctr
  else
    CTR="sudo -n ctr"
  fi
fi
ADDR="${CONTAINERD_ADDRESS:-/run/containerd/containerd.sock}"

command -v ctr >/dev/null
command -v containerd-shim-fluxvm-v2 >/dev/null
command -v fluxvm-container-agent >/dev/null || test -x "${FLUXVM_CONTAINER_AGENT_BINARY:-/usr/local/libexec/fluxvm-container-agent}"
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null

$CTR --address "$ADDR" images pull "$IMAGE"
output="$($CTR --address "$ADDR" run --rm --runtime "$RUNTIME" "$IMAGE" "$ID" /bin/sh -c 'echo fluxvm-secure-container-ok')"
if [[ "$output" != *"fluxvm-secure-container-ok"* ]]; then
  echo "unexpected output: $output" >&2
  exit 1
fi

echo "E2E PASS: $RUNTIME executed $IMAGE inside a FluxVM sandbox"
