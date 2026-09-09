#!/usr/bin/env bash
set -euo pipefail

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
ID="fluxvm-secure-smoke-$$"

command -v ctr >/dev/null
command -v containerd-shim-fluxvm-v2 >/dev/null
command -v fluxvm-container-agent >/dev/null || test -x "${FLUXVM_CONTAINER_AGENT_BINARY:-/usr/local/libexec/fluxvm-container-agent}"
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null

ctr images pull "$IMAGE"
output="$(ctr run --rm --runtime "$RUNTIME" "$IMAGE" "$ID" /bin/sh -c 'echo fluxvm-secure-container-ok')"
if [[ "$output" != *"fluxvm-secure-container-ok"* ]]; then
  echo "unexpected output: $output" >&2
  exit 1
fi

echo "E2E PASS: $RUNTIME executed $IMAGE inside a FluxVM sandbox"
