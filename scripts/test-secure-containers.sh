#!/usr/bin/env bash
set -euo pipefail

cargo test -p fluxvm-container-protocol
cargo test -p fluxvm-container-agent
cargo test -p fluxvm-container-client
cargo test -p fluxvm-containerd-shim
cargo build --release -p fluxvm-container-agent -p fluxvm-containerd-shim

# Optional host integration gate. It is intentionally opt-in because GitHub
# hosted runners do not provide the KVM/containerd/FluxVM setup this needs.
if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" == "1" ]]; then
  : "${FLUXVM_CONTAINER_GUEST_IMAGE:?set FLUXVM_CONTAINER_GUEST_IMAGE}"
  command -v containerd >/dev/null
  command -v ctr >/dev/null
  test -e /dev/kvm
  test -S /run/containerd/containerd.sock
  curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null
  ./scripts/e2e-secure-containers-ctr.sh
fi
