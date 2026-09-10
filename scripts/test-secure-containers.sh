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
  if [[ "${FLUXVM_SECURE_CONTAINERS_TTY_E2E:-0}" == "1" ]]; then
    ./scripts/e2e-secure-containers-tty.sh
  fi
fi


if [[ "${FLUXVM_SECURE_CONTAINERS_DUALSTACK_E2E:-0}" == "1" ]]; then
  FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/e2e-secure-containers-dualstack.sh
fi

if [[ "${FLUXVM_SECURE_CONTAINERS_OOM_E2E:-0}" == "1" ]]; then
  FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/e2e-secure-containers-oom.sh
fi

if [[ "${FLUXVM_SECURE_CONTAINERS_DEVICE_LIFECYCLE_E2E:-0}" == "1" ]]; then
  : "${PVC_NAME:?set PVC_NAME to a disposable Bound volumeMode: Block PVC}"
  FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/e2e-secure-containers-device-lifecycle.sh
fi


if [[ "${FLUXVM_SECURE_CONTAINERS_SECURITY_E2E:-0}" == "1" ]]; then
  FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/e2e-secure-containers-security.sh
fi

if [[ "${FLUXVM_SECURE_CONTAINERS_SET11_PREFLIGHT:-0}" == "1" ]]; then
  ./scripts/preflight-secure-containers-set11.sh
fi
