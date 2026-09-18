#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Cilium CNI support evidence (Secure Containers L2 handoff).
#
# Always runs static checks (docs, config, shim symbols, unit tests when cargo
# is available). Optional live gate when FLUXVM_CILIUM_CNI_LIVE=1 and the host
# has Cilium markers + kubectl RuntimeClass pods.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pass() { echo "✅ PASS: $*"; }
fail() { echo "❌ FAIL: $*" >&2; exit 1; }
skip() { echo "⏭️  SKIP: $*"; }
need_file() { [[ -f "$1" ]] || fail "missing $1"; }

echo "🔌 == Cilium CNI static evidence =="

need_file docs/cilium-cni.md
need_file configs/cilium-cni.toml
need_file deploy/k8s/cilium/README.md
need_file deploy/k8s/cilium/runtime-env.env
grep -q 'FLUXVM_CONTAINER_CNI_PROVIDER' configs/cilium-cni.toml \
  || fail "configs/cilium-cni.toml missing provider env comments"
grep -q 'mode = "cilium"' configs/cilium-cni.toml \
  || fail "configs/cilium-cni.toml must set dataplane mode=cilium"

SHIM=crates/fluxvm-containerd-shim/src/main.rs
need_file "$SHIM"
for sym in resolve_cni_provider resolve_cni_interface CniProvider is_multus_secondary_iface; do
  grep -q "$sym" "$SHIM" || fail "shim missing $sym"
done
grep -q 'FLUXVM_CONTAINER_CNI_PROVIDER' "$SHIM" \
  || fail "shim missing FLUXVM_CONTAINER_CNI_PROVIDER"
pass "shim Cilium CNI symbols present"

# Unit tests (provider labels / Multus naming) — Linux-only; shim is
# containerd/KVM and does not compile cleanly on Darwin libc.
if command -v cargo >/dev/null 2>&1 && [[ "$(uname -s)" == "Linux" ]]; then
  cargo test -p fluxvm-containerd-shim cni_provider_labels_and_multus_names -- --nocapture
  pass "shim unit test cni_provider_labels_and_multus_names"
elif [[ "$(uname -s)" != "Linux" ]]; then
  skip "cargo unit test (shim is Linux-only; host=$(uname -s))"
else
  skip "cargo not available for unit test"
fi

# Host markers (informational when not live).
CILIUM_MARKERS=0
[[ -S /var/run/cilium/cilium.sock ]] && CILIUM_MARKERS=$((CILIUM_MARKERS + 1)) && pass "cilium.sock present"
[[ -x /opt/cni/bin/cilium-cni || -x /opt/cni/bin/cilium ]] && CILIUM_MARKERS=$((CILIUM_MARKERS + 1)) && pass "cilium CNI binary present"
if compgen -G '/etc/cni/net.d/*cilium*' >/dev/null 2>&1; then
  CILIUM_MARKERS=$((CILIUM_MARKERS + 1))
  pass "cilium CNI conf present"
fi

if [[ "${FLUXVM_CILIUM_CNI_LIVE:-0}" != 1 ]]; then
  echo "🎉 Cilium CNI static evidence: PASS (set FLUXVM_CILIUM_CNI_LIVE=1 for live Pod gate)"
  exit 0
fi

echo "🧪 == Cilium CNI live evidence =="
[[ "$CILIUM_MARKERS" -ge 1 ]] || fail "FLUXVM_CILIUM_CNI_LIVE=1 but no Cilium host markers"
need() { command -v "$1" >/dev/null 2>&1 || fail "missing $1"; }
need kubectl

NS="${FLUXVM_CILIUM_CNI_NS:-fluxvm-cilium-cni-$RANDOM}"
RUNTIME_CLASS="${RUNTIME_CLASS:-${FLUXVM_RUNTIMECLASS:-fluxvm}}"
KUBECTL="${KUBECTL:-kubectl}"

cleanup() {
  $KUBECTL delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT

$KUBECTL create ns "$NS"
$KUBECTL -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: cilium-cni-probe
  labels:
    app: fluxvm-cilium-cni
spec:
  runtimeClassName: ${RUNTIME_CLASS}
  containers:
  - name: pause
    image: registry.k8s.io/pause:3.9
EOF

$KUBECTL -n "$NS" wait --for=condition=Ready pod/cilium-cni-probe --timeout=180s \
  || fail "RuntimeClass pod not Ready under Cilium"
POD_IP=$($KUBECTL -n "$NS" get pod cilium-cni-probe -o jsonpath='{.status.podIP}')
[[ -n "$POD_IP" ]] || fail "pod has no PodIP"
pass "Cilium CNI live Pod Ready ip=$POD_IP runtimeClass=$RUNTIME_CLASS"
echo "🎉 Cilium CNI live evidence: PASS"
