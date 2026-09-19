#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Direct (bridge-less) datapath evidence -- docs/direct-datapath.md.
#
# Three tiers, each opt-in beyond the first:
#   1. static (always)          files, symbols, script syntax, and -- on Linux with cargo -- the unit and
#                               integration suites that need no root
#   2. kernel (FLUXVM_DIRECT_KERNEL=1, Linux root)
#                               verifier budget, pod-policy verdicts, the netns datapath tests and the
#                               uplink test on a real kernel. Needs built BPF objects (FLUXVM_BPF_DIR,
#                               default dist/bpf) and, for the two cargo-built tests, prebuilt binaries
#                               (see FLUXVM_LOADER_TEST_BIN / FLUXVM_UPLINK_TEST_BIN below)
#   3. live (FLUXVM_DIRECT_LIVE=1)
#                               a RuntimeClass Pod on a Cilium + KVM node with the shim in direct mode:
#                               Ready, reachable, no bridge on the node, and a NetworkPolicy still enforced.
#                               THIS TIER IS WHAT THE DEFAULT FLIP TO `auto` WAITS FOR.
#
#   ./scripts/evidence-direct-datapath.sh
#   sudo FLUXVM_DIRECT_KERNEL=1 FLUXVM_BPF_DIR=dist/bpf ./scripts/evidence-direct-datapath.sh
#   FLUXVM_DIRECT_LIVE=1 FLUXVM_CONTAINER_CNI_DATAPATH=direct ./scripts/evidence-direct-datapath.sh
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

pass() { echo "✅ PASS: $*"; }
fail() { echo "❌ FAIL: $*" >&2; exit 1; }
skip() { echo "⏭️  SKIP: $*"; }
need_file() { [[ -f "$1" ]] || fail "missing $1"; }
has() { grep -q -- "$2" "$1" || fail "$1 is missing: $2"; }

echo "⚡ == Direct datapath static evidence =="

for f in docs/direct-datapath.md bpf/fluxvm_direct.bpf.c bpf/fluxvm_direct.bpf.h \
         bpf/tests/fluxvm_direct_stub_egress.bpf.c bpf/tests/prefix_match_equiv.bpf.c \
         crates/fluxvm-network/src/direct.rs crates/fluxvm-network/src/netns_scope.rs \
         crates/fluxvm-network/tests/direct_loader.rs crates/fluxvm-network/tests/direct_uplink.rs \
         scripts/test-direct-datapath.sh scripts/test-direct-uplink.sh scripts/test-verifier-budget.sh \
         scripts/test-pod-policy-verdict.py scripts/bench-direct-datapath.sh deploy/k8s/cilium/runtime-env.env \
         configs/direct-datapath.toml; do
  need_file "$f"
done
has deploy/k8s/cilium/runtime-env.env FLUXVM_CONTAINER_CNI_DATAPATH
pass "files present"

# Symbols that would silently disappear in a refactor and quietly turn the feature off.
has crates/fluxvm-containerd-shim/src/main.rs "fn prepare_cni_direct"
has crates/fluxvm-containerd-shim/src/main.rs "fn resolve_datapath"
has crates/fluxvm-containerd-shim/src/main.rs "fn direct_hotplug_body"
has crates/fluxvm-containerd-shim/src/main.rs "FLUXVM_CONTAINER_CNI_DATAPATH"
has crates/fluxvm-network/src/ebpf.rs "fn attach_direct_in"
has crates/fluxvm-network/src/ebpf.rs "fn ensure_uplink_maps"
has crates/fluxvm-network/src/packetflow.rs "pub enum HopPath"
has crates/fluxvm-qemu/src/qmp.rs "pub async fn hotplug_nic_fd"
has crates/fluxvm-scheduler/src/lib.rs "fn plug_direct_nic"
has bpf/fluxvm_direct.bpf.h "fluxvm_direct_redirect"
has tools/fluxvm-sentinel-certify.py "redirect_peer"
pass "shim / loader / QMP / scheduler / BPF symbols present"

# Default-datapath guard: the original bridge chain must remain the default until live evidence
# exists. Flipping it is a deliberate one-line change in CniDatapath's #[default].
if ! awk '/enum CniDatapath/,/^}/' crates/fluxvm-containerd-shim/src/main.rs | grep -B1 "Bridge," | grep -q "#\[default\]"; then
  echo "note: CniDatapath's default is no longer Bridge -- make sure the live tier below has been run" >&2
fi

for f in scripts/test-direct-datapath.sh scripts/test-direct-uplink.sh scripts/test-verifier-budget.sh scripts/bench-direct-datapath.sh; do
  bash -n "$f" || fail "syntax: $f"
done
python3 -m py_compile scripts/test-pod-policy-verdict.py scripts/direct-datapath-guest.py scripts/bpf-map-clear.py \
  || fail "python syntax"
pass "scripts parse"

if compgen -G 'docs/benchmarks/evidence/direct-datapath-*.txt' >/dev/null; then
  pass "benchmark evidence archived: $(ls docs/benchmarks/evidence/direct-datapath-*.txt | wc -l) file(s)"
else
  skip "no archived benchmark evidence yet (scripts/bench-direct-datapath.sh)"
fi

if command -v cargo >/dev/null 2>&1 && [[ "$(uname -s)" == "Linux" ]]; then
  cargo test -q -p fluxvm-core direct
  cargo test -q -p fluxvm-network --lib
  cargo test -q -p fluxvm-qemu fd_session
  cargo test -q -p fluxvm-scheduler --lib
  cargo test -q -p fluxvm-containerd-shim --bin containerd-shim-fluxvm-v2 direct_datapath_tests
  cargo test -q -p fluxvm-microvm direct
  python3 -m unittest tools.tests.test_fluxvm_sentinel_certify >/dev/null
  pass "unit + integration suites (root-gated ones skip themselves without root)"
elif [[ "$(uname -s)" != "Linux" ]]; then
  skip "cargo suites (the network/shim/qemu crates are Linux-only; host=$(uname -s))"
else
  skip "cargo not available"
fi

if [[ "${FLUXVM_DIRECT_KERNEL:-0}" == 1 ]]; then
  echo "🧪 == Direct datapath kernel evidence =="
  [[ "$(uname -s)" == "Linux" && "$(id -u)" -eq 0 ]] || fail "FLUXVM_DIRECT_KERNEL=1 needs Linux root"
  export FLUXVM_BPF_DIR="${FLUXVM_BPF_DIR:-$ROOT/dist/bpf}"
  [[ -f "$FLUXVM_BPF_DIR/fluxvm_tc.bpf.o" ]] || fail "no BPF objects in $FLUXVM_BPF_DIR (run scripts/build-ebpf.sh)"
  ./scripts/test-verifier-budget.sh
  ./scripts/test-pod-policy-verdict.py
  ./scripts/test-direct-datapath.sh
  if [[ -n "${FLUXVM_UPLINK_TEST_BIN:-}" ]]; then
    ./scripts/test-direct-uplink.sh
  else
    skip "uplink test: set FLUXVM_UPLINK_TEST_BIN (cargo test -p fluxvm-network --test direct_uplink --no-run)"
  fi
  if [[ -n "${FLUXVM_LOADER_TEST_BIN:-}" ]]; then
    FLUXVM_TEST_BPF_DIR="$FLUXVM_BPF_DIR" "$FLUXVM_LOADER_TEST_BIN"
  else
    skip "loader test: set FLUXVM_LOADER_TEST_BIN (cargo test -p fluxvm-network --test direct_loader --no-run)"
  fi
  pass "kernel tier"
fi

if [[ "${FLUXVM_DIRECT_LIVE:-0}" != 1 ]]; then
  echo "🎉 Direct datapath static evidence: PASS (FLUXVM_DIRECT_KERNEL=1 for the kernel tier, FLUXVM_DIRECT_LIVE=1 for the live Pod gate)"
  exit 0
fi

echo "🧪 == Direct datapath live evidence =="
command -v kubectl >/dev/null 2>&1 || fail "missing kubectl"
[[ "${FLUXVM_CONTAINER_CNI_DATAPATH:-}" == "direct" ]] \
  || fail "set FLUXVM_CONTAINER_CNI_DATAPATH=direct (and the same on the node's shim) so a fallback cannot pass for direct"
NS="${FLUXVM_DIRECT_NS:-fluxvm-direct-$RANDOM}"
RUNTIME_CLASS="${RUNTIME_CLASS:-${FLUXVM_RUNTIMECLASS:-fluxvm}}"
KUBECTL="${KUBECTL:-kubectl}"
trap '$KUBECTL delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true' EXIT

$KUBECTL create ns "$NS"
for name in server client; do
  $KUBECTL -n "$NS" apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata: {name: $name, labels: {app: $name}}
spec:
  runtimeClassName: ${RUNTIME_CLASS}
  containers:
  - {name: c, image: busybox:1.36, command: [sleep, "3600"]}
EOF
done
$KUBECTL -n "$NS" wait --for=condition=Ready pod/server pod/client --timeout=240s \
  || fail "RuntimeClass pods not Ready in direct mode"
SERVER_IP=$($KUBECTL -n "$NS" get pod server -o jsonpath='{.status.podIP}')
[[ -n "$SERVER_IP" ]] || fail "server has no PodIP"

# 1. traffic flows through the direct datapath
$KUBECTL -n "$NS" exec client -- ping -c 3 -W 2 "$SERVER_IP" >/dev/null \
  || fail "client cannot reach server ($SERVER_IP) in direct mode"
pass "pod -> pod reachable in direct mode ($SERVER_IP)"

# 2. the bridge chain is really absent on the node (a silent fallback must not pass)
if ip -o link show | grep -Eq ' fvbh[0-9a-f]{6}[: ]'; then
  fail "a host bridge (fvbh*) exists: the shim fell back to the bridge chain"
fi
pass "no fvbh* host bridge on the node"

# 3. Cilium still enforces NetworkPolicy on the lxc* peer
$KUBECTL -n "$NS" apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: deny-all}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress]
EOF
sleep 5
if $KUBECTL -n "$NS" exec client -- ping -c 2 -W 2 "$SERVER_IP" >/dev/null 2>&1; then
  fail "NetworkPolicy deny-all did not block client -> server: Cilium is being bypassed"
fi
pass "Cilium NetworkPolicy still enforced in direct mode"
echo "🎉 Direct datapath live evidence: PASS"
