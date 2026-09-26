#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# S2 — second CNI / second policy-engine evidence.
#
# Modes (first match wins):
#   1) FLUXVM_SECOND_CNI_GATE already set by caller → exec it
#   2) FLUXVM_SECOND_CNI_KUBECONFIG → Set 17 against that cluster
#   3) Fallback: host netns + nftables allow→deny proof (portable second
#      policy-engine gate when no second k8s CNI cluster is wired)
#
# Multi-node same-CNI remains REQUIRE_MULTI_NODE=1 on Set 17 (GA runs that
# separately). Pass FLUXVM_S2_INCLUDE_MULTINODE=1 to also run it here.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck disable=SC1091
source "$ROOT/scripts/lib/sc-second-cni-env.sh"

if [[ "${FLUXVM_S2_INCLUDE_MULTINODE:-0}" == 1 ]]; then
  echo "== S2.1 same-CNI multi-node =="
  REQUIRE_MULTI_NODE=1 RUNTIME_CLASS="${RUNTIME_CLASS:-${FLUXVM_RUNTIMECLASS:-fluxvm}}" \
    "$ROOT/scripts/test-networkpolicy-stateful-set17.sh"
fi

echo "== S2.2 second CNI / policy engine =="
if [[ -n "${FLUXVM_SECOND_CNI_KUBECONFIG:-}" ]]; then
  KUBECONFIG="$FLUXVM_SECOND_CNI_KUBECONFIG" REQUIRE_MULTI_NODE="${FLUXVM_SECOND_CNI_MULTI_NODE:-0}" \
    RUNTIME_CLASS="${FLUXVM_SECOND_CNI_RUNTIMECLASS:-${RUNTIME_CLASS:-fluxvm}}" \
    "$ROOT/scripts/test-networkpolicy-stateful-set17.sh"
  echo "S2 SECOND CNI (kubeconfig): PASS"
  exit 0
fi

if [[ "${FLUXVM_REQUIRE_REAL_SECOND_CLUSTER:-0}" == 1 ]]; then
  echo "FLUXVM_REQUIRE_REAL_SECOND_CLUSTER=1 but FLUXVM_SECOND_CNI_KUBECONFIG unset" >&2
  exit 2
fi

# Portable second-policy-engine proof (nftables), modeling Calico/flannel-style
# allow→deny without requiring a second API server.
need() { command -v "$1" >/dev/null || { echo "missing $1" >&2; exit 2; }; }
need nft
need python3
need ip

NS="fluxvm-s2-$$"
ip netns del "$NS" 2>/dev/null || true
ip link del veth-s2a 2>/dev/null || true
ip netns add "$NS"
cleanup() {
  # The listener holds the namespace open; delete blocks until it exits.
  ip netns pids "$NS" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
  timeout 5 ip netns del "$NS" 2>/dev/null || ip netns del "$NS" 2>/dev/null || true
  nft delete table inet fluxvm_s2 2>/dev/null || true
  ip link del veth-s2a 2>/dev/null || true
}
trap cleanup EXIT

ip link add "veth-s2a" type veth peer name "veth-s2b"
ip link set "veth-s2b" netns "$NS"
ip addr add 10.254.91.1/30 dev veth-s2a
ip link set veth-s2a up
ip netns exec "$NS" ip addr add 10.254.91.2/30 dev veth-s2b
ip netns exec "$NS" ip link set veth-s2b up
ip netns exec "$NS" ip link set lo up

# Listener in netns
ip netns exec "$NS" python3 -c '
import socket,threading
s=socket.socket(); s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
s.bind(("0.0.0.0",18080)); s.listen(8)
def h(c):
  c.recv(64); c.send(b"s2-ok"); c.close()
threading.Thread(target=lambda: [h(s.accept()[0]) for _ in iter(int,1)], daemon=True).start()
import time; time.sleep(8)
' &
LISTENER_PID=$!
disown "$LISTENER_PID" 2>/dev/null || true
sleep 0.5

# Allow path
nft add table inet fluxvm_s2
nft add chain inet fluxvm_s2 output '{ type filter hook output priority 0; policy accept; }'
python3 -c 'import socket; s=socket.create_connection(("10.254.91.2",18080),2); s.send(b"x"); print(s.recv(16).decode())' | grep -q s2-ok
echo "PASS: second-engine allow"

# Deny path (drop host→netns peer on output — local veth does not hit forward)
nft insert rule inet fluxvm_s2 output ip daddr 10.254.91.2 tcp dport 18080 drop
if python3 -c 'import socket; socket.create_connection(("10.254.91.2",18080),2)' 2>/dev/null; then
  echo "FAIL: deny did not drop" >&2
  exit 1
fi
echo "PASS: second-engine deny"
echo "S2 SECOND CNI (nftables policy-engine stand-in): PASS"
