#!/usr/bin/env bash
set -euo pipefail

state_dir="${FLUXVM_CONTAINERD_STATE_DIR:-/run/fluxvm/containerd}"
namespace="${1:-k8s.io}"
group="${2:-}"

if [[ -z "$group" ]]; then
  echo "usage: $0 [namespace] <containerd-group-or-sandbox-id>" >&2
  exit 2
fi

state="$state_dir/$namespace/$group/runtime-state.json"
if [[ ! -f "$state" ]]; then
  echo "no recovery journal: $state" >&2
  exit 1
fi

if command -v jq >/dev/null; then
  jq '{
    version,
    sandbox: (.sandbox | if . == null then null else {
      vm_id, vm_name, ready, share_dir,
      cni: (.cni | if . == null then null else {
        host_bridge, host_veth, netns_alias, cni_bridge, cni_veth, interface,
        addresses: .network.addresses
      } end)
    } end),
    init_tasks: (.tasks | keys),
    exec_tasks: (.execs | keys)
  }' "$state"
else
  cat "$state"
fi
