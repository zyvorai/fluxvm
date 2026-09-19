#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Portable tests for Multus extra NICs, warm-pool NIC claim, in-tree Windows
# tables, and the S2/S8/S10/S11 evidence scripts.
#
#   ./scripts/test-multus-warm-windows.sh unit
#   ./scripts/test-multus-warm-windows.sh evidence
#   ./scripts/test-multus-warm-windows.sh observer
#   ./scripts/test-multus-warm-windows.sh all
#
# `unit` needs a Linux cargo toolchain (the shim and scheduler do not build
# on Darwin). `evidence` needs root or passwordless sudo, iproute2, and
# nftables. `observer` needs Go matching tools/fluxvm-policy-observer/go.mod.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

UNIT_TESTS=(
  tap_without_extra_deserializes_empty_multus_list
  tap_extra_nics_round_trip_bridge_and_mac
  primary_tap_without_extras_does_not_pin_a_hotplug_port
  multus_extra_nics_use_successive_hotplug_ports
  config_json_attaches_multus_extra_nics
  extra_nics_are_repeated_net_flags
  warm_pool_none_network_claims_the_first_hotplug_slot
  second_hotplug_appends_a_multus_extra
  user_and_macvtap_do_not_consume_a_recorded_slot
  cni_provider_labels_and_multus_names
  multus_guest_script_configures_nics_in_probe_order
  dsdt_checksums_and_names_pci0
  acpi_reset_recognizes_cf9
  msix_cap_is_chained_from_device_cfg
  msix_message_control_enable_bit_is_writable
  bar0_size_probe_reports_four_kib
  msix_table_window_accepts_a_vector
  windows_path_enters_firmware_and_publishes_reset_register
)

run_unit() {
  echo "== unit: Multus / warm-pool / Windows =="
  cargo test \
    -p fluxvm-core \
    -p fluxvm-qemu \
    -p fluxvm-firecracker \
    -p fluxvm-cloud-hypervisor \
    -p fluxvm-scheduler \
    -p fluxvm-containerd-shim \
    -p fluxvm-hypervisor \
    --lib \
    -- \
    --test-threads=8 \
    "${UNIT_TESTS[@]}"
}

run_evidence() {
  echo "== evidence: shell syntax =="
  local f
  for f in scripts/evidence-*.sh scripts/e2e-networkpolicy-s1-depth.sh; do
    bash -n "$f"
    echo "OK bash -n $f"
  done

  echo "== evidence: S10 skips without FLUXVM_FLEET_E2E =="
  ./scripts/evidence-fleet-multihost.sh

  echo "== evidence: S11 skips when FLUXVM_ATTACHED_MIGRATION=0 =="
  FLUXVM_ATTACHED_MIGRATION=0 ./scripts/evidence-migration-attached-vm.sh

  echo "== evidence: Calico/flannel churn =="
  if [[ "$(id -u)" -eq 0 ]]; then
    FLUXVM_CNI_CHURN_ROUNDS="${FLUXVM_CNI_CHURN_ROUNDS:-3}" \
      bash scripts/evidence-cni-churn.sh
  else
    sudo -n env FLUXVM_CNI_CHURN_ROUNDS="${FLUXVM_CNI_CHURN_ROUNDS:-3}" \
      bash scripts/evidence-cni-churn.sh
  fi

  echo "== evidence: S2 nftables stand-in =="
  if [[ "$(id -u)" -eq 0 ]]; then
    bash scripts/evidence-networkpolicy-second-cni.sh
  else
    sudo -n -E bash scripts/evidence-networkpolicy-second-cni.sh
  fi
}

run_observer() {
  echo "== S8: policy-observer unit tests =="
  (
    cd tools/fluxvm-policy-observer
    go test ./...
  )
  echo "== S8: live /metrics scrape and RSS =="
  local bin pid
  bin="$(mktemp)"
  (
    cd tools/fluxvm-policy-observer
    go build -o "$bin" ./cmd/fluxvm-policy-observer
  )
  "$bin" -listen 127.0.0.1:9090 >/tmp/fluxvm-policy-observer-ci.log 2>&1 &
  pid=$!
  cleanup() { kill "$pid" 2>/dev/null || true; rm -f "$bin"; }
  trap cleanup EXIT
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if curl -sf --max-time 1 http://127.0.0.1:9090/metrics | grep -q fluxvm_sentinel_observer_scrapes_total; then
      break
    fi
    sleep 0.2
  done
  OBSERVER_URL=http://127.0.0.1:9090 ./scripts/evidence-policy-observer-scrape.sh
  awk '/^VmRSS:/ {print}' "/proc/${pid}/status"
  grep -q fluxvm_sentinel_observer_scrapes_total \
    docs/benchmarks/evidence/policy-observer-scrape-*.txt
}

case "${1:-all}" in
  unit) run_unit ;;
  evidence) run_evidence ;;
  observer) run_observer ;;
  all)
    run_unit
    run_evidence
    run_observer
    ;;
  *)
    echo "usage: $0 unit|evidence|observer|all" >&2
    exit 2
    ;;
esac
