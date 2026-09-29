#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# TEMPORARY validation tool, not part of the regular test suite: boots a
# Linux guest on THIS (real Intel) host with FLUXVM_TEST_SPOOF_AMD_VENDOR=1,
# which makes fluxvm-hypervisor's setup_cpuid() present an AuthenticAMD
# vendor string plus the AMD 0x80000008/0x8000001E leaves instead of the
# real Intel ones. The point is to exercise the guest kernel's actual AMD
# topology-detection code path (arch/x86/kernel/cpu/amd.c's
# amd_get_topology(), gated on TopologyExtensions) end to end, something no
# unit test can do, without needing real AMD silicon -- this hypervisor
# fully synthesizes every CPUID leaf, so the guest only ever sees what we
# hand it. It reuses test-kvm-topology.sh's probe and pass/fail rules
# unchanged: the assertions (one package, N cores, no SMT siblings, nproc)
# should hold exactly the same whether the guest thinks it's on Intel or
# AMD, since fluxvm's topology math (cpuid_topology.rs) doesn't depend on
# vendor beyond which leaves it writes.
#
# This does NOT validate anything AMD-specific below the topology leaves
# (MSRs, cache/TLB leaves 0x8000001D/0x80000006, errata, RAPL/power
# management) -- those still require real AMD hardware.
#
# Usage: sudo env FLUXVM_HYPERVISOR=... CPUS=4 ./scripts/test-kvm-topology-amd-spoof.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export FLUXVM_TEST_SPOOF_AMD_VENDOR=1
export WANT_VENDOR_ID="AuthenticAMD"
exec "${SCRIPT_DIR}/test-kvm-topology.sh"
