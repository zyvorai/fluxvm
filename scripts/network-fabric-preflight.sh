#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Host readiness checks for Network Fabric (GA; dataplane schema v4) before
# enabling eBPF/cilium mode. Does not flip dataplane mode and does not run
# cargo/CI gates (see validate-network-fabric.sh for those).
#
# Usage:
#   ./scripts/network-fabric-preflight.sh
#   ./scripts/network-fabric-preflight.sh --require-bpf
#   ./scripts/network-fabric-preflight.sh --health
#
set -euo pipefail

BPF_TC="${FLUXVM_BPF_TC:-/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o}"
REQUIRE_BPF=0
CHECK_HEALTH=0
UNIT="${FLUXVM_UNIT:-fluxvm}"
FAILS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --require-bpf) REQUIRE_BPF=1; shift ;;
    --health) CHECK_HEALTH=1; shift ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

ok() { echo "OK  $*"; }
warn() { echo "WARN $*"; }
fail() { echo "FAIL $*"; FAILS=$((FAILS + 1)); }

if [[ "$(uname -s)" != "Linux" ]]; then
  fail "Linux host required (got $(uname -s))"
else
  ok "Linux kernel $(uname -r)"
fi

if [[ -d /sys/fs/bpf ]]; then
  if mountpoint -q /sys/fs/bpf 2>/dev/null || findmnt -n /sys/fs/bpf >/dev/null 2>&1; then
    ok "bpffs mounted at /sys/fs/bpf"
  else
    # Some hosts expose the dir without findmnt labeling it; still usable if writable.
    if [[ -w /sys/fs/bpf ]]; then
      warn "bpffs path exists and is writable but mountpoint check inconclusive"
    else
      fail "bpffs not mounted or not writable at /sys/fs/bpf"
    fi
  fi
else
  fail "missing /sys/fs/bpf (mount bpffs)"
fi

if command -v bpftool >/dev/null 2>&1; then
  ok "bpftool: $(command -v bpftool)"
else
  fail "bpftool not on PATH"
fi

if command -v tc >/dev/null 2>&1; then
  ok "tc: $(command -v tc)"
else
  fail "tc (iproute2) not on PATH"
fi

if [[ -f "$BPF_TC" ]]; then
  ok "TC BPF object: $BPF_TC"
elif [[ $REQUIRE_BPF -eq 1 ]]; then
  fail "missing $BPF_TC (run scripts/build-ebpf.sh + install, or enable-network-fabric-ga.sh)"
else
  warn "missing $BPF_TC (enable script will build/install)"
fi

if systemctl cat "$UNIT" >/dev/null 2>&1; then
  unit_text="$(systemctl cat "$UNIT" 2>/dev/null || true)"
  if grep -q 'LimitMEMLOCK=infinity' <<<"$unit_text"; then
    ok "$UNIT LimitMEMLOCK=infinity"
  else
    fail "$UNIT missing LimitMEMLOCK=infinity (see systemd/fluxvm.service)"
  fi
  if grep -E 'ReadWritePaths=.*(/sys/fs/bpf|/run/fluxvm)' <<<"$unit_text" >/dev/null; then
    ok "$UNIT ReadWritePaths covers bpffs /run/fluxvm"
  else
    # Broader match: any ReadWritePaths mentioning bpf or fluxvm run dir
    if grep -q 'ReadWritePaths=' <<<"$unit_text" && \
       grep -E '/sys/fs/bpf|/run/fluxvm' <<<"$unit_text" >/dev/null; then
      ok "$UNIT ReadWritePaths mentions bpf/fluxvm paths"
    else
      fail "$UNIT ReadWritePaths should include /sys/fs/bpf and /run/fluxvm"
    fi
  fi
else
  warn "systemd unit $UNIT not installed; skip MEMLOCK/ReadWritePaths checks"
fi

if [[ $CHECK_HEALTH -eq 1 ]]; then
  if command -v fluxvm >/dev/null 2>&1; then
    if fluxvm dataplane health >/dev/null 2>&1; then
      ok "fluxvm dataplane health"
    else
      fail "fluxvm dataplane health failed (is fluxvm serve running with Fabric enabled?)"
    fi
  else
    fail "fluxvm binary not on PATH for --health"
  fi
fi

if [[ $FAILS -gt 0 ]]; then
  echo "preflight: $FAILS check(s) failed" >&2
  exit 1
fi
echo "preflight: all required checks passed"
exit 0
