#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Linux-root test for the standalone "l2-uplink" direct mode (two VMs, one unbridged uplink, no
# bridge). Runs crates/fluxvm-network/tests/direct_uplink.rs twice -- with TCX and with the legacy
# clsact/tc fallback (FLUXVM_TCX=off) -- inside a PRIVATE network + mount namespace, so a live
# host's own interfaces, sysfs and bpffs are never touched. sysfs and bpffs are remounted inside
# because the loader reads ifindexes from /sys/class/net and pins programs under /sys/fs/bpf.
#
#   sudo ./scripts/test-direct-uplink.sh
#   sudo FLUXVM_UPLINK_TEST_BIN=/path/to/direct_uplink-<hash> FLUXVM_BPF_DIR=dist/bpf ./scripts/test-direct-uplink.sh
#
# The test binary comes from FLUXVM_UPLINK_TEST_BIN, or is built with cargo when root can run it
# (build it as your own user first if root has no toolchain: `cargo test -p fluxvm-network
# --test direct_uplink --no-run`).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say()  { echo "test-direct-uplink: $*"; }
skip() { say "SKIP: $*"; exit 0; }

[[ "$(uname -s)" == "Linux" ]] || skip "Linux required"
[[ "$(id -u)" -eq 0 ]] || skip "root required (run with sudo)"
for c in ip tc bpftool python3 unshare mount; do
  command -v "$c" >/dev/null || skip "$c not found"
done

WORK="$(mktemp -d "${TMPDIR:-/tmp}/direct-uplink.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

if [[ -n "${FLUXVM_BPF_DIR:-}" ]]; then
  BPF="$FLUXVM_BPF_DIR"
else
  command -v clang >/dev/null || skip "clang not found (set FLUXVM_BPF_DIR to prebuilt objects)"
  BPF="$WORK/bpf"
  bash "$ROOT/scripts/build-ebpf.sh" "$BPF" >/dev/null 2>&1 || { say "FAIL: build-ebpf.sh"; exit 1; }
fi

BIN="${FLUXVM_UPLINK_TEST_BIN:-}"
if [[ -z "$BIN" ]]; then
  command -v cargo >/dev/null || skip "no test binary: set FLUXVM_UPLINK_TEST_BIN (build with cargo test --no-run as a normal user)"
  BIN="$(cd "$ROOT" && cargo test -p fluxvm-network --test direct_uplink --no-run 2>&1 | sed -n 's/.*Executable .*(\(.*\))/\1/p' | tail -1)"
  [[ -x "$BIN" ]] || { say "FAIL: could not build the test binary"; exit 1; }
fi
[[ -x "$BIN" ]] || { say "FAIL: $BIN is not executable"; exit 1; }

FAILS=0
run_case() { # label [extra env...]
  local label="$1"; shift
  echo "== $label =="
  if timeout 240 unshare --net --mount -- bash -c '
        set -e
        mount --make-rprivate /
        mount -t sysfs sysfs /sys
        mount -t bpf bpf /sys/fs/bpf
        exec "$@"
      ' _ env FLUXVM_TEST_ISOLATED=1 FLUXVM_TEST_BPF_DIR="$BPF" "$@" "$BIN" --nocapture --test-threads=1 \
      </dev/null > "$WORK/out.txt" 2>&1; then
    grep -E "inbound attach mode|test result" "$WORK/out.txt" | sed 's/^/  /'
    echo "  ✅ $label"
  else
    FAILS=$((FAILS + 1))
    tail -25 "$WORK/out.txt" | sed 's/^/  /' >&2
    echo "  ❌ $label" >&2
  fi
}

run_case "TCX (default attach)"
run_case "legacy clsact/tc (FLUXVM_TCX=off)" FLUXVM_TCX=off

echo
if [[ "$FAILS" -eq 0 ]]; then echo "🎉 direct uplink test PASS"; else echo "direct uplink test: $FAILS FAILED" >&2; exit 1; fi
