#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
[[ ${EUID:-$(id -u)} -eq 0 ]] || { echo "run as root" >&2; exit 2; }
"$ROOT/scripts/build-runtime-intelligence.sh"
install -D -m0755 "$ROOT/dist/bin/fluxvm-intelligence" /usr/bin/fluxvm-intelligence
install -D -m0755 "$ROOT/dist/bin/fluxvm-intelligence-loader" /usr/libexec/fluxvm/fluxvm-intelligence-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-tcx" /usr/libexec/fluxvm/fluxvm-tcx
install -D -m0755 "$ROOT/dist/bin/fluxvm-flight-reader" /usr/libexec/fluxvm/fluxvm-flight-reader
install -D -m0755 "$ROOT/dist/bin/fluxvm-guard" /usr/bin/fluxvm-guard
install -D -m0755 "$ROOT/dist/bin/fluxvm-qos" /usr/bin/fluxvm-qos
install -D -m0755 "$ROOT/dist/bin/fluxvm-guard-loader" /usr/libexec/fluxvm/fluxvm-guard-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-guard-events" /usr/libexec/fluxvm/fluxvm-guard-events
install -D -m0644 "$ROOT/dist/bpf/fluxvm_intelligence.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_intelligence.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_guard.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_guard.bpf.o
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-guard.service" /etc/systemd/system/fluxvm-guard.service
install -D -m0644 "$ROOT/deploy/systemd/fluxvm-intelligence.service" /etc/systemd/system/fluxvm-intelligence.service
systemctl daemon-reload
systemctl enable --now fluxvm-intelligence.service
if grep -Eq '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
  systemctl enable --now fluxvm-guard.service
else
  echo "VMM Guard installed but not enabled: BPF LSM is unavailable on this host" >&2
fi
