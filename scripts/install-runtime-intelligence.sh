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
install -D -m0755 "$ROOT/dist/bin/fluxvm-shield" /usr/bin/fluxvm-shield
install -D -m0755 "$ROOT/dist/bin/fluxvm-tcpintel" /usr/bin/fluxvm-tcpintel
install -D -m0755 "$ROOT/dist/bin/fluxvm-netintel" /usr/bin/fluxvm-netintel
install -D -m0755 "$ROOT/dist/bin/fluxvm-xdp-shield-loader" /usr/libexec/fluxvm/fluxvm-xdp-shield-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-shield-events" /usr/libexec/fluxvm/fluxvm-shield-events
install -D -m0755 "$ROOT/dist/bin/fluxvm-tcp-loader" /usr/libexec/fluxvm/fluxvm-tcp-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-tcp-events" /usr/libexec/fluxvm/fluxvm-tcp-events
install -D -m0755 "$ROOT/dist/bin/fluxvm-memprof" /usr/bin/fluxvm-memprof
install -D -m0755 "$ROOT/dist/bin/fluxvm-memprof-loader" /usr/libexec/fluxvm/fluxvm-memprof-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-memprof-events" /usr/libexec/fluxvm/fluxvm-memprof-events
install -D -m0755 "$ROOT/dist/bin/fluxvm-topology" /usr/bin/fluxvm-topology
install -D -m0755 "$ROOT/dist/bin/fluxvm-topology-loader" /usr/libexec/fluxvm/fluxvm-topology-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-topology-events" /usr/libexec/fluxvm/fluxvm-topology-events
install -D -m0644 "$ROOT/dist/bpf/fluxvm_intelligence.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_intelligence.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_guard.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_guard.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_xdp_shield.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_xdp_shield.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_tcp_intel.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_tcp_intel.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_memprof.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_memprof.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_topology.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_topology.bpf.o
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-netintel.service" /etc/systemd/system/fluxvm-netintel.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-memprof.service" /etc/systemd/system/fluxvm-memprof.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-topology.service" /etc/systemd/system/fluxvm-topology.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-guard.service" /etc/systemd/system/fluxvm-guard.service
install -D -m0644 "$ROOT/deploy/systemd/fluxvm-intelligence.service" /etc/systemd/system/fluxvm-intelligence.service
systemctl daemon-reload
systemctl enable --now fluxvm-intelligence.service
systemctl enable --now fluxvm-netintel.service
systemctl enable --now fluxvm-memprof.service
systemctl enable --now fluxvm-topology.service
if grep -Eq '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
  systemctl enable --now fluxvm-guard.service
else
  echo "VMM Guard installed but not enabled: BPF LSM is unavailable on this host" >&2
fi
