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
install -D -m0755 "$ROOT/dist/bin/fluxvm-afxdp" /usr/bin/fluxvm-afxdp
install -D -m0755 "$ROOT/dist/bin/fluxvm-afxdp-loader" /usr/libexec/fluxvm/fluxvm-afxdp-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-afxdp-worker" /usr/libexec/fluxvm/fluxvm-afxdp-worker
install -D -m0755 "$ROOT/dist/bin/fluxvm-afxdp-events" /usr/libexec/fluxvm/fluxvm-afxdp-events
install -D -m0755 "$ROOT/dist/bin/fluxvm-quiclb" /usr/bin/fluxvm-quiclb
install -D -m0755 "$ROOT/dist/bin/fluxvm-quiclb-loader" /usr/libexec/fluxvm/fluxvm-quiclb-loader
install -D -m0755 "$ROOT/dist/bin/fluxvm-quiclb-events" /usr/libexec/fluxvm/fluxvm-quiclb-events
install -D -m0755 "$ROOT/dist/bin/fluxvm-scx" /usr/bin/fluxvm-scx
if [[ -x "$ROOT/dist/bin/fluxvm-scx-loader" && -x "$ROOT/dist/bin/fluxvm-scx-taskctl" && -x "$ROOT/dist/bin/fluxvm-scx-events" ]]; then
  install -D -m0755 "$ROOT/dist/bin/fluxvm-scx-loader" /usr/libexec/fluxvm/fluxvm-scx-loader
  install -D -m0755 "$ROOT/dist/bin/fluxvm-scx-taskctl" /usr/libexec/fluxvm/fluxvm-scx-taskctl
  install -D -m0755 "$ROOT/dist/bin/fluxvm-scx-events" /usr/libexec/fluxvm/fluxvm-scx-events
fi
install -D -m0644 "$ROOT/dist/bpf/fluxvm_intelligence.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_intelligence.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_guard.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_guard.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_xdp_shield.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_xdp_shield.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_tcp_intel.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_tcp_intel.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_memprof.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_memprof.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_topology.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_topology.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_afxdp.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_afxdp.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_quiclb.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_quiclb.bpf.o
install -D -m0644 "$ROOT/dist/bpf/fluxvm_quiclb_hw.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_quiclb_hw.bpf.o
[[ ! -f "$ROOT/dist/bpf/fluxvm_scx.bpf.o" ]] || install -D -m0644 "$ROOT/dist/bpf/fluxvm_scx.bpf.o" /usr/lib/fluxvm/bpf/fluxvm_scx.bpf.o
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-netintel.service" /etc/systemd/system/fluxvm-netintel.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-memprof.service" /etc/systemd/system/fluxvm-memprof.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-topology.service" /etc/systemd/system/fluxvm-topology.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-afxdp.service" /etc/systemd/system/fluxvm-afxdp.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-quiclb.service" /etc/systemd/system/fluxvm-quiclb.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-scx.service" /etc/systemd/system/fluxvm-scx.service
install -D -m0644 "$ROOT/packaging/systemd/fluxvm-guard.service" /etc/systemd/system/fluxvm-guard.service
install -D -m0644 "$ROOT/deploy/systemd/fluxvm-intelligence.service" /etc/systemd/system/fluxvm-intelligence.service
systemctl daemon-reload
systemctl enable --now fluxvm-intelligence.service
systemctl enable --now fluxvm-netintel.service
systemctl enable --now fluxvm-memprof.service
systemctl enable --now fluxvm-topology.service
systemctl enable --now fluxvm-afxdp.service
systemctl enable --now fluxvm-quiclb.service
systemctl enable --now fluxvm-scx.service
if grep -Eq '(^|,)bpf(,|$)' /sys/kernel/security/lsm 2>/dev/null; then
  systemctl enable --now fluxvm-guard.service
else
  echo "VMM Guard installed but not enabled: BPF LSM is unavailable on this host" >&2
fi
