#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Enable Network Fabric v3 GA on this host: ensure BPF objects, merge the GA
# dataplane profile into /etc/fluxvm.toml, restart fluxvm when requested.
#
# Usage:
#   sudo ./scripts/enable-network-fabric-ga.sh
#   sudo ./scripts/enable-network-fabric-ga.sh --config /etc/fluxvm.toml --restart
#   sudo ./scripts/enable-network-fabric-ga.sh --cilium --restart
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
BPF_TC="/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
BPF_XDP="/usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o"
RESTART=0
MODE=ebpf
DRY=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --restart) RESTART=1; shift ;;
    --cilium) MODE=cilium; shift ;;
    --dry-run) DRY=1; shift ;;
    -h|--help)
      sed -n '2,14p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need python3

if [[ ! -f "$BPF_TC" ]]; then
  echo "==> building + installing eBPF objects"
  if [[ $DRY -eq 1 ]]; then
    echo "DRY: would run build-ebpf.sh and install $BPF_TC"
  else
    "$ROOT/scripts/build-ebpf.sh"
    install -D -m 0644 "$ROOT/dist/bpf/fluxvm_tc.bpf.o" "$BPF_TC"
    [[ -f "$ROOT/dist/bpf/fluxvm_xdp.bpf.o" ]] && \
      install -D -m 0644 "$ROOT/dist/bpf/fluxvm_xdp.bpf.o" "$BPF_XDP"
  fi
fi
[[ -f "$BPF_TC" || $DRY -eq 1 ]] || { echo "missing $BPF_TC" >&2; exit 1; }

GA_TMP="$(mktemp)"
trap 'rm -f "$GA_TMP"' EXIT
cat >"$GA_TMP" <<EOF
# --- Network Fabric v3 GA (managed by enable-network-fabric-ga.sh) ---
[sandbox.dataplane]
mode = "${MODE}"
bpf_object = "${BPF_TC}"
pin_root = "/sys/fs/bpf/fluxvm"
required = true
default_allow = false
allow_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
allow_ports = ["tcp/443", "tcp/80", "udp/53"]
max_egress_mbps = 250
max_egress_pps = 100000
sample_rate = 100
# --- end Network Fabric v3 GA ---
EOF

if [[ ! -f "$CONFIG" ]]; then
  echo "config not found: $CONFIG (copy config.example.toml first)" >&2
  exit 1
fi

echo "==> merging GA dataplane into $CONFIG (mode=${MODE})"
if [[ $DRY -eq 1 ]]; then
  cat "$GA_TMP"
  exit 0
fi

python3 - "$CONFIG" "$GA_TMP" <<'PY'
import re, sys
from pathlib import Path
cfg_path, frag_path = Path(sys.argv[1]), Path(sys.argv[2])
text = cfg_path.read_text()
frag = frag_path.read_text().rstrip() + "\n"
# Drop any previous managed GA block or bare [sandbox.dataplane] section.
text = re.sub(
    r"\n?# --- Network Fabric v3 GA.*?# --- end Network Fabric v3 GA ---\n?",
    "\n",
    text,
    flags=re.S,
)
# If an unmanaged [sandbox.dataplane] remains, comment it out to avoid dup keys.
def comment_section(src: str, header: str) -> str:
    lines = src.splitlines(True)
    out = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if re.match(rf"^\[{re.escape(header)}\]\s*$", line.strip()):
            out.append(f"# superseded by Network Fabric v3 GA\n# {line}")
            i += 1
            while i < len(lines) and not re.match(r"^\[", lines[i]):
                if lines[i].startswith("#") or lines[i].strip() == "":
                    out.append(lines[i])
                else:
                    out.append("# " + lines[i] if not lines[i].startswith("#") else lines[i])
                i += 1
            continue
        out.append(line)
        i += 1
    return "".join(out)

text = comment_section(text, "sandbox.dataplane")
text = comment_section(text, "sandbox.dataplane.xdp")
if not text.endswith("\n"):
    text += "\n"
text += "\n" + frag
bak = cfg_path.with_suffix(cfg_path.suffix + ".bak-pre-ga")
bak.write_text(cfg_path.read_text())
cfg_path.write_text(text)
print(f"backed up previous config to {bak}")
print(f"wrote GA profile into {cfg_path}")
PY

if [[ $RESTART -eq 1 ]]; then
  if systemctl is-enabled fluxvm >/dev/null 2>&1 || systemctl cat fluxvm >/dev/null 2>&1; then
    echo "==> restarting fluxvm"
    systemctl restart fluxvm
    systemctl --no-pager -l status fluxvm | head -20
  else
    echo "fluxvm unit not found; restart your serve process manually" >&2
  fi
fi

echo "Network Fabric v3 GA enabled (mode=${MODE}, required=true)."
echo "Verify: curl -sS http://127.0.0.1:7788/v1/vms/<uuid>/network/status"
echo "Note: after a control-plane restart, a live VM may keep a pre-restart TC"
echo "filter (ownership mismatch). Detach once, then reconcile reattaches:"
echo "  sudo tc filter del dev <vh*|tap*> ingress"
echo "Docs: docs/network-fabric.md"
