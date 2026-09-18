#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Enable Network Fabric (GA; dataplane schema v4) on this host: ensure BPF
# objects, merge a dataplane profile into /etc/fluxvm.toml, restart when
# requested. Does not change the upgrade-safe code default (mode=legacy).
#
# Usage:
#   sudo ./scripts/enable-network-fabric-ga.sh
#   sudo ./scripts/enable-network-fabric-ga.sh --config /etc/fluxvm.toml --restart
#   sudo ./scripts/enable-network-fabric-ga.sh --lab --restart
#   sudo ./scripts/enable-network-fabric-ga.sh --cilium --restart
#   sudo ./scripts/enable-network-fabric-ga.sh --dry-run
#
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
BPF_TC="/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
BPF_XDP="/usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o"
RESTART=0
MODE=ebpf
PROFILE=ga
DRY=0
SKIP_PREFLIGHT=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config) CONFIG="$2"; shift 2 ;;
    --restart) RESTART=1; shift ;;
    --cilium) MODE=cilium; shift ;;
    --lab) PROFILE=lab; shift ;;
    --dry-run) DRY=1; shift ;;
    --skip-preflight) SKIP_PREFLIGHT=1; shift ;;
    -h|--help)
      sed -n '2,18p' "$0"
      exit 0
      ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing: $1" >&2; exit 1; }; }
need python3

FRAG="$ROOT/configs/network-fabric-${PROFILE}.toml"
[[ -f "$FRAG" ]] || { echo "missing profile fragment: $FRAG" >&2; exit 1; }

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

if [[ $SKIP_PREFLIGHT -eq 0 && $DRY -eq 0 ]]; then
  echo "==> Network Fabric preflight"
  FLUXVM_BPF_TC="$BPF_TC" "$ROOT/scripts/network-fabric-preflight.sh" --require-bpf
fi

MARKER_START="# --- Network Fabric GA schema v4 (managed by enable-network-fabric-ga.sh) ---"
MARKER_END="# --- end Network Fabric GA schema v4 ---"

GA_TMP="$(mktemp)"
trap 'rm -f "$GA_TMP"' EXIT

{
  echo "$MARKER_START"
  # Extract [sandbox.dataplane] keys from the profile SoT; rewrite mode for --cilium.
  python3 - "$FRAG" "$MODE" <<'PY'
import sys
from pathlib import Path
lines = Path(sys.argv[1]).read_text().splitlines()
mode = sys.argv[2]
in_section = False
out = []
for line in lines:
    stripped = line.strip()
    if stripped.startswith("[") and stripped.endswith("]"):
        in_section = stripped == "[sandbox.dataplane]"
        if in_section:
            out.append(line)
        continue
    if not in_section:
        continue
    if stripped.startswith("mode ="):
        out.append(f'mode = "{mode}"')
    elif stripped.startswith("#") or stripped == "":
        continue
    else:
        out.append(line)
print("\n".join(out).rstrip())
PY
  echo "$MARKER_END"
} >"$GA_TMP"

echo "==> merging Network Fabric ${PROFILE} profile into $CONFIG (mode=${MODE})"
if [[ $DRY -eq 1 ]]; then
  cat "$GA_TMP"
  exit 0
fi

if [[ ! -f "$CONFIG" ]]; then
  echo "config not found: $CONFIG (copy config.example.toml first)" >&2
  exit 1
fi

python3 - "$CONFIG" "$GA_TMP" "$MARKER_START" "$MARKER_END" <<'PY'
import re, sys
from pathlib import Path
cfg_path, frag_path = Path(sys.argv[1]), Path(sys.argv[2])
text = cfg_path.read_text()
frag = frag_path.read_text().rstrip() + "\n"
# Drop any previous managed GA block (current or legacy markers).
text = re.sub(
    r"\n?# --- Network Fabric (?:GA schema v4|v3 GA).*?# --- end Network Fabric (?:GA schema v4|v3 GA) ---\n?",
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
            out.append(f"# superseded by Network Fabric GA schema v4\n# {line}")
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
print(f"wrote {sys.argv[1]} Network Fabric profile into {cfg_path}")
PY

if [[ $RESTART -eq 1 ]]; then
  if systemctl is-enabled fluxvm >/dev/null 2>&1 || systemctl cat fluxvm >/dev/null 2>&1; then
    echo "==> restarting fluxvm"
    systemctl restart fluxvm
    systemctl --no-pager -l status fluxvm | head -20
    echo "==> post-restart health (best-effort)"
    if command -v fluxctl >/dev/null 2>&1; then
      fluxvm dataplane health || true
    else
      echo "fluxvm not on PATH; skip dataplane health"
    fi
    FLUXVM_BPF_TC="$BPF_TC" "$ROOT/scripts/network-fabric-preflight.sh" --require-bpf || true
  else
    echo "fluxvm unit not found; restart your serve process manually" >&2
  fi
fi

echo "Network Fabric GA (schema v4) enabled (profile=${PROFILE}, mode=${MODE})."
if [[ "$PROFILE" == "lab" ]]; then
  echo "Lab profile: required=false, default_allow=true (not fail-closed)."
else
  echo "GA profile: required=true, default_allow=false (fail-closed on host-visible edges)."
fi
echo "Verify: fluxvm dataplane health"
echo "        curl -sS http://127.0.0.1:7788/v1/vms/<uuid>/network/status"
echo "Note: after a control-plane restart, a live VM may keep a pre-restart TC"
echo "filter (ownership mismatch). Detach once, then reconcile reattaches:"
echo "  sudo tc filter del dev <vh*|tap*> ingress"
echo "Docs: docs/network-fabric.md · docs/production-dataplane.md"
