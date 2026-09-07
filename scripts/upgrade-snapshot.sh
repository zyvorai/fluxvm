#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Snapshot / restore FluxVM state_dir before pairing an upgrade with Fabric.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  upgrade-snapshot.sh snapshot --tag TAG [--state-dir DIR] [--config FILE] [--backup-root DIR]
  upgrade-snapshot.sh restore  --tag TAG [--state-dir DIR] [--config FILE] [--backup-root DIR]
  upgrade-snapshot.sh verify   [--base-url URL]

Defaults match fluxvm config.example.toml:
  state-dir   /var/lib/fluxvm
  config      /etc/fluxvm.toml
  backup-root /var/lib/fluxvm/upgrade-snapshots
  base-url    http://127.0.0.1:7788
EOF
}

cmd="${1:-}"
shift || true
TAG=""
STATE_DIR="${FLUXVM_STATE_DIR:-/var/lib/fluxvm}"
CONFIG="${FLUXVM_CONFIG:-/etc/fluxvm.toml}"
BACKUP_ROOT="${FLUXVM_UPGRADE_BACKUP_ROOT:-/var/lib/fluxvm/upgrade-snapshots}"
BASE_URL="${FLUXVM_URL:-http://127.0.0.1:7788}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --tag) TAG="$2"; shift 2 ;;
    --state-dir) STATE_DIR="$2"; shift 2 ;;
    --config) CONFIG="$2"; shift 2 ;;
    --backup-root) BACKUP_ROOT="$2"; shift 2 ;;
    --base-url) BASE_URL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg $1" >&2; usage; exit 2 ;;
  esac
done

need_tag() {
  [[ -n "$TAG" && "$TAG" =~ ^[A-Za-z0-9._-]+$ ]] || {
    echo "error: valid --tag required" >&2
    exit 2
  }
}

do_snapshot() {
  need_tag
  local dest="$BACKUP_ROOT/$TAG"
  mkdir -p "$dest" "$STATE_DIR"
  tar -C "$(dirname "$STATE_DIR")" -czf "$dest/state.tar.gz" "$(basename "$STATE_DIR")"
  if [[ -f "$CONFIG" ]]; then
    cp -a "$CONFIG" "$dest/fluxvm.toml"
  fi
  {
    echo "tag=$TAG"
    echo "created=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "state_dir=$STATE_DIR"
    echo "fluxvm_version=${FLUXVM_VERSION:-unknown}"
  } >"$dest/MANIFEST"
  echo "snapshot written: $dest"
}

do_restore() {
  need_tag
  local dest="$BACKUP_ROOT/$TAG"
  [[ -f "$dest/state.tar.gz" ]] || {
    echo "error: snapshot $TAG missing" >&2
    exit 1
  }
  mkdir -p "$(dirname "$STATE_DIR")"
  tar -C "$(dirname "$STATE_DIR")" -xzf "$dest/state.tar.gz"
  if [[ -f "$dest/fluxvm.toml" ]]; then
    mkdir -p "$(dirname "$CONFIG")"
    cp -a "$dest/fluxvm.toml" "$CONFIG"
  fi
  echo "restored $TAG"
}

do_verify() {
  local code
  code="$(curl -sS -m 2 -o /dev/null -w '%{http_code}' "$BASE_URL/healthz" || true)"
  echo "healthz_http=$code"
  [[ "$code" == "200" ]]
}

case "$cmd" in
  snapshot) do_snapshot ;;
  restore) do_restore ;;
  verify) do_verify ;;
  ""|-h|--help) usage ;;
  *) echo "unknown command $cmd" >&2; usage; exit 2 ;;
esac
