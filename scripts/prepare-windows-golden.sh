#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Resolve a Windows golden qcow2 for FluxVM from the sibling Kryton checkout
# (https://github.com/zyvorai/kryton). Optionally build via Kryton's
# build-golden-image.sh, then install under /var/lib/fluxvm/images/.
#
# Usage:
#   ./scripts/prepare-windows-golden.sh
#   ./scripts/prepare-windows-golden.sh --build --version 11e
#   ./scripts/prepare-windows-golden.sh --build --version tiny11 --image-id windows-tiny11
#   KRYTON_WINDOWS_IMAGE=/path/to/golden.qcow2 ./scripts/prepare-windows-golden.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PARENT="$(cd "$ROOT/.." && pwd)"

VERSION="${VERSION:-11e}"
IMAGE_ID="${IMAGE_ID:-}"
BUILD=0
DEST_DIR="${DEST_DIR:-/var/lib/fluxvm/images}"
KRYTON_DIR="${KRYTON_DIR:-$PARENT/kryton}"
SRC="${KRYTON_WINDOWS_IMAGE:-${WINDOWS_IMAGE:-}}"

usage() {
  cat <<EOF
Prepare a Kryton Windows golden qcow2 for FluxVM.

Options:
  --build              Run Kryton scripts/build-golden-image.sh --auto
  --version CODE       dockur VERSION (default: 11e; tiny11, core11, 2025, …)
  --image-id ID        Kryton catalog id (default: Kryton map for VERSION)
  --kryton-dir PATH    Sibling Kryton checkout (default: ../kryton)
  --dest-dir PATH      Install directory (default: /var/lib/fluxvm/images)
  -h, --help           Show this help

Env:
  KRYTON_WINDOWS_IMAGE / WINDOWS_IMAGE   Existing golden qcow2 (skips --build)
  VERSION, IMAGE_ID, KRYTON_DIR, DEST_DIR
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --build) BUILD=1; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    --image-id) IMAGE_ID="$2"; shift 2 ;;
    --kryton-dir) KRYTON_DIR="$2"; shift 2 ;;
    --dest-dir) DEST_DIR="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

default_image_id() {
  case "$1" in
    11e) echo windows-11-enterprise ;;
    11) echo windows-11-pro ;;
    10) echo windows-10-pro ;;
    tiny11) echo windows-tiny11 ;;
    core11) echo windows-tiny11-core ;;
    2025) echo windows-server-2025 ;;
    2022) echo windows-server-2022 ;;
    2019) echo windows-server-2019 ;;
    *) echo "windows-${1}" ;;
  esac
}

if [[ -z "$IMAGE_ID" ]]; then
  IMAGE_ID="$(default_image_id "$VERSION")"
fi

GOLDEN_NAME="windows-${VERSION}-golden.qcow2"
KRYTON_OUT="${KRYTON_DIR}/out/${GOLDEN_NAME}"
DEST="${DEST_DIR}/${GOLDEN_NAME}"

if [[ -z "$SRC" && "$BUILD" -eq 1 ]]; then
  if [[ ! -x "${KRYTON_DIR}/scripts/build-golden-image.sh" ]]; then
    echo "error: Kryton not found at ${KRYTON_DIR}" >&2
    echo "  clone https://github.com/zyvorai/kryton next to fluxvm, or pass --kryton-dir" >&2
    exit 1
  fi
  echo "==> building golden via Kryton (VERSION=${VERSION} IMAGE_ID=${IMAGE_ID})"
  echo "    this can take 45–90+ minutes; console often on :8006 / :8066"
  (
    cd "$KRYTON_DIR"
    VERSION="$VERSION" KRYTON_IMAGE_ID="$IMAGE_ID" IMAGE_ID="$IMAGE_ID" \
      ./scripts/build-golden-image.sh --auto --version "$VERSION" --image-id "$IMAGE_ID"
  )
  SRC="$KRYTON_OUT"
fi

if [[ -z "$SRC" ]]; then
  if [[ -f "$KRYTON_OUT" ]]; then
    SRC="$KRYTON_OUT"
  elif [[ -f "$DEST" ]]; then
    SRC="$DEST"
  else
    echo "error: no golden image found" >&2
    echo "  set KRYTON_WINDOWS_IMAGE, or run with --build, or place ${KRYTON_OUT}" >&2
    echo "  see docs/windows-golden.md" >&2
    exit 1
  fi
fi

if [[ ! -f "$SRC" ]]; then
  echo "error: golden not found: $SRC" >&2
  exit 1
fi

if [[ "$SRC" -ef "$DEST" ]] 2>/dev/null || [[ "$(cd "$(dirname "$SRC")" && pwd)/$(basename "$SRC")" == "$(cd "$(dirname "$DEST")" 2>/dev/null && pwd)/$(basename "$DEST")" ]]; then
  echo "OK: golden already at $DEST"
  echo "$DEST"
  exit 0
fi

echo "==> installing $SRC → $DEST"
if [[ -w "$(dirname "$DEST")" ]] 2>/dev/null || mkdir -p "$DEST_DIR" 2>/dev/null; then
  :
else
  echo "note: need write access to $DEST_DIR (try sudo)" >&2
fi

if [[ ! -w "$DEST_DIR" ]]; then
  sudo mkdir -p "$DEST_DIR"
  sudo cp -f "$SRC" "$DEST"
  if [[ -f "${SRC}.sha256" ]]; then
    sudo cp -f "${SRC}.sha256" "${DEST}.sha256"
  fi
  if [[ -f "${SRC}.passport.json" ]]; then
    sudo cp -f "${SRC}.passport.json" "${DEST}.passport.json"
  fi
else
  mkdir -p "$DEST_DIR"
  cp -f "$SRC" "$DEST"
  [[ -f "${SRC}.sha256" ]] && cp -f "${SRC}.sha256" "${DEST}.sha256" || true
  [[ -f "${SRC}.passport.json" ]] && cp -f "${SRC}.passport.json" "${DEST}.passport.json" || true
fi

echo "OK: $DEST"
echo "$DEST"
