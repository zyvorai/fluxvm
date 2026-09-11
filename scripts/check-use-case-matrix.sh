#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Fail if any row in the Secure Containers use-case matrix points at a missing
# test target. Live-only rows still require the script/file to exist on disk.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MATRIX="${ROOT}/docs/secure-containers-use-case-matrix.md"
[[ -f "$MATRIX" ]] || { echo "missing $MATRIX" >&2; exit 2; }

missing=0
checked=0
while IFS= read -r line; do
  case "$line" in
    \|---*|'#'*) continue ;;
  esac
  case "$line" in
    \|*) ;;
    *) continue ;;
  esac
  # Fields: empty | ID | use case | set | target | job | live | empty
  target="$(printf '%s\n' "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$5); gsub(/`/,"",$5); print $5}')"
  id="$(printf '%s\n' "$line" | awk -F'|' '{gsub(/^[[:space:]]+|[[:space:]]+$/,"",$2); print $2}')"
  if [[ "$id" == "ID" || -z "$target" || "$target" == "Test target" ]]; then
    continue
  fi
  checked=$((checked + 1))
  path="${ROOT}/${target}"
  if [[ ! -e "$path" ]]; then
    echo "MISSING: $id -> $target" >&2
    missing=$((missing + 1))
  fi
done < "$MATRIX"

if [[ "$checked" -lt 10 ]]; then
  echo "use-case matrix: parsed too few rows ($checked)" >&2
  exit 1
fi
if [[ "$missing" -ne 0 ]]; then
  echo "use-case matrix: $missing missing target(s) of $checked" >&2
  exit 1
fi
echo "use-case matrix: $checked test targets present"
