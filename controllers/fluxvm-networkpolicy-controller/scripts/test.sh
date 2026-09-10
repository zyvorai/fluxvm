#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

cd "$(dirname "$0")/.."

unformatted="$(gofmt -l cmd internal)"
if [[ -n "$unformatted" ]]; then
  echo "gofmt required for:" >&2
  echo "$unformatted" >&2
  exit 1
fi

go vet ./...
go test ./...
go test -race ./...
CGO_ENABLED=0 go build -trimpath -o /tmp/fluxvm-networkpolicy-controller ./cmd/fluxvm-networkpolicy-controller
/tmp/fluxvm-networkpolicy-controller -version
