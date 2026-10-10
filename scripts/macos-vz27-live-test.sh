#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Hardware gate for the macOS 27 VZ feature set. Run on Apple silicon with
# Xcode 27/current SDK after `cargo build -p fluxvm-apple`.
set -euo pipefail

: "${FLUXVM_VZ_RUNNER:?set FLUXVM_VZ_RUNNER to the built fluxvm-vz-runner}"
: "${FLUXVM_VZ_TEST_CONFIG:?set FLUXVM_VZ_TEST_CONFIG to a Linux VZ config JSON with custom_virtio=true}"

[[ "$(uname -s)" == Darwin ]] || { echo "SKIP: macOS required"; exit 77; }
major="$(sw_vers -productVersion | cut -d. -f1)"
(( major >= 27 )) || { echo "SKIP: macOS 27+ required"; exit 77; }

"$FLUXVM_VZ_RUNNER" check --config "$FLUXVM_VZ_TEST_CONFIG"

# The runner's source-contract tests prove that custom_virtio is backed by a
# provider/delegate. This live gate proves VZ accepts the full configuration on
# the current hardware/SDK. A guest driver test can be layered on once the
# Linux virtio-flux driver is installed in the image.
echo "PASS: VZ configuration accepted on macOS $(sw_vers -productVersion)"
