#!/bin/bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Example only. Adjust NIC / bridge to your host.
set -euo pipefail
TAP="${1:-tap0}"
USER="${SUDO_USER:-$USER}"
ip tuntap add dev "$TAP" mode tap user "$USER" multi_queue || true
ip link set "$TAP" up
echo "TAP $TAP owned by $USER"
