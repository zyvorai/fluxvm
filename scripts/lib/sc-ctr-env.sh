#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Source from SC e2e scripts: sets CTR / CONTAINERD_ADDRESS for root-only sockets.
# shellcheck shell=bash
if [[ -z "${CTR:-}" ]]; then
  if [[ -S "${CONTAINERD_ADDRESS:-/run/containerd/containerd.sock}" && -w "${CONTAINERD_ADDRESS:-/run/containerd/containerd.sock}" ]]; then
    CTR=ctr
  else
    CTR="sudo -n ctr"
  fi
fi
export CTR
export CONTAINERD_ADDRESS="${CONTAINERD_ADDRESS:-/run/containerd/containerd.sock}"
# Convenience: ctr invocations that take --address
ctr_addr() {
  # shellcheck disable=SC2086
  $CTR --address "$CONTAINERD_ADDRESS" "$@"
}
