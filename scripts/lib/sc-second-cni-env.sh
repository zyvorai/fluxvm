#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Source from SC evidence / matrix scripts: load FLUXVM_SECOND_CNI_* if unset.
# shellcheck shell=bash
if [[ -z "${FLUXVM_SECOND_CNI_KUBECONFIG:-}" && -r /etc/fluxvm-second-cni.env ]]; then
  # shellcheck disable=SC1091
  set -a
  # shellcheck disable=SC1091
  source /etc/fluxvm-second-cni.env
  set +a
fi
if [[ -z "${FLUXVM_SECOND_CNI_KUBECONFIG:-}" && -r "${HOME}/.config/fluxvm/second-cni.env" ]]; then
  # shellcheck disable=SC1090
  source "${HOME}/.config/fluxvm/second-cni.env"
fi
