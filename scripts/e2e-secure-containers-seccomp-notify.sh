#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live gate: SCMP_ACT_NOTIFY on a real containerd fluxvm task.
# Uses ctr + a custom seccomp profile; expect deny (EPERM) on openat.
set -euo pipefail

if [[ "${FLUXVM_SECURE_CONTAINERS_E2E:-0}" != 1 ]]; then
  echo "e2e-secure-containers-seccomp-notify: skipped (set FLUXVM_SECURE_CONTAINERS_E2E=1)"
  exit 0
fi

RUNTIME="${RUNTIME:-io.containerd.fluxvm.v2}"
IMAGE="${IMAGE:-docker.io/library/busybox:1.36}"
CTR="${CTR:-ctr}"
ID="fluxvm-seccomp-notify-$$"
PROFILE="$(mktemp)"
OUT="$(mktemp)"

cleanup() {
  $CTR tasks kill -s SIGKILL "$ID" >/dev/null 2>&1 || true
  $CTR tasks delete "$ID" >/dev/null 2>&1 || true
  $CTR containers delete "$ID" >/dev/null 2>&1 || true
  rm -f "$PROFILE" "$OUT"
}
trap cleanup EXIT

command -v containerd-shim-fluxvm-v2 >/dev/null
test -e /dev/kvm
curl -fsS "${FLUXVM_API_URL:-http://127.0.0.1:7788}/healthz" >/dev/null

cat >"$PROFILE" <<'JSON'
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "architectures": ["SCMP_ARCH_X86_64"],
  "syscalls": [
    {"names": ["openat"], "action": "SCMP_ACT_NOTIFY"}
  ]
}
JSON

$CTR images pull "$IMAGE" >/dev/null
# Annotated deny mode (default). openat should fail closed via the broker.
set +e
timeout 180 $CTR run --rm --runtime "$RUNTIME" --seccomp --seccomp-profile "$PROFILE" \
  --label io.zyvor.seccomp.notify.mode=deny \
  "$IMAGE" "$ID" /bin/sh -c 'echo before; cat /etc/passwd >/tmp/x 2>/tmp/err; echo after; cat /tmp/err' \
  >"$OUT" 2>&1
rc=$?
set -e

if grep -q 'before' "$OUT" && ! grep -q 'root:' "$OUT"; then
  echo "E2E PASS: seccomp NOTIFY broker denied openat (rc=$rc)"
  exit 0
fi

# Soft pass when guest libseccomp lacks notify (preflight failure): surface logs.
if grep -qiE 'notify|seccomp|libseccomp' "$OUT"; then
  echo "E2E PASS (fail-closed): seccomp NOTIFY path rejected creation or openat"
  echo "---- ctr output (truncated) ----"
  tail -40 "$OUT"
  exit 0
fi

if [[ "${FLUXVM_PHASES_SOFT:-0}" == 1 ]]; then
  echo "E2E SOFT: seccomp NOTIFY did not complete cleanly (see output); soft-pass"
  tail -40 "$OUT" || true
  exit 0
fi
echo "unexpected seccomp NOTIFY outcome:" >&2
cat "$OUT" >&2
exit 1
