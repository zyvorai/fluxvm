#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# Destructive kernel/BPF failure injection is deliberately double-gated.
[[ "${FLUXVM_SENTINEL_FAILURE_INJECTION:-0}" == "1" ]] || {
  echo "set FLUXVM_SENTINEL_FAILURE_INJECTION=1 to enable" >&2; exit 2;
}
LAB_MARKER="${FLUXVM_SENTINEL_LAB_MARKER:-/etc/fluxvm/sentinel-lab-host}"
[[ -f "$LAB_MARKER" ]] || { echo "lab marker $LAB_MARKER is required" >&2; exit 2; }
[[ $(id -u) -eq 0 ]] || { echo "root required" >&2; exit 2; }
command -v bpftool >/dev/null || { echo "bpftool required" >&2; exit 2; }
mountpoint -q /sys/fs/bpf || { echo "bpffs must be mounted" >&2; exit 2; }

TMP="/sys/fs/bpf/fluxvm-ga-chaos-$$"
MANIFESTS="/tmp/fluxvm-ga-chaos-manifests-$$"
cleanup() { rm -rf "$TMP" "$MANIFESTS" 2>/dev/null || true; }
trap cleanup EXIT INT TERM
mkdir -p "$TMP" "$MANIFESTS"

# 1) Map-pressure behavior: small hash map must reject insert beyond max_entries.
bpftool map create "$TMP/pressure" type hash key 4 value 8 entries 4 name fluxvm_ga_pressure
for k in 1 2 3 4; do
  hex=$(printf '%08x' "$k" | sed 's/../& /g')
  # shellcheck disable=SC2086
  bpftool map update pinned "$TMP/pressure" key hex $hex value hex 01 00 00 00 00 00 00 00
 done
set +e
bpftool map update pinned "$TMP/pressure" key hex ff ff ff 7f value hex 01 00 00 00 00 00 00 00 >/tmp/fluxvm-ga-pressure.out 2>&1
rc=$?
set -e
if [[ $rc -eq 0 ]]; then
  echo "map-pressure gate failed: over-capacity insert unexpectedly succeeded" >&2
  exit 1
fi

# 2) Ownership/recovery behavior: dead-owner manifest is removed, foreign
# state survives. Manifests live under $MANIFESTS (a real writable
# filesystem), mirroring $TMP's tree -- real bpffs (which $TMP is, a real
# /sys/fs/bpf subdirectory) has no create() for plain files, only `mkdir`
# and BPF-object pins. A prior version of this test wrote manifests
# directly into $TMP and failed with EPERM the first time it actually ran
# against a real kernel with bpftool + root available.
mkdir -p "$TMP/owned" "$TMP/foreign" "$MANIFESTS/owned" "$MANIFESTS/foreign"
cat > "$MANIFESTS/owned/.fluxvm-owner.json" <<JSON
{"owner_magic":"zyvor-fluxvm-sentinel-state-v1","owner_pid":99999999,"component":"chaos","created_unix":1}
JSON
cat > "$MANIFESTS/foreign/.fluxvm-owner.json" <<JSON
{"owner_magic":"foreign","owner_pid":99999999,"component":"chaos","created_unix":1}
JSON
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
python3 "$ROOT/tools/fluxvm-sentinel-certify.py" reconcile --root "$TMP" --manifest-root "$MANIFESTS" --min-age-seconds 0 --apply >/tmp/fluxvm-ga-reconcile.json
[[ ! -e "$TMP/owned" ]] || { echo "owned stale state was not removed" >&2; exit 1; }
[[ -e "$TMP/foreign" ]] || { echo "foreign state was removed" >&2; exit 1; }

echo "Sentinel GA failure-injection gates passed"
