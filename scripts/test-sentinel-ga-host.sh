#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
"$ROOT/scripts/test-sentinel-ga-static.sh"
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
TARGET="$TMP/target"
MANIFESTS="$TMP/manifests"
mkdir -p "$TARGET/owned" "$TARGET/foreign"
# Manifests live in a tree mirroring $TARGET, never inside it -- a real
# bpffs target has no create() for plain files (only `mkdir` and
# BPF-object pins), confirmed against a real kernel.
python3 "$ROOT/tools/fluxvm-sentinel-certify.py" write-owner-manifest "$TARGET/owned" \
  --pid 99999999 --component host-test --target-root "$TARGET" --manifest-root "$MANIFESTS" >/dev/null
# Age the test manifest without depending on filesystem timestamp semantics.
python3 - "$MANIFESTS/owned/.fluxvm-owner.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); d['created_unix']=1; open(p,'w').write(json.dumps(d)+'\n')
PY
mkdir -p "$MANIFESTS/foreign"
printf '%s\n' '{"owner_magic":"foreign","owner_pid":99999999,"created_unix":1}' > "$MANIFESTS/foreign/.fluxvm-owner.json"
python3 "$ROOT/tools/fluxvm-sentinel-certify.py" reconcile --root "$TARGET" --manifest-root "$MANIFESTS" --min-age-seconds 0 --apply > "$TMP/reconcile.json"
[[ ! -d "$TARGET/owned" ]]
[[ -d "$TARGET/foreign" ]]
# Full destructive BPF pressure tests are opt-in and lab-gated.
if [[ "${FLUXVM_SENTINEL_FAILURE_INJECTION:-0}" == "1" ]]; then
  "$ROOT/scripts/sentinel-ga-failure-injection.sh"
fi
echo "Sentinel Set 12E host gates passed"
