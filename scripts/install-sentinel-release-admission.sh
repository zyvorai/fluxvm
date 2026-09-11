#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DESTDIR="${DESTDIR:-}"
install -d "$DESTDIR/usr/libexec/fluxvm" "$DESTDIR/usr/share/fluxvm/schemas" "$DESTDIR/usr/share/doc/fluxvm/examples"
install -m 0755 "$ROOT/tools/fluxvm_release_admission.py" "$DESTDIR/usr/libexec/fluxvm/fluxvm-admit"
install -m 0644 "$ROOT/schemas/sentinel-release-admission.schema.json" "$DESTDIR/usr/share/fluxvm/schemas/"
install -m 0644 "$ROOT/examples/sentinel-release-admission.json" "$DESTDIR/usr/share/doc/fluxvm/examples/"
if [[ -z "$DESTDIR" ]]; then
  ln -sfn /usr/libexec/fluxvm/fluxvm-admit /usr/local/bin/fluxvm-admit
fi
