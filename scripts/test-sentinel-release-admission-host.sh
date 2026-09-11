#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export PYTHONDONTWRITEBYTECODE=1
python3 "$ROOT/tools/fluxvm_release_admission.py" --help >/dev/null
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
printf candidate >"$TMP/artifact"
SHA="$(sha256sum "$TMP/artifact" | awk '{print $1}')"
printf '{"status":"pass"}\n' >"$TMP/evidence.json"
ESHA="$(sha256sum "$TMP/evidence.json" | awk '{print $1}')"
cat >"$TMP/plan.json" <<EOF
{"schema_version":1,"admission_id":"host-smoke","candidate":{"release_id":"smoke","artifact_path":"$TMP/artifact","artifact_sha256":"$SHA","state_abis":{}},"evidence":[{"name":"smoke","path":"$TMP/evidence.json","sha256":"$ESHA","assertions":[{"pointer":"/status","op":"eq","value":"pass"}]}],"nodes":[{"name":"node-a","host":"127.0.0.1"}],"policy":{"min_reachable_percent":0,"min_compatible_percent":0,"max_unreachable_nodes":1}}
EOF
python3 "$ROOT/tools/fluxvm_release_admission.py" validate "$TMP/plan.json" >/dev/null
python3 - <<'PY' "$ROOT/tools/fluxvm_release_admission.py" "$TMP/plan.json"
import importlib.util,json,pathlib,sys
p=sys.argv[1]; spec=importlib.util.spec_from_file_location('a',p); m=importlib.util.module_from_spec(spec); sys.modules[spec.name]=m; spec.loader.exec_module(m)
plan=m.validate(json.load(open(sys.argv[2]))); assert m.verify_candidate(plan)['ok']; assert m.verify_evidence_entry(plan['evidence'][0])['ok']
PY
echo "Set 17E host smoke: PASS"
