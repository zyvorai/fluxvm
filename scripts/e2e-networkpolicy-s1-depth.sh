#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# S1 depth — mid-flow kill + live SYN anti-replay under load.
set -euo pipefail
NS="${S1_NAMESPACE:-fluxvm-s1-depth-$RANDOM}"
KUBECTL="${KUBECTL:-kubectl}"
RUNTIME_CLASS="${RUNTIME_CLASS:-${FLUXVM_RUNTIMECLASS:-}}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 2; }; }
need "$KUBECTL"

cleanup() { "$KUBECTL" delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
"$KUBECTL" create ns "$NS"

RC_YAML=""
if [[ -n "$RUNTIME_CLASS" ]]; then
  RC_YAML="  runtimeClassName: ${RUNTIME_CLASS}"
fi

cat <<YAML | "$KUBECTL" -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata: {name: server, labels: {app: server}}
spec:
${RC_YAML}
  containers:
  - name: server
    image: python:3.13-alpine
    command: ["python3","-m","http.server","8080"]
    ports: [{name: http, containerPort: 8080, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata: {name: client, labels: {app: client}}
spec:
${RC_YAML}
  containers:
  - name: client
    image: python:3.13-alpine
    command: ["sh","-c","sleep 3600"]
YAML
"$KUBECTL" -n "$NS" wait --for=condition=Ready pod/server pod/client --timeout=240s
SERVER_IP="$("$KUBECTL" -n "$NS" get pod server -o jsonpath='{.status.podIP}')"

apply_allow() {
  cat <<YAML | "$KUBECTL" -n "$NS" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: client-allow}
spec:
  podSelector: {matchLabels: {app: client}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress:
  - to:
    - podSelector: {matchLabels: {app: server}}
    ports: [{protocol: TCP, port: 8080}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: server-allow}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress, Egress]
  ingress:
  - from:
    - podSelector: {matchLabels: {app: client}}
    ports: [{protocol: TCP, port: 8080}]
  egress: []
YAML
}

apply_deny_client() {
  cat <<'YAML' | "$KUBECTL" -n "$NS" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: client-allow}
spec:
  podSelector: {matchLabels: {app: client}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
YAML
}

apply_allow
sleep 3

# ---- (1) Mid-flow kill ----
# Start a background HTTP/1.1 keepalive reader inside the client, revoke
# egress, and require subsequent reads to fail (CT cleared → drop).
"$KUBECTL" -n "$NS" exec client -- python3 -c "
import http.client, time, sys
c = http.client.HTTPConnection('${SERVER_IP}', 8080, timeout=5)
c.request('GET', '/')
r = c.getresponse(); r.read(1)
print('mid-flow established', flush=True)
open('/tmp/s1-hold','w').write('1')
# Hold the connection open; outer script will revoke, then we keep reading.
deadline = time.time() + 12
alive_after = False
while time.time() < deadline:
    try:
        c.request('GET', '/')
        r = c.getresponse(); r.read(64)
        alive_after = True
        time.sleep(0.5)
    except Exception as e:
        print('mid-flow terminated:', type(e).__name__, flush=True)
        sys.exit(0)
print('FAIL: mid-flow still alive after revoke window', file=sys.stderr)
sys.exit(1)
" &
MIDPID=$!
# Wait until session marker exists
for _ in $(seq 1 30); do
  if "$KUBECTL" -n "$NS" exec client -- test -f /tmp/s1-hold 2>/dev/null; then
    break
  fi
  sleep 0.2
done
apply_deny_client
sleep 4
if ! wait "$MIDPID"; then
  echo "FAIL: mid-flow kill check failed" >&2
  exit 1
fi
printf '%s\n' 'PASS: S1 mid-flow kill (held TCP died after CT-clear revoke)'

# ---- (2) Live SYN anti-replay under load ----
apply_allow
sleep 2
"$KUBECTL" -n "$NS" exec client -- python3 -c "
import concurrent.futures, urllib.request
url='http://${SERVER_IP}:8080/'
def one(_):
    with urllib.request.urlopen(url, timeout=3) as r:
        r.read(16)
    return True
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    list(ex.map(one, range(64)))
print('churn: 64 ok', flush=True)
with concurrent.futures.ThreadPoolExecutor(max_workers=32) as ex:
    list(ex.map(one, range(64)))
print('churn: 64 reuse SYNs ok', flush=True)
"
apply_deny_client
sleep 2
if "$KUBECTL" -n "$NS" exec client -- python3 -c "
import urllib.request
urllib.request.urlopen('http://${SERVER_IP}:8080/', timeout=2).read(8)
" >/dev/null 2>&1; then
  echo "FAIL: new SYN survived after hot-CT revoke" >&2
  exit 1
fi
printf '%s\n' 'PASS: S1 live SYN anti-replay under load (hot CT + revoke)'
printf '%s\n' 'S1 DEPTH: PASS'
