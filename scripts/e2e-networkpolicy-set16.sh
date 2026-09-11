#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Real-cluster gate for Set 16. This script intentionally does not pretend to
# provision FluxVM itself; run it only on a cluster where Secure Containers
# Pods are already backed by FluxVM schema-v9 eBPF VMs.
set -euo pipefail
NS="${SET16_NAMESPACE:-fluxvm-set16-e2e}"
KUBECTL="${KUBECTL:-kubectl}"

need() { command -v "$1" >/dev/null 2>&1 || { echo "missing $1" >&2; exit 2; }; }
need "$KUBECTL"

cleanup() { "$KUBECTL" delete ns "$NS" --ignore-not-found >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup
"$KUBECTL" create ns "$NS"

cat <<'YAML' | "$KUBECTL" -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata: {name: server, labels: {app: server}}
spec:
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
  containers:
  - name: client
    image: curlimages/curl:8.12.1
    command: ["sh","-c","sleep 3600"]
YAML
"$KUBECTL" -n "$NS" wait --for=condition=Ready pod/server pod/client --timeout=180s
SERVER_IP="$($KUBECTL -n "$NS" get pod server -o jsonpath='{.status.podIP}')"

# Server ingress permits client TCP/8080 but egress is deny-all. HTTP response
# must still leave the server through reverse established-flow state.
cat <<'YAML' | "$KUBECTL" -n "$NS" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: server-stateful}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress, Egress]
  ingress:
  - from:
    - podSelector: {matchLabels: {app: client}}
    ports: [{protocol: TCP, port: 8080}]
  egress: []
YAML
sleep 3
"$KUBECTL" -n "$NS" exec client -- curl -fsS --max-time 5 "http://$SERVER_IP:8080/" >/dev/null
printf '%s\n' 'PASS: ingress-authorized HTTP response crossed egress deny-all via established state'

# Client ingress deny-all + explicit egress to server. The response must enter
# the client despite its ingress isolation because it is reverse state for an
# allowed egress connection.
cat <<YAML | "$KUBECTL" -n "$NS" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: client-stateful}
spec:
  podSelector: {matchLabels: {app: client}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress:
  - to:
    - podSelector: {matchLabels: {app: server}}
    ports: [{protocol: TCP, port: 8080}]
YAML
sleep 3
"$KUBECTL" -n "$NS" exec client -- curl -fsS --max-time 5 "http://$SERVER_IP:8080/" >/dev/null
printf '%s\n' 'PASS: egress-authorized HTTP response crossed client ingress deny-all via established state'

# Policy-revocation smoke: change the client to egress deny-all and require a
# new TCP connection to fail. Set 16 clears fluxvm_ct before policy publish, so
# an old tuple cannot authorize a newly opened SYN after tightening.
cat <<'YAML' | "$KUBECTL" -n "$NS" apply -f -
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: client-stateful}
spec:
  podSelector: {matchLabels: {app: client}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress: []
YAML
sleep 3
if "$KUBECTL" -n "$NS" exec client -- curl -fsS --no-keepalive --max-time 3 "http://$SERVER_IP:8080/" >/dev/null 2>&1; then
  echo 'FAIL: new TCP flow survived egress policy revocation' >&2
  exit 1
fi
printf '%s\n' 'PASS: tightened policy revoked new TCP connectivity'

cat <<'TXT'
SCTP gate is intentionally separate: run on nodes/images with SCTP tooling and
kernel SCTP enabled. Apply a NetworkPolicy with protocol: SCTP and verify both
exact port and endPort behavior. See docs/secure-containers-set16.md.
TXT
