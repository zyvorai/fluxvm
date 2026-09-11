#!/usr/bin/env bash
# FLUXVM_SECURE_CONTAINERS_SET17
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Real RuntimeClass stateful NetworkPolicy proof.
# - client initiates TCP to server: allowed by client egress + server ingress
# - server's HTTP response must traverse server egress deny-all and client
#   ingress deny-all via FluxVM's shared reverse conntrack state
# - a fresh server->client connection is denied (control)
# - when >=2 schedulable nodes exist, client/server are pinned to different
#   nodes, giving a cross-node NetworkPolicy starter in the same run.
set -euo pipefail

RUNTIME_CLASS="${RUNTIME_CLASS:-fluxvm}"
NS="${NAMESPACE:-fluxvm-set17-$RANDOM-$RANDOM}"
REQUIRE_MULTI_NODE="${REQUIRE_MULTI_NODE:-0}"
KEEP_NAMESPACE="${KEEP_NAMESPACE:-0}"
WAIT_POLICY_SECONDS="${WAIT_POLICY_SECONDS:-8}"

command -v kubectl >/dev/null || { echo "missing kubectl" >&2; exit 2; }
kubectl get runtimeclass "$RUNTIME_CLASS" >/dev/null 2>&1 || {
  echo "RuntimeClass $RUNTIME_CLASS not found" >&2; exit 2;
}

mapfile -t NODES < <(kubectl get nodes -o json | python3 -c '
import json,sys
x=json.load(sys.stdin)
for n in x.get("items",[]):
  unsched=bool(n.get("spec",{}).get("unschedulable"))
  ready=any(c.get("type")=="Ready" and c.get("status")=="True" for c in n.get("status",{}).get("conditions",[]))
  if ready and not unsched: print(n["metadata"]["name"])
')
[[ ${#NODES[@]} -ge 1 ]] || { echo "no schedulable Ready nodes" >&2; exit 2; }
if [[ "$REQUIRE_MULTI_NODE" == "1" && ${#NODES[@]} -lt 2 ]]; then
  echo "Set17 multi-node gate requested but fewer than two nodes are Ready" >&2
  exit 2
fi
CLIENT_NODE="${NODES[0]}"
SERVER_NODE="${NODES[0]}"
if [[ ${#NODES[@]} -ge 2 ]]; then SERVER_NODE="${NODES[1]}"; fi

cleanup() {
  if [[ "$KEEP_NAMESPACE" != "1" ]]; then
    kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  else
    echo "keeping namespace $NS"
  fi
}
trap cleanup EXIT

kubectl create ns "$NS" >/dev/null
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: $NS
  labels: {app: client}
spec:
  runtimeClassName: $RUNTIME_CLASS
  nodeName: $CLIENT_NODE
  containers:
    - name: app
      image: busybox:1.36
      command: ["sh", "-ec"]
      args:
        - mkdir -p /www; echo client-ok >/www/index.html; exec httpd -f -p 8081 -h /www
      ports: [{name: client-http, containerPort: 8081, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: $NS
  labels: {app: server}
spec:
  runtimeClassName: $RUNTIME_CLASS
  nodeName: $SERVER_NODE
  containers:
    - name: app
      image: busybox:1.36
      command: ["sh", "-ec"]
      args:
        - mkdir -p /www; echo set17-ok >/www/index.html; exec httpd -f -p 8080 -h /www
      ports: [{name: http, containerPort: 8080, protocol: TCP}]
YAML

kubectl wait -n "$NS" --for=condition=Ready pod/client pod/server --timeout=180s >/dev/null
CLIENT_IP="$(kubectl get pod -n "$NS" client -o jsonpath='{.status.podIP}')"
SERVER_IP="$(kubectl get pod -n "$NS" server -o jsonpath='{.status.podIP}')"
[[ -n "$CLIENT_IP" && -n "$SERVER_IP" ]] || { echo "Pods have no IPs" >&2; exit 1; }
echo "client=$CLIENT_IP@$CLIENT_NODE server=$SERVER_IP@$SERVER_NODE"

# Pre-policy connectivity proves both listeners/routes work before enforcement.
[[ "$(kubectl exec -n "$NS" client -- wget -qO- -T 4 "http://$SERVER_IP:8080/")" == "set17-ok" ]] || {
  echo "baseline client->server failed" >&2; exit 1;
}
[[ "$(kubectl exec -n "$NS" server -- wget -qO- -T 4 "http://$CLIENT_IP:8081/")" == "client-ok" ]] || {
  echo "baseline server->client failed" >&2; exit 1;
}

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: client-policy, namespace: $NS}
spec:
  podSelector: {matchLabels: {app: client}}
  policyTypes: [Ingress, Egress]
  ingress: []
  egress:
    - to:
        - podSelector: {matchLabels: {app: server}}
      ports:
        - {protocol: TCP, port: 8080}
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: server-policy, namespace: $NS}
spec:
  podSelector: {matchLabels: {app: server}}
  policyTypes: [Ingress, Egress]
  ingress:
    - from:
        - podSelector: {matchLabels: {app: client}}
      ports:
        - {protocol: TCP, port: 8080}
  egress: []
YAML

sleep "$WAIT_POLICY_SECONDS"

# This one HTTP transaction proves BOTH stateful directions simultaneously:
# client reply ingress is deny-all except conntrack, and server reply egress
# is deny-all except the reverse entry learned by the ingress program.
OUT="$(kubectl exec -n "$NS" client -- wget -qO- -T 5 "http://$SERVER_IP:8080/")" || {
  echo "FAIL: allowed TCP request lost its stateful reply" >&2
  exit 1
}
[[ "$OUT" == "set17-ok" ]] || { echo "unexpected response: $OUT" >&2; exit 1; }
echo "PASS: stateful client->server HTTP reply traversed both isolated return directions"

# Control: a genuinely new server-initiated flow must NOT inherit the prior
# connection's state; server egress is deny-all and client ingress is deny-all.
if kubectl exec -n "$NS" server -- wget -qO- -T 3 "http://$CLIENT_IP:8081/" >/dev/null 2>&1; then
  echo "FAIL: new server->client flow bypassed deny-all policy" >&2
  exit 1
fi
echo "PASS: fresh reverse-direction flow is denied"

if [[ "$CLIENT_NODE" != "$SERVER_NODE" ]]; then
  echo "PASS: same proof crossed nodes ($CLIENT_NODE -> $SERVER_NODE)"
else
  echo "INFO: single-node proof; set REQUIRE_MULTI_NODE=1 on a >=2-node lab for S2 gate"
fi
