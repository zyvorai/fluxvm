#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Live Kubernetes EndpointSlice/Service-VIP compiler gate for Set 18.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL="$ROOT/controllers/fluxvm-networkpolicy-controller"
for c in kubectl go curl; do command -v "$c" >/dev/null || { echo "missing $c" >&2; exit 2; }; done
NS="fluxvm-set18-$RANDOM-$$"
PROXY_PORT="${SET18_PROXY_PORT:-18081}"
PROXY_PID=""
cleanup(){ set +e; [[ -n "$PROXY_PID" ]] && kill "$PROXY_PID" 2>/dev/null; kubectl delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1; }
trap cleanup EXIT
kubectl create ns "$NS" >/dev/null
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: client, namespace: $NS, labels: {role: client}}
spec:
  containers:
  - name: client
    image: busybox:1.36
    command: ["sh","-c","sleep 600"]
---
apiVersion: v1
kind: Pod
metadata: {name: selected, namespace: $NS, labels: {app: db, policy-peer: "yes"}}
spec:
  containers:
  - name: server
    image: busybox:1.36
    command: ["sh","-c","sleep 600"]
    ports: [{containerPort: 8080, protocol: TCP}]
---
apiVersion: v1
kind: Pod
metadata: {name: unselected, namespace: $NS, labels: {app: db, policy-peer: "no"}}
spec:
  containers:
  - name: server
    image: busybox:1.36
    command: ["sh","-c","sleep 600"]
    readinessProbe: {exec: {command: ["sh","-c","exit 1"]}, initialDelaySeconds: 1, periodSeconds: 1}
---
apiVersion: v1
kind: Service
metadata: {name: db, namespace: $NS}
spec:
  selector: {app: db}
  ports: [{port: 8080, targetPort: 8080, protocol: TCP}]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {name: client-egress, namespace: $NS}
spec:
  podSelector: {matchLabels: {role: client}}
  policyTypes: [Egress]
  egress:
  - to:
    - podSelector: {matchLabels: {policy-peer: "yes"}}
    ports: [{protocol: TCP, port: 8080}]
YAML
kubectl wait -n "$NS" --for=condition=Ready pod/client pod/selected --timeout=120s >/dev/null
# unselected intentionally remains NotReady but must still exist in EndpointSlice.
for _ in $(seq 1 60); do
  if kubectl get endpointslice -n "$NS" -l kubernetes.io/service-name=db -o json | grep -q 'uid'; then break; fi
  sleep 1
done
SERVICE_IP="$(kubectl get svc db -n "$NS" -o jsonpath='{.spec.clusterIP}')"
kubectl proxy --port="$PROXY_PORT" --accept-hosts='^127\.0\.0\.1$' >/tmp/fluxvm-set18-proxy.log 2>&1 & PROXY_PID=$!
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$PROXY_PORT/version" >/dev/null && break; sleep .2; done
run_live(){
  (
    cd "$CTRL"
    FLUXVM_SET18_LIVE_API="http://127.0.0.1:$PROXY_PORT" \
    FLUXVM_SET18_LIVE_NAMESPACE="$NS" \
    FLUXVM_SET18_LIVE_TARGET="client" \
    FLUXVM_SET18_SERVICE_IP="$SERVICE_IP" \
    FLUXVM_SET18_EXPECT_VIP="$1" \
    go test ./internal/policy -run '^TestSet18LiveEndpointSliceServiceVIP$' -count=1
  )
}
echo "-- Set 18: NotReady unselected backend is not routable; VIP should be admitted --"
run_live 1

echo "-- Set 18: make the unselected Service backend Ready; VIP must be removed --"
kubectl delete pod unselected -n "$NS" --wait=true >/dev/null
cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata: {name: unselected, namespace: $NS, labels: {app: db, policy-peer: "no"}}
spec:
  containers:
  - name: server
    image: busybox:1.36
    command: ["sh","-c","sleep 600"]
    ports: [{containerPort: 8080, protocol: TCP}]
YAML
kubectl wait -n "$NS" --for=condition=Ready pod/unselected --timeout=120s >/dev/null
for _ in $(seq 1 60); do
  READY_COUNT="$(kubectl get endpointslice -n "$NS" -l kubernetes.io/service-name=db -o jsonpath='{range .items[*].endpoints[*]}{.conditions.ready}{"\n"}{end}' | grep -c '^true$' || true)"
  [[ "$READY_COUNT" -ge 2 ]] && break
  sleep 1
done
run_live 0
echo "Set 18 live EndpointSlice Service-VIP gate: PASS"
