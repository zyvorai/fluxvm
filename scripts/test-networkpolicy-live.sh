#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
#
# Live single-node Kubernetes reconciliation test for
# fluxvm-networkpolicy-controller (Set 14 NetworkPolicy v2). Unlike the
# compiler's own Go unit tests (hand-built kube.Pod/kube.NetworkPolicy Go
# structs) and the eBPF-side scripts/test-ebpf-smoke.sh (a real kernel, but
# synthetic map entries), this proves the controller's Kubernetes-facing
# half end-to-end against a genuinely live cluster: real Pods with real
# container specs and real Kubernetes-assigned IPs, real
# `networking.k8s.io/v1 NetworkPolicy` objects decoded from the real API
# server's actual JSON shape, and the controller's real reconcile loop
# (list/select/compile/apply) running unmodified. Two fake VMs are mapped
# to the two test Pods so both directions get a real assertion: the client
# Pod's compiled *egress* schema-v2 rule proves a named port resolves
# against the real *peer* (server) Pod's own container spec; the server
# Pod's compiled *ingress* schema-v2 rule proves numeric-port ingress
# resolves against the real client Pod IP as a /32 CIDR tuple.
#
# What is intentionally NOT real here: the FluxVM side. Running actual
# Secure Containers VMs inside a throwaway k3s test cluster is out of scope
# for this test -- the controller's HTTP behavior against the real FluxVM
# API is already covered by internal/fluxvm/client_test.go's integration
# tests. This script stands up a small mock FluxVM API server instead,
# recording whatever Pod policy the controller computes and POSTs per VM,
# so this test can assert on the exact compiled result of a real
# Kubernetes reconciliation without needing a real VM.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CTRL_DIR="$ROOT/controllers/fluxvm-networkpolicy-controller"
KUBECONFIG_PATH="${KUBECONFIG:-/etc/rancher/k3s/k3s.yaml}"

for cmd in kubectl go curl; do
  command -v "$cmd" >/dev/null || { echo "missing $cmd" >&2; exit 2; }
done
[[ -f "$KUBECONFIG_PATH" ]] || { echo "no kubeconfig at $KUBECONFIG_PATH; run scripts/bootstrap-lab-k3s.sh first" >&2; exit 2; }
export KUBECONFIG="$KUBECONFIG_PATH"
kubectl get nodes >/dev/null || { echo "cluster at $KUBECONFIG_PATH is not reachable" >&2; exit 2; }

SUFFIX="$$"
NS="fluxvm-np-live-${SUFFIX}"
SA="fluxvm-np-live-${SUFFIX}"
TMP="$(mktemp -d)"
MOCK_PORT=18790
CTRL_METRICS_PORT=18791
SERVER_VM="11111111-2222-4333-8444-555555555555"
CLIENT_VM="22222222-3333-4444-8444-666666666666"

CTRL_PID=""
MOCK_PID=""
cleanup() {
  set +e
  [[ -n "$CTRL_PID" ]] && kill "$CTRL_PID" 2>/dev/null
  [[ -n "$MOCK_PID" ]] && kill "$MOCK_PID" 2>/dev/null
  kubectl delete namespace "$NS" --ignore-not-found --wait=false >/dev/null 2>&1
  kubectl delete clusterrolebinding "$SA" --ignore-not-found >/dev/null 2>&1
  rm -rf "$TMP"
}
trap cleanup EXIT

echo "-- namespace, RBAC, and test Pods --"
kubectl create namespace "$NS" >/dev/null
kubectl create serviceaccount "$SA" -n "$NS" >/dev/null
kubectl create clusterrolebinding "$SA" --clusterrole=view --serviceaccount="$NS:$SA" >/dev/null

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: server
  namespace: $NS
  labels: {role: server}
spec:
  containers:
    - name: server
      image: busybox:1.36
      command: ["sleep", "600"]
      ports:
        - name: http
          containerPort: 8080
          protocol: TCP
---
apiVersion: v1
kind: Pod
metadata:
  name: client
  namespace: $NS
  labels: {role: client}
spec:
  containers:
    - name: client
      image: busybox:1.36
      command: ["sleep", "600"]
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: client-egress
  namespace: $NS
spec:
  podSelector: {matchLabels: {role: client}}
  policyTypes: [Egress]
  egress:
    - to:
        - podSelector: {matchLabels: {role: server}}
      ports:
        - protocol: TCP
          port: http
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: server-ingress
  namespace: $NS
spec:
  podSelector: {matchLabels: {role: server}}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {matchLabels: {role: client}}
      ports:
        - protocol: TCP
          port: 8080
YAML

echo "-- waiting for Pods to be Running with assigned IPs --"
kubectl wait -n "$NS" --for=condition=Ready pod/server pod/client --timeout=120s >/dev/null
for _ in $(seq 1 30); do
  SERVER_IP="$(kubectl get pod server -n "$NS" -o jsonpath='{.status.podIP}')"
  CLIENT_IP="$(kubectl get pod client -n "$NS" -o jsonpath='{.status.podIP}')"
  [[ -n "$SERVER_IP" && -n "$CLIENT_IP" ]] && break
  sleep 1
done
[[ -n "$SERVER_IP" && -n "$CLIENT_IP" ]] || { echo "Pods never got IPs" >&2; exit 1; }
SERVER_UID="$(kubectl get pod server -n "$NS" -o jsonpath='{.metadata.uid}')"
CLIENT_UID="$(kubectl get pod client -n "$NS" -o jsonpath='{.metadata.uid}')"
echo "server=$SERVER_IP ($SERVER_UID) client=$CLIENT_IP ($CLIENT_UID)"

echo "-- mock FluxVM API server (records every POSTed Pod policy per VM id) --"
mkdir -p "$TMP/policies"
cat >"$TMP/mockflux.go" <<'GOSRC'
package main

import (
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type vmRecord struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Status  string `json:"status"`
	Request struct {
		PodUID *string `json:"pod_uid"`
	} `json:"request"`
}

func main() {
	addr := flag.String("addr", ":18790", "listen address")
	mappings := flag.String("map", "", "comma-separated vm_id=pod_uid pairs")
	outDir := flag.String("out-dir", "", "directory to write <vm_id>.json to on every POST")
	flag.Parse()

	var vms []vmRecord
	for _, pair := range strings.Split(*mappings, ",") {
		if pair == "" {
			continue
		}
		parts := strings.SplitN(pair, "=", 2)
		podUID := parts[1]
		rec := vmRecord{ID: parts[0], Name: "test-vm-" + parts[0], Status: "running"}
		rec.Request.PodUID = &podUID
		vms = append(vms, rec)
	}

	var mu sync.Mutex
	last := map[string]json.RawMessage{}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/vms", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"items": vms})
	})
	mux.HandleFunc("/v1/vms/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/vms/"), "/network/pod-policy")
		mu.Lock()
		defer mu.Unlock()
		switch r.Method {
		case http.MethodGet:
			if body, ok := last[id]; ok {
				_, _ = w.Write(body)
				return
			}
			_, _ = w.Write([]byte("null"))
		case http.MethodPost:
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			last[id] = body
			if *outDir != "" {
				_ = os.WriteFile(filepath.Join(*outDir, id+".json"), body, 0o600)
			}
			w.WriteHeader(http.StatusOK)
		case http.MethodDelete:
			delete(last, id)
			w.WriteHeader(http.StatusOK)
		}
	})
	if err := http.ListenAndServe(*addr, mux); err != nil {
		panic(err)
	}
}
GOSRC
cat >"$TMP/go.mod" <<'GOMOD'
module mockflux

go 1.22
GOMOD
(cd "$TMP" && go build -o mockflux .)

"$TMP/mockflux" -addr ":$MOCK_PORT" -map "$SERVER_VM=$SERVER_UID,$CLIENT_VM=$CLIENT_UID" -out-dir "$TMP/policies" &
MOCK_PID=$!
sleep 0.3
curl -sf "http://127.0.0.1:$MOCK_PORT/v1/vms" >/dev/null || { echo "mock FluxVM API did not start" >&2; exit 1; }

echo "-- building and running fluxvm-networkpolicy-controller --"
if [[ -n "${CONTROLLER_BIN:-}" ]]; then
  # go.mod pins `go 1.27`; a host whose installed `go` is older and has no
  # network access to auto-download that toolchain (a pre-existing
  # environment gap, unrelated to Set 14) can't `go build` this locally --
  # set CONTROLLER_BIN to a binary cross-compiled elsewhere instead.
  cp "$CONTROLLER_BIN" "$TMP/fluxvm-networkpolicy-controller"
  chmod +x "$TMP/fluxvm-networkpolicy-controller"
else
  (cd "$CTRL_DIR" && go build -o "$TMP/fluxvm-networkpolicy-controller" ./cmd/fluxvm-networkpolicy-controller)
fi

NODE_NAME="$(kubectl get pod server -n "$NS" -o jsonpath='{.spec.nodeName}')"
API_SERVER="$(kubectl config view --minify --raw -o jsonpath='{.clusters[0].cluster.server}')"
# A real file, not process substitution: internal/fluxvm/client.go rereads
# the token file on every request (to support projected/rotated tokens in
# production), and a `<()` pipe/fifo only yields data to the first reader.
kubectl create token "$SA" -n "$NS" --duration=30m > "$TMP/token"

"$TMP/fluxvm-networkpolicy-controller" \
  --node-name "$NODE_NAME" \
  --interval 2s \
  --kube-api "$API_SERVER" \
  --kube-token-file "$TMP/token" \
  --kube-insecure-skip-verify \
  --fluxvm-url "http://127.0.0.1:$MOCK_PORT" \
  --metrics-listen ":$CTRL_METRICS_PORT" \
  >"$TMP/controller.log" 2>&1 &
CTRL_PID=$!

echo "-- waiting for reconciliation to post both Pods' policies --"
for _ in $(seq 1 30); do
  [[ -s "$TMP/policies/$SERVER_VM.json" && -s "$TMP/policies/$CLIENT_VM.json" ]] && break
  sleep 1
done
if [[ ! -s "$TMP/policies/$SERVER_VM.json" || ! -s "$TMP/policies/$CLIENT_VM.json" ]]; then
  echo "controller never POSTed both Pod policies" >&2
  cat "$TMP/controller.log" >&2
  exit 1
fi

echo "-- asserting the live-compiled schema-v2 policies --"
python3 - "$TMP/policies/$SERVER_VM.json" "$TMP/policies/$CLIENT_VM.json" "$SERVER_IP" "$CLIENT_IP" <<'PY'
import json, sys
server_policy_path, client_policy_path, server_ip, client_ip = sys.argv[1:5]
server_policy = json.load(open(server_policy_path))
client_policy = json.load(open(client_policy_path))

def rules(policy):
    return policy.get("rules") or []

# Server Pod: only server-ingress selects it. Set 14 emits a directional
# schema-v2 policy: ingress_isolated, default_deny (legacy roll-forward
# bit), and one ingress CIDR+L4 tuple for the real client Pod IP / TCP 8080.
assert server_policy.get("schema_version") == 2, server_policy
assert server_policy["default_deny"] is True, server_policy
assert server_policy.get("ingress_isolated") is True, server_policy
assert not server_policy.get("egress_isolated"), server_policy
assert rules(server_policy) == [
    {
        "direction": "ingress",
        "cidr": f"{client_ip}/32",
        "protocol": "TCP",
        "port_start": 8080,
        "port_end": 8080,
    }
], f"expected ingress allow from real client Pod IP on port 8080: {server_policy}"

# Client Pod: client-egress selects it with a *named* port ("http"),
# which must resolve against the real *peer* (server) Pod's own container
# spec -- proving this is genuinely live, not a synthetic fixture, since
# the mapping from "http" -> 8080 only exists in the server Pod object
# Kubernetes itself returned.
assert client_policy.get("schema_version") == 2, client_policy
assert client_policy["default_deny"] is True, client_policy
assert client_policy.get("egress_isolated") is True, client_policy
assert not client_policy.get("ingress_isolated"), client_policy
assert rules(client_policy) == [
    {
        "direction": "egress",
        "cidr": f"{server_ip}/32",
        "protocol": "TCP",
        "port_start": 8080,
        "port_end": 8080,
    }
], f"expected named port 'http' to resolve to 8080 against the real server Pod: {client_policy}"

print("live NetworkPolicy reconciliation test (Set 14 schema v2): PASS")
PY
