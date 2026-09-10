#!/usr/bin/env bash
set -euo pipefail

# Self-hosted Kubernetes dual-stack smoke for FluxVM RuntimeClass.
# Requires a cluster whose CNI is already configured for dual-stack.
: "${FLUXVM_SECURE_CONTAINERS_E2E:=0}"
if [[ "$FLUXVM_SECURE_CONTAINERS_E2E" != "1" ]]; then
  echo "SKIP: set FLUXVM_SECURE_CONTAINERS_E2E=1 on a dual-stack KVM node"
  exit 0
fi

for bin in kubectl jq; do
  command -v "$bin" >/dev/null || { echo "missing $bin" >&2; exit 1; }
done

ns="fluxvm-set6-$RANDOM"
pod="dualstack"
cleanup() { kubectl delete ns "$ns" --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT

kubectl create ns "$ns" >/dev/null
cat <<'YAML' | kubectl -n "$ns" apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: dualstack
spec:
  runtimeClassName: fluxvm
  restartPolicy: Never
  containers:
  - name: probe
    image: busybox:1.36
    command: ["/bin/sh","-c"]
    args:
    - |
      ip -4 addr show || true
      ip -6 addr show || true
      ip -4 route show || true
      ip -6 route show || true
      sleep 300
YAML

kubectl -n "$ns" wait --for=condition=Ready "pod/$pod" --timeout=180s
pod_json="$(kubectl -n "$ns" get pod "$pod" -o json)"
mapfile -t pod_ips < <(jq -r '.status.podIPs[]?.ip' <<<"$pod_json")
if (( ${#pod_ips[@]} < 2 )); then
  echo "FAIL: cluster did not report dual-stack Pod IPs: ${pod_ips[*]-}" >&2
  exit 1
fi

inside="$(kubectl -n "$ns" exec "$pod" -- sh -c 'ip -o -4 addr; ip -o -6 addr')"
for ip in "${pod_ips[@]}"; do
  grep -Fq "$ip" <<<"$inside" || {
    echo "FAIL: Kubernetes Pod IP $ip is not present inside FluxVM guest/container" >&2
    echo "$inside" >&2
    exit 1
  }
done
echo "PASS: FluxVM Secure Containers dual-stack Pod IPs: ${pod_ips[*]}"
