#!/usr/bin/env bash
set -euo pipefail

for cmd in kubectl ctr timeout grep; do
  command -v "$cmd" >/dev/null || { echo "missing required command: $cmd" >&2; exit 2; }
done

NS="${FLUXVM_SET7_NAMESPACE:-fluxvm-set7-e2e}"
POD="${FLUXVM_SET7_OOM_POD:-oom-probe}"
EVENTS="$(mktemp)"
cleanup() {
  kubectl delete ns "$NS" --wait=false >/dev/null 2>&1 || true
  rm -f "$EVENTS"
}
trap cleanup EXIT

kubectl create ns "$NS" >/dev/null 2>&1 || true

# Capture containerd OOM events while the Pod intentionally exceeds its memory
# cgroup. `ctr events` formatting varies slightly by containerd release, so the
# assertion checks the canonical topic instead of depending on JSON layout.
timeout 90 ctr -n k8s.io events --filter 'topic=="/tasks/oom"' >"$EVENTS" 2>&1 &
EVENT_PID=$!

cat <<YAML | kubectl apply -f - >/dev/null
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
  namespace: ${NS}
spec:
  runtimeClassName: fluxvm
  restartPolicy: Never
  containers:
  - name: burn
    image: busybox:1.36
    command: ["sh", "-c", "awk 'BEGIN { s=\"x\"; while (1) s=s s }'"]
    resources:
      requests:
        memory: 16Mi
      limits:
        memory: 32Mi
YAML

reason=""
for _ in $(seq 1 120); do
  reason="$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[0].state.terminated.reason}' 2>/dev/null || true)"
  [[ -n "$reason" ]] && break
  sleep 1
done

# Give the shim's memory.events poller a final interval to publish.
sleep 1
kill "$EVENT_PID" >/dev/null 2>&1 || true
wait "$EVENT_PID" >/dev/null 2>&1 || true

if [[ "$reason" != "OOMKilled" && "$reason" != "Error" ]]; then
  echo "expected OOM-style termination, got reason=${reason:-<none>}" >&2
  kubectl -n "$NS" get pod "$POD" -o wide >&2 || true
  exit 1
fi

if ! grep -q '/tasks/oom' "$EVENTS"; then
  echo "containerd /tasks/oom event not observed" >&2
  cat "$EVENTS" >&2
  exit 1
fi

echo "PASS: FluxVM secure-container OOM produced containerd /tasks/oom (pod reason=$reason)"
