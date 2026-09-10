#!/usr/bin/env bash
set -euo pipefail

NAMESPACE=${NAMESPACE:-default}
RUNTIME_CLASS=${RUNTIME_CLASS:-fluxvm}
IMAGE=${IMAGE:-busybox:1.36}
POD=${POD:-fluxvm-security-set10}

command -v kubectl >/dev/null

cleanup() {
  kubectl -n "$NAMESPACE" delete pod "$POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

cat <<YAML | kubectl -n "$NAMESPACE" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
spec:
  runtimeClassName: ${RUNTIME_CLASS}
  restartPolicy: Never
  securityContext:
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: test
    image: ${IMAGE}
    command: ["sh", "-c", "grep '^Seccomp:' /proc/self/status; sleep 300"]
YAML

kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$POD" --timeout=180s
mode=$(kubectl -n "$NAMESPACE" exec "$POD" -- awk '/^Seccomp:/ {print $2}' /proc/self/status | tr -d '\r')
if [[ "$mode" != "2" ]]; then
  echo "expected seccomp filter mode 2, got: ${mode:-<empty>}" >&2
  exit 1
fi

echo "Set 10 seccomp RuntimeDefault smoke passed"

if [[ -n "${APPARMOR_PROFILE:-}" ]]; then
  cleanup
  cat <<YAML | kubectl -n "$NAMESPACE" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: ${POD}
spec:
  runtimeClassName: ${RUNTIME_CLASS}
  restartPolicy: Never
  containers:
  - name: test
    image: ${IMAGE}
    securityContext:
      appArmorProfile:
        type: Localhost
        localhostProfile: ${APPARMOR_PROFILE}
    command: ["sh", "-c", "cat /proc/self/attr/current; sleep 300"]
YAML
  kubectl -n "$NAMESPACE" wait --for=condition=Ready "pod/$POD" --timeout=180s
  current=$(kubectl -n "$NAMESPACE" exec "$POD" -- cat /proc/self/attr/current | tr -d '\r')
  if [[ "$current" != *"$APPARMOR_PROFILE"* ]]; then
    echo "AppArmor profile not visible in process label: $current" >&2
    exit 1
  fi
  echo "Set 10 AppArmor smoke passed"
fi
