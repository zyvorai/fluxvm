#!/usr/bin/env bash
set -euo pipefail
# Node-level Set 8 raw block smoke. Requires a Kubernetes raw block PVC and
# RuntimeClass fluxvm. Destructive writes are intentionally opt-in.
: "${PVC_NAME:?set PVC_NAME to a Bound PVC with volumeMode: Block}"
NS=${NS:-default}
POD=${POD:-fluxvm-raw-block-smoke}
IMAGE=${IMAGE:-busybox:1.36}
cat <<YAML | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $POD
spec:
  runtimeClassName: fluxvm
  restartPolicy: Never
  containers:
  - name: test
    image: $IMAGE
    command: ["sh","-c","ls -l /dev/fluxvm-test && test -b /dev/fluxvm-test && blockdev --getsize64 /dev/fluxvm-test || true; sleep 2"]
    volumeDevices:
    - name: raw
      devicePath: /dev/fluxvm-test
  volumes:
  - name: raw
    persistentVolumeClaim:
      claimName: $PVC_NAME
YAML
kubectl -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout=180s || true
kubectl -n "$NS" logs "$POD" || true
kubectl -n "$NS" get pod "$POD" -o wide
