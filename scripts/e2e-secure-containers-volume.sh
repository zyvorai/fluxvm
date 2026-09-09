#!/usr/bin/env bash
set -euo pipefail

NS="${1:-default}"
RC="${2:-fluxvm}"
NAME="fluxvm-volume-e2e"
PVC="fluxvm-volume-e2e"

cleanup() {
  kubectl -n "$NS" delete pod "$NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true
  kubectl -n "$NS" delete pvc "$PVC" --ignore-not-found --wait=true >/dev/null 2>&1 || true
}
trap cleanup EXIT

cat <<YAML | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: $PVC
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 64Mi
---
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  runtimeClassName: $RC
  restartPolicy: Never
  containers:
  - name: writer
    image: busybox:1.36
    command: ["sh","-c","echo fluxvm-set4-write-through > /data/probe; cat /data/probe"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: $PVC
YAML

kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$NAME" --timeout=180s
[[ "$(kubectl -n "$NS" logs "$NAME")" == *"fluxvm-set4-write-through"* ]]
kubectl -n "$NS" delete pod "$NAME" --wait=true

cat <<YAML | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  runtimeClassName: $RC
  restartPolicy: Never
  containers:
  - name: reader
    image: busybox:1.36
    command: ["cat","/data/probe"]
    volumeMounts:
    - name: data
      mountPath: /data
  volumes:
  - name: data
    persistentVolumeClaim:
      claimName: $PVC
YAML
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$NAME" --timeout=180s
[[ "$(kubectl -n "$NS" logs "$NAME")" == *"fluxvm-set4-write-through"* ]]
echo "FluxVM Set 4 PVC write-through E2E: PASS"
