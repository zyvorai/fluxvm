#!/usr/bin/env bash
set -euo pipefail

# Set 9 node-level lifecycle test. Requires a disposable raw-block PVC and a
# working FluxVM RuntimeClass. It verifies that a container restart releases
# the old device owner, hot-unplugs it, and attaches/claims it again.
: "${PVC_NAME:?set PVC_NAME to a Bound PVC with volumeMode: Block}"
NS=${NS:-default}
POD=${POD:-fluxvm-device-lifecycle}
IMAGE=${IMAGE:-busybox:1.36}
STATE_ROOT=${FLUXVM_CONTAINERD_STATE_DIR:-/run/fluxvm/containerd}
TIMEOUT=${TIMEOUT:-180}

cleanup() { kubectl -n "$NS" delete pod "$POD" --ignore-not-found --wait=false >/dev/null 2>&1 || true; }
trap cleanup EXIT
cleanup

cat <<YAML | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $POD
spec:
  runtimeClassName: fluxvm
  restartPolicy: Always
  containers:
  - name: device
    image: $IMAGE
    command: ["sh","-c","test -b /dev/fluxvm-test; trap 'exit 0' TERM; while :; do sleep 30; done"]
    volumeDevices:
    - name: raw
      devicePath: /dev/fluxvm-test
  volumes:
  - name: raw
    persistentVolumeClaim:
      claimName: $PVC_NAME
YAML
kubectl -n "$NS" wait --for=condition=Ready "pod/$POD" --timeout="${TIMEOUT}s"

old_cid=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="device")].containerID}' | sed 's#^[^:]*://##')
[[ -n "$old_cid" ]] || { echo "could not resolve initial container ID" >&2; exit 1; }

journal=$(grep -rl --include=runtime-state.json "\"$old_cid\"" "$STATE_ROOT" 2>/dev/null | head -1 || true)
[[ -n "$journal" ]] || { echo "could not locate runtime-state.json containing $old_cid under $STATE_ROOT" >&2; exit 2; }

read_stat() {
  python3 - "$journal" "$1" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]))
print((s.get('device_stats') or {}).get(sys.argv[2],0))
PY
}
detach_before=$(read_stat detach_total)
attach_before=$(read_stat attach_total)

# Kill only the container process. Kubelet should recreate the container in
# the same Pod sandbox. BusyBox kill is available in the test image.
kubectl -n "$NS" exec "$POD" -c device -- sh -c 'kill -KILL 1' >/dev/null 2>&1 || true

end=$((SECONDS + TIMEOUT))
new_cid=""
while (( SECONDS < end )); do
  new_cid=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="device")].containerID}' 2>/dev/null | sed 's#^[^:]*://##' || true)
  restart=$(kubectl -n "$NS" get pod "$POD" -o jsonpath='{.status.containerStatuses[?(@.name=="device")].restartCount}' 2>/dev/null || echo 0)
  if [[ "$restart" =~ ^[0-9]+$ ]] && (( restart >= 1 )) && [[ -n "$new_cid" && "$new_cid" != "$old_cid" ]]; then
    break
  fi
  sleep 1
done
[[ -n "$new_cid" && "$new_cid" != "$old_cid" ]] || { echo "container did not restart with a new ID" >&2; exit 3; }

end=$((SECONDS + TIMEOUT))
# Wait for lifecycle counters and ownership to converge. Depending on kubelet
# timing, reattach can happen immediately after detach, so counters are the
# reliable proof that an actual QMP unplug occurred.
while (( SECONDS < end )); do
  detach_now=$(read_stat detach_total)
  attach_now=$(read_stat attach_total)
  ownership=$(python3 - "$journal" "$old_cid" "$new_cid" <<'PY'
import json,sys
s=json.load(open(sys.argv[1])); old,new=sys.argv[2:]
devs=((s.get('sandbox') or {}).get('devices') or [])
owners=[o for d in devs for o in (d.get('owners') or [])]
print('ok' if old not in owners and new in owners else 'wait')
PY
)
  if (( detach_now > detach_before )) && (( attach_now > attach_before )) && [[ "$ownership" == ok ]]; then
    echo "Set 9 device lifecycle PASS: old=$old_cid new=$new_cid attach=$attach_now detach=$detach_now journal=$journal"
    exit 0
  fi
  sleep 1
done

echo "device lifecycle did not converge; inspect $journal and QEMU logs" >&2
"$(dirname "$0")/inspect-secure-container-devices.sh" || true
exit 4
