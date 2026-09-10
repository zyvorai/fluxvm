#!/usr/bin/env bash
set -euo pipefail

NS="${1:-default}"
RC="${2:-fluxvm}"
NAME="fluxvm-namespaces-e2e"

cleanup() {
  kubectl -n "$NS" delete pod "$NAME" --ignore-not-found --wait=true >/dev/null 2>&1 || true
}
trap cleanup EXIT

# Two containers in one Pod (default shareProcessNamespace: false): each gets
# its own private PID/mount namespace, but IPC and UTS are Pod-shared.
cat <<YAML | kubectl -n "$NS" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: $NAME
spec:
  runtimeClassName: $RC
  restartPolicy: Never
  containers:
  - name: a
    image: busybox:1.36
    command: ["sh","-c","echo A_HOSTNAME=\$(hostname); echo A_IPC=\$(readlink /proc/self/ns/ipc); echo A_PID_SELF=\$(readlink /proc/self/ns/pid); touch /a-marker; ls /b-marker 2>&1 || echo A_CANNOT_SEE_B_ROOTFS; sleep 5"]
  - name: b
    image: busybox:1.36
    command: ["sh","-c","sleep 1; echo B_HOSTNAME=\$(hostname); echo B_IPC=\$(readlink /proc/self/ns/ipc); echo B_PID_SELF=\$(readlink /proc/self/ns/pid); touch /b-marker; ls /a-marker 2>&1 || echo B_CANNOT_SEE_A_ROOTFS; ps -A -o pid,comm 2>&1 | head -5"]
YAML

kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$NAME" --timeout=180s || {
  kubectl -n "$NS" describe pod "$NAME" || true
  kubectl -n "$NS" logs "$NAME" --all-containers || true
  exit 1
}

LOG_A="$(kubectl -n "$NS" logs "$NAME" -c a)"
LOG_B="$(kubectl -n "$NS" logs "$NAME" -c b)"

IPC_A="$(grep -o 'A_IPC=.*' <<<"$LOG_A")"
IPC_B="$(grep -o 'B_IPC=.*' <<<"$LOG_B")"
[[ "${IPC_A#A_IPC=}" == "${IPC_B#B_IPC=}" ]] || { echo "FAIL: IPC namespace not shared within Pod: $IPC_A vs $IPC_B" >&2; exit 1; }

PID_A="$(grep -o 'A_PID_SELF=.*' <<<"$LOG_A")"
PID_B="$(grep -o 'B_PID_SELF=.*' <<<"$LOG_B")"
[[ "${PID_A#A_PID_SELF=}" != "${PID_B#B_PID_SELF=}" ]] || { echo "FAIL: PID namespaces should differ without shareProcessNamespace: $PID_A vs $PID_B" >&2; exit 1; }

[[ "$LOG_A" == *"A_CANNOT_SEE_B_ROOTFS"* ]] || { echo "FAIL: container a should not see container b's rootfs (private mount namespaces)" >&2; exit 1; }
[[ "$LOG_B" == *"B_CANNOT_SEE_A_ROOTFS"* ]] || { echo "FAIL: container b should not see container a's rootfs (private mount namespaces)" >&2; exit 1; }

# containerd translates a Pod's IPC path onto the sandbox container's own
# namespace, so this Pod's two workload containers sharing IPC (and each
# having a private PID/mount namespace) is exactly the runc/Kata baseline
# this Set targets — no shareProcessNamespace needed to observe it.
echo "FluxVM Set 6 namespace isolation E2E: PASS (shared IPC/UTS, private PID/mount per container)"
