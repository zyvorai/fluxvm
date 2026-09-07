#!/usr/bin/env bash
# Copyright 2026 Zyvor AI Labs · https://zyvor.dev
# SPDX-License-Identifier: Apache-2.0
# Production-style MicroVM k3s smoke on a FluxVM lab host.
set -euo pipefail
exec </dev/null
source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.cargo/bin:/usr/local/bin:$PATH"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

BIN="${FLUXVM_MICROVM_BIN:-$ROOT/target/release/fluxvm-microvm}"
[[ -x "$BIN" ]] || cargo build -p fluxvm-microvm --release
IMG="${MICROVM_SMOKE_IMAGE:-/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2}"
[[ -f "$IMG" ]] || IMG="$(ls /var/lib/fluxvm/images/*.qcow2 2>/dev/null | head -1)"
[[ -f "$IMG" ]] || { echo "no qcow2 image under /var/lib/fluxvm/images" >&2; exit 2; }

sudo kubectl create ns fluxvm-system --dry-run=client -o yaml | sudo kubectl apply -f -
sudo kubectl apply -f deploy/k8s/microvm/crd.yaml
sudo kubectl apply -f deploy/k8s/microvm/rbac.yaml
NODE="$(sudo kubectl get nodes -o jsonpath='{.items[0].metadata.name}')"
sudo kubectl label node "$NODE" ragnarok.io/fluxvm-capable=true --overwrite
echo "NODE=$NODE IMG=$IMG"

sudo pkill -f 'fluxvm-microvm controller' 2>/dev/null || true
sudo pkill -f 'fluxvm-microvm node-agent' 2>/dev/null || true
sleep 1
sudo mkdir -p /tmp/microvm-lab
TOKEN="${FLUXVM_TOKEN:-}"
if [[ -z "$TOKEN" && -f /etc/fluxvm.toml ]]; then
  TOKEN="$(python3 - <<'PY'
from pathlib import Path
text = Path("/etc/fluxvm.toml").read_text()
tok = ""
in_auth = False
for line in text.splitlines():
    s = line.strip()
    if s == "[auth]":
        in_auth = True
        continue
    if in_auth and s.startswith("[") and not s.startswith("[["):
        break
    if in_auth and s.startswith("token"):
        tok = s.split("=", 1)[1].strip().strip('"')
print(tok)
PY
)"
fi

sudo bash -c "cd '$ROOT' && KUBECONFIG=/etc/rancher/k3s/k3s.yaml RUST_LOG=debug PATH='$PATH' \
  nohup '$BIN' controller >/tmp/microvm-lab/controller.log 2>&1 & echo \$! >/tmp/microvm-lab/controller.pid"
sudo bash -c "cd '$ROOT' && KUBECONFIG=/etc/rancher/k3s/k3s.yaml RUST_LOG=debug PATH='$PATH' \
  NODE_NAME='$NODE' FLUXVM_URL=http://127.0.0.1:7788 FLUXVM_TOKEN='$TOKEN' \
  nohup '$BIN' node-agent >/tmp/microvm-lab/node-agent.log 2>&1 & echo \$! >/tmp/microvm-lab/agent.pid"
sleep 5
echo "CONTROLLER=$(sudo cat /tmp/microvm-lab/controller.pid)"
echo "AGENT=$(sudo cat /tmp/microvm-lab/agent.pid)"
sudo tail -20 /tmp/microvm-lab/controller.log || true
sudo tail -20 /tmp/microvm-lab/node-agent.log || true

sudo kubectl delete mvm lab-smoke lab-converted-skip --ignore-not-found --wait=false || true
sleep 2

cat >/tmp/mvm-smoke.yaml <<YAML
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVM
metadata:
  name: lab-smoke
  namespace: default
spec:
  backend: qemu
  image: ${IMG}
  vcpus: 1
  memoryMib: 1024
  networkMode: user
  ttlSeconds: 300
  persist: false
YAML
sudo kubectl apply -f /tmp/mvm-smoke.yaml

for i in $(seq 1 60); do
  PHASE="$(sudo kubectl get mvm lab-smoke -o jsonpath='{.status.phase}' 2>/dev/null || true)"
  RNODE="$(sudo kubectl get mvm lab-smoke -o jsonpath='{.status.runtime.node}' 2>/dev/null || true)"
  UUID="$(sudo kubectl get mvm lab-smoke -o jsonpath='{.status.runtime.uuid}' 2>/dev/null || true)"
  PODN="$(sudo kubectl get pod -o name 2>/dev/null | grep mvm-lab-smoke | head -1 || true)"
  echo "t=$i phase=$PHASE node=$RNODE uuid=${UUID:0:8} pod=$PODN"
  if [[ -n "$PODN" ]]; then
    CPU="$(sudo kubectl get "$PODN" -o jsonpath='{.spec.containers[0].resources.requests.cpu}' 2>/dev/null || true)"
    MEM="$(sudo kubectl get "$PODN" -o jsonpath='{.spec.containers[0].resources.requests.memory}' 2>/dev/null || true)"
    echo "  shadow cpu=$CPU mem=$MEM"
  fi
  case "$PHASE" in Running|Failed) break ;; esac
  sleep 2
done

PODN="$(sudo kubectl get pod -o name 2>/dev/null | grep mvm-lab-smoke | head -1 || true)"
if [[ -z "$PODN" ]]; then
  echo FAIL_NO_SHADOW
  sudo kubectl describe mvm lab-smoke | tail -50 || true
  sudo tail -80 /tmp/microvm-lab/controller.log || true
  exit 1
fi
CPU="$(sudo kubectl get "$PODN" -o jsonpath='{.spec.containers[0].resources.requests.cpu}')"
MEM="$(sudo kubectl get "$PODN" -o jsonpath='{.spec.containers[0].resources.requests.memory}')"
echo "ASSERT shadow cpu=$CPU mem=$MEM"
[[ "$CPU" == "10m" && "$MEM" == "32Mi" ]] || { echo FAIL_SHADOW_BUDGET; exit 1; }
echo SHADOW_BUDGET_OK

cat >/tmp/mvm-converted.yaml <<YAML
apiVersion: microvm.fluxvm.zyvor.io/v1alpha1
kind: MicroVM
metadata:
  name: lab-converted-skip
  namespace: default
  annotations:
    microvm.fluxvm.zyvor.io/converted-from: disposablevm
    microvm.fluxvm.zyvor.io/driven-by: fluxvm-kube
spec:
  backend: qemu
  image: ${IMG}
  vcpus: 1
  memoryMib: 512
  networkMode: user
  nodeName: ${NODE}
  persist: true
YAML
sudo kubectl apply -f /tmp/mvm-converted.yaml
sleep 8
if sudo grep -q 'skip: driven by fluxvm-kube' /tmp/microvm-lab/node-agent.log; then
  echo DRIVEN_BY_SKIP_LOG_OK
fi
CUUID="$(sudo kubectl get mvm lab-converted-skip -o jsonpath='{.status.runtime.uuid}' 2>/dev/null || true)"
echo "converted_uuid=$CUUID"
[[ -z "$CUUID" ]] || { echo CONVERTED_HAS_UUID_UNEXPECTED; exit 1; }
echo DRIVEN_BY_SKIP_OK
echo CONVERTED_NO_UUID_OK

FINAL="$(sudo kubectl get mvm lab-smoke -o jsonpath='{.status.phase}' 2>/dev/null || true)"
MSG="$(sudo kubectl get mvm lab-smoke -o jsonpath='{.status.message}' 2>/dev/null || true)"
UUID="$(sudo kubectl get mvm lab-smoke -o jsonpath='{.status.runtime.uuid}' 2>/dev/null || true)"
echo "lab_smoke_phase=$FINAL msg=$MSG uuid=$UUID"
sudo kubectl get mvm -A -o wide || true

if [[ -n "$UUID" ]]; then
  TOKEN="$(python3 - <<'PY'
from pathlib import Path
text = Path("/etc/fluxvm.toml").read_text()
tok = ""
in_auth = False
for line in text.splitlines():
    s = line.strip()
    if s == "[auth]":
        in_auth = True
        continue
    if in_auth and s.startswith("[") and not s.startswith("[["):
        break
    if in_auth and s.startswith("token"):
        tok = s.split("=", 1)[1].strip().strip('"')
print(tok)
PY
)"
  curl -sf -H "Authorization: Bearer $TOKEN" -X DELETE "http://127.0.0.1:7788/v1/vms/$UUID" || true
fi

sudo kubectl delete mvm lab-smoke lab-converted-skip --ignore-not-found --wait=false || true
sudo kill "$(sudo cat /tmp/microvm-lab/controller.pid)" 2>/dev/null || true
sudo kill "$(sudo cat /tmp/microvm-lab/agent.pid)" 2>/dev/null || true
sudo pkill -f 'fluxvm-microvm controller' 2>/dev/null || true
sudo pkill -f 'fluxvm-microvm node-agent' 2>/dev/null || true
echo MICROVM_K8S_SMOKE_DONE
