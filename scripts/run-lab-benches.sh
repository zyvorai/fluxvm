#!/usr/bin/env bash
# Run on lab host from /home/sus/.deployments/fluxvm
set -euo pipefail
exec </dev/null
source "$HOME/.cargo/env" 2>/dev/null || true
export PATH="$HOME/.cargo/bin:/usr/local/bin:$PATH"
cd /home/sus/.deployments/fluxvm

TOKEN=$(python3 - <<'PY'
from pathlib import Path
text = Path("/etc/fluxvm.toml").read_text()
tok=""; in_auth=False
for line in text.splitlines():
    s=line.strip()
    if s=="[auth]": in_auth=True; continue
    if in_auth and s.startswith("[") and not s.startswith("[["): break
    if in_auth and s.startswith("token"): tok=s.split("=",1)[1].strip().strip('"')
print(tok)
PY
)

echo "########## sandbox bench ##########"
FLUXVM_API=http://127.0.0.1:7788 BENCH_N=5 FLUXVM_TOKEN="$TOKEN" \
  IMAGE=/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4 \
  KERNEL=/var/lib/fluxvm/kernels/vmlinux \
  bash ./scripts/bench-sandbox.sh | tee /tmp/bench-sandbox.out

echo "########## density bench ##########"
FLUXVM_API=http://127.0.0.1:7788 BENCH_N=8 FLUXVM_TOKEN="$TOKEN" \
  IMAGE=/var/lib/fluxvm/images/bionic-fabric-rootfs.ext4 \
  KERNEL=/var/lib/fluxvm/kernels/vmlinux \
  bash ./scripts/bench-density.sh | tee /tmp/bench-density.out

echo "########## ensure MicroVM controllers ##########"
test -x ./target/release/fluxvm-microvm || cargo build -p fluxvm-microvm --release
sudo kubectl create ns fluxvm-system --dry-run=client -o yaml | sudo kubectl apply -f -
sudo kubectl apply -f deploy/k8s/microvm/crd.yaml >/dev/null
sudo kubectl apply -f deploy/k8s/microvm/rbac.yaml >/dev/null
NODE=$(sudo kubectl get nodes -o jsonpath='{.items[0].metadata.name}')
sudo kubectl label node "$NODE" ragnarok.io/fluxvm-capable=true --overwrite >/dev/null
sudo pkill -f 'fluxvm-microvm controller' 2>/dev/null || true
sudo pkill -f 'fluxvm-microvm node-agent' 2>/dev/null || true
sleep 1
sudo mkdir -p /tmp/microvm-lab
sudo bash -c "cd /home/sus/.deployments/fluxvm && KUBECONFIG=/etc/rancher/k3s/k3s.yaml RUST_LOG=info PATH=$PATH \
  nohup ./target/release/fluxvm-microvm controller >/tmp/microvm-lab/controller.log 2>&1 & echo \$! >/tmp/microvm-lab/controller.pid"
sudo bash -c "cd /home/sus/.deployments/fluxvm && KUBECONFIG=/etc/rancher/k3s/k3s.yaml RUST_LOG=info PATH=$PATH \
  NODE_NAME=$NODE FLUXVM_URL=http://127.0.0.1:7788 FLUXVM_TOKEN=$TOKEN \
  nohup ./target/release/fluxvm-microvm node-agent >/tmp/microvm-lab/node-agent.log 2>&1 & echo \$! >/tmp/microvm-lab/agent.pid"
sleep 4

echo "########## microvm bench ##########"
BENCH_N=5 IMAGE=/var/lib/fluxvm/images/fluxvm-lifecycle-test.qcow2 \
  bash ./scripts/bench-microvm.sh | tee /tmp/bench-microvm.out

sudo kill "$(sudo cat /tmp/microvm-lab/controller.pid)" 2>/dev/null || true
sudo kill "$(sudo cat /tmp/microvm-lab/agent.pid)" 2>/dev/null || true
sudo pkill -f 'fluxvm-microvm' 2>/dev/null || true

echo "########## SUMMARY ##########"
echo "=== sandbox ==="
cat /tmp/bench-sandbox.out
echo "=== density ==="
cat /tmp/bench-density.out
echo "=== microvm ==="
cat /tmp/bench-microvm.out
