# Flip RuntimeClass to FluxVM Secure Containers

Fifteen-minute path from a Linux/KVM + k3s (or containerd) host to a smoke Pod
on RuntimeClass `fluxvm`. For the supported production matrix see
[secure-containers-supported-profile.md](secure-containers-supported-profile.md).

## Prerequisites

- Linux with `/dev/kvm`, cgroup v2
- Working `fluxctl serve` (or FluxVM DaemonSet) on `http://127.0.0.1:7788`
- containerd **or** k3s
- `virtiofsd` on PATH (QEMU/CH shares)
- Guest image at `/var/lib/fluxvm/images/secure-container.qcow2` (or set
  `FLUXVM_CONTAINER_GUEST_IMAGE`) with `fluxvm-guest-agent` enabled

## 1. Install shim + agent

```bash
# From a fluxvm checkout
sudo ./scripts/install-secure-containers.sh
# Or full lab provision (builds guest image if missing):
sudo ./scripts/provision-secure-containers-lab.sh
# Load k3s runtime drop-in:
sudo FLUXVM_SC_RESTART_K3S=1 ./scripts/provision-secure-containers-lab.sh
```

Confirm Absolute `BinaryName` (k3s often omits `/usr/local/bin` from PATH):

```bash
grep -R BinaryName /var/lib/rancher/k3s/agent/etc/containerd/config-v3.toml.d/ 2>/dev/null
# expect: BinaryName = "/usr/local/bin/containerd-shim-fluxvm-v2"
```

## 2. Shim environment

Systemd drop-ins (written by the provision script) should include:

```text
FLUXVM_API_URL=http://127.0.0.1:7788
FLUXVM_CONTAINER_GUEST_IMAGE=/var/lib/fluxvm/images/secure-container.qcow2
FLUXVM_CONTAINER_AGENT_BINARY=/usr/local/libexec/fluxvm-container-agent
FLUXVM_CONTAINER_USERNS=1
```

**CNI:** Full Cilium/Calico L2 needs FluxVM CNI enabled on the shim path used by
your cluster. For a hostNetwork smoke that skips Pod CNI hangs, use the wow demo
hostNetwork mode or set `FLUXVM_CONTAINER_CNI=0` only in controlled labs.
Default production profile expects CNI on.

Keep **sandboxer=podsandbox** (default). Do not set `sandboxer=shim` — this
shim does not implement containerd’s Sandbox TTRPC service.

## 3. RuntimeClass

```bash
kubectl apply -f deploy/containerd/runtimeclass.yaml
kubectl get runtimeclass fluxvm
```

## 4. Smoke Pod

```bash
kubectl apply -f - <<'YAML'
apiVersion: v1
kind: Pod
metadata:
  name: fluxvm-sc-smoke
spec:
  runtimeClassName: fluxvm
  restartPolicy: Never
  containers:
  - name: probe
    image: busybox:1.36
    command: ["sh", "-c", "echo hello-from-guest-kernel; sleep 30"]
YAML
kubectl wait --for=condition=Ready pod/fluxvm-sc-smoke --timeout=600s
kubectl logs fluxvm-sc-smoke
kubectl delete pod fluxvm-sc-smoke --wait=false
```

## 5. Optional wow path

```bash
FLUXVM_SECURE_CONTAINERS_E2E=1 ./scripts/demo-secure-containers-wow.sh
```

Runs RuntimeClass userns (and optional SELinux / multi-container distinct)
wrappers against the same lab.

## When to stay on Kata

- You need SEV-SNP/TDX + attestation (use Ragnarok + Kata/KubeVirt).
- You need unrestricted hostPath or Firecracker + live virtio-fs.
- You need remote seccomp policy RPC.

Otherwise `runtimeClassName: fluxvm` is the supported flip.
