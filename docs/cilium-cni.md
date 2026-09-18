# 🔌 Cilium CNI support (Secure Containers)

FluxVM does **not** ship a Cilium fork or write Cilium-private BPF maps.
On Cilium nodes, Secure Containers keep Cilium as the Pod CNI and hand the
Pod's primary L2 endpoint (`eth0` IP/MAC/routes) into the guest VM.

Network Fabric `sandbox.dataplane.mode = "cilium"` is a separate coexistence
path for **VM-edge** TC policy — see [ebpf-cilium.md](ebpf-cilium.md). This
document covers the **containerd shim CNI L2** path.

## ✅ What works

| Piece | Behavior |
|-------|----------|
| Provider | `FLUXVM_CONTAINER_CNI_PROVIDER=auto\|cilium\|generic` (default `auto`) |
| Detection | `auto` checks `cilium.sock`, `/opt/cni/bin/cilium-cni`, `/etc/cni/net.d/*cilium*`, and pod-side `cilium*` ifaces |
| Primary iface | Prefers configured iface (default `eth0`); falls back to first routable non-Multus iface |
| Multus | `netN` secondaries are **ignored** under provider=`cilium` so primary handoff proceeds; they are **not** attached to the guest |
| Dual-stack | IPv4 + IPv6 addresses/routes on the primary iface (Set 6) |
| Host TC | Cilium programs stay on the host `lxc*` peer; FluxVM bridges the pod-side endpoint |

## ⚠️ What does not work (honesty bounds)

- Full Multus / secondary-NIC hotplug into the guest (still open; Set 6 guard).
- Writing Cilium identity / ipcache / endpoints maps.
- Replacing Cilium NetworkPolicy with FluxVM as the Pod CNI.
- Claiming Hubble attribution for every guest packet without CEP enrich
  ([hubble-lite.md](hubble-lite.md)).

## 🛠️ Operator setup

1. Install Secure Containers (`scripts/install-secure-containers.sh`) and merge
   `deploy/containerd/fluxvm-runtime.toml`.
2. On Cilium nodes, export shim env (or use `configs/cilium-cni.toml` as the
   Network Fabric coexistence fragment + the env comments as SoT):

```bash
export FLUXVM_CONTAINER_CNI=1
export FLUXVM_CONTAINER_CNI_PROVIDER=auto   # or force cilium
export FLUXVM_CONTAINER_CNI_INTERFACE=eth0
```

3. Optional VM-edge Fabric coexistence:

```bash
sudo ./scripts/enable-network-fabric-ga.sh --cilium --restart
```

4. Deploy RuntimeClass / DaemonSet mounts from [deploy/k8s/cilium/](../deploy/k8s/cilium/).

5. Evidence:

```bash
./scripts/evidence-cilium-cni.sh
# live (optional): FLUXVM_CILIUM_CNI_LIVE=1 ./scripts/evidence-cilium-cni.sh
```

## 📡 Packet path (primary)

```text
Pod netns eth0 (CNI-assigned IP/MAC)
  → FluxVM L2 rebridge (host bridge + guest TAP)
  → guest virtio-net with same IP/MAC/routes
Host lxc* peer keeps Cilium TC/eBPF; FluxVM never writes Cilium maps.
```

## 📚 Related

- [secure-containers-set6.md](secure-containers-set6.md) — dual-stack + Multus guard
- [ebpf-cilium.md](ebpf-cilium.md) — `mode=cilium` Fabric coexistence
- [network-policy.md](network-policy.md) — FluxVM policy vs Cilium CNP
