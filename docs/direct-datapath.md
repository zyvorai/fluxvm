# ⚡ Direct (bridge-less) datapath

Cilium delivers to a Pod without the host stack: `bpf_host` does `bpf_redirect_peer(lxc*)` and
the packet lands in the Pod's `eth0`. A Secure Container's guest used to sit behind a bridge
chain after that. The direct datapath removes the chain: a TC redirect moves frames straight
between the outer device and the guest's tap, and **Cilium keeps every hook it has** on the
host-side `lxc*` peer. FluxVM never writes Cilium maps ([cilium-cni.md](cilium-cni.md)).

Two attach modes share one mechanism:

| Mode | Outer device | Where | Use |
|------|--------------|-------|-----|
| `peer-veth` | the Pod's veth `eth0` | tap created **inside the Pod netns** | Secure Containers under Cilium/any veth CNI |
| `l2-uplink` | a physical/bond NIC with no bridge master | tap in the host netns | standalone VMs replacing `vmbr0` |

## ✅ What works

| Piece | Behavior |
|-------|----------|
| Shim knob | `FLUXVM_CONTAINER_CNI_DATAPATH=bridge\|direct\|auto` (default `auto`) |
| `auto` | Direct when every precondition holds, else the bridge chain with the reason logged; a create or warm-pool hotplug the daemon rejects is retried **once** on the bridge chain |
| `direct` | Direct or the Pod fails to start (no silent fallback) |
| Preconditions | kernel ≥ 5.10 (`bpf_redirect_peer`), the primary interface is a `veth`, no Multus secondaries |
| Pod topology | `eth0` keeps its MAC; its addresses/routes move to the guest (restored on teardown). No host bridge, no extra veth pair, no in-Pod bridge |
| Tap handoff | Created by the daemon inside the Pod netns and given to QEMU as an inherited fd (QEMU runs in the host netns and cannot open it by name). Non-persistent: it disappears with the VMM |
| Warm pool | The claimed VM (booted `network.mode=none`) gets its NIC over QMP: `getfd` (the tap as `SCM_RIGHTS`) → `netdev_add fd=…` → `device_add`, all on **one** QMP session because QEMU resolves a named fd through the monitor that received it. The dataplane is applied *before* QEMU sees the NIC |
| Policy | Guest→out runs `fluxvm_egress` (allow-list, L4, rate, conntrack, stats) **before** the redirect. Out→guest passes the tap's egress hook, so the Set 14 Pod-ingress program still runs |
| Recovery | The wiring is recorded per VM (`direct.json`), so repair, reconfigure, status and remove re-enter the right netns and re-apply the redirect config |
| Attach | TCX when available, else legacy clsact at a reserved pref with a per-VM handle. Both are tested |
| `l2-uplink` | Several VMs share one unbridged uplink: inbound frames are steered by destination MAC, ARP requests by their **target IP** (`direct.guest_ips`), guest↔guest is switched locally. The MAC/IP maps are shared per uplink and each VM adds/removes only its own entries |
| CRD | `MicroVM.spec.networkMode: direct` with `parent` (the uplink), `mac`, `guestIps` |
| Hop view | `hubble observe` / packet-flow hops show the real path (no invented bridge) |
| Capability probe | `tools/fluxvm-sentinel-certify.py` reports `redirect_peer` / `redirect_neigh` from the kernel's own helper list |
| Linux 7.x | The VM-edge program loads on Linux 7.0 (see the verifier note) |

## ⚠️ What does not work (honesty bounds)

- **The shim default is `auto`, on the strength of one live run.** On a single-node k3s + Cilium v1.20.2
  (veth mode) node, kernel 7.0.0-31, KVM, QEMU 10.2.1, two `RuntimeClass fluxvm` Pods in `direct` mode became
  Ready, reached each other, left no `fvbh*` bridge on the node, and a deny-all `NetworkPolicy` still blocked
  the client ([evidence](benchmarks/evidence/direct-datapath-live-20260919T202359Z.txt)). A real QEMU also
  accepted both the launch-time tap descriptor and the warm-pool `getfd`/`netdev_add fd=` sequence.
  **Not measured or exercised live:** bridge-vs-direct latency/throughput with a real guest (the table below is a
  veth stand-in), the create-time `auto` fallback loop (no automated test), a warm-pool claim from a Pod,
  Multus secondaries, and standalone `l2-uplink` with a real guest (that mode is chosen per VM, never by default).
  `FLUXVM_CONTAINER_CNI_DATAPATH=bridge` is the kill switch.
- Multus secondary NICs use the bridge chain (`auto` falls back, `direct` fails).
- **Service Fabric is not applied to direct taps** (its attaches take a bare interface name).
- Cilium in **netkit** mode (or macvlan/ipvlan Pods) is not a veth → bridge chain.
- Requires the daemon's `sandbox.dataplane.mode = ebpf` or `cilium`; `legacy` is rejected because the
  redirect is the only forwarding path. A failed dataplane attach is **fatal** for a direct VM.
- `l2-uplink` bounds: **IPv4 ARP only (no IPv6 NDP)**, **no host↔guest traffic** (same as macvtap; the
  host cannot reach a guest on its own uplink without an egress hook), DHCP broadcast replies and other
  broadcast/multicast do not reach guests, the uplink must not be a bridge/bond port, and at most 1024
  MACs / IPs per uplink. Stale entries from a crashed daemon are overwritten on the next attach.
- `l2-uplink` steering comes only from the operator-declared MAC and `guest_ips`, never learned from guest
  traffic, so a guest cannot poison the maps. Declaring the **same** MAC or IP for two VMs on one uplink
  is not detected: the last attach wins.
- Live migration of a direct VM is not validated.
- The shared per-uplink maps stay pinned under `<pin_root>/uplinks/<nic>/` (a few KB) after the last VM leaves.
- A failed create leaves a `Failed` VM record in the daemon (pre-existing behavior for any create failure).
- `Policy.allowed_network_modes` sees a direct VM as `tap`.

## 🛠️ Operator setup

```bash
# daemon: sandbox.dataplane.mode = "ebpf" (or "cilium"); /usr/lib/fluxvm/bpf must hold
#   fluxvm_tc.bpf.o and fluxvm_direct.bpf.o  (scripts/build-ebpf.sh, scripts/enable-network-fabric-ga.sh)
# TCX attach needs the helper: /usr/libexec/fluxvm/fluxvm-tcx (scripts/build-runtime-intelligence.sh);
#   without it FLUXVM_TCX=auto quietly uses legacy tc
export FLUXVM_CONTAINER_CNI_DATAPATH=auto     # or direct / bridge   (shim, per node)
```

An old `fluxvm_tc.bpf.o` without the `fluxvm_direct` map cannot serve a direct VM: the attach fails,
and `auto` falls back to the bridge chain.

**Standalone uplink VM** (`POST /v1/vms`; the uplink must be an unenslaved NIC):

```json
{"network": {"mode": "tap", "mac": "02:00:00:00:0a:0a",
             "direct": {"outer": "enp1s0", "mode": "l2-uplink", "guest_ips": ["192.168.1.50"]}}}
```

## 📡 Packet paths

```text
Pod (peer-veth)
  in : NIC → bpf_host → redirect_peer → eth0 ingress [fluxvm_direct_in] → tap → guest
                                                       (tap egress hook: Pod-ingress policy)
  out: guest → tap ingress [fluxvm_egress policy, then redirect_peer] → lxc* ingress → bpf_lxc → NIC

Standalone (l2-uplink)
  in : LAN → NIC ingress [fluxvm_direct_in: ARP by target IP / MAC → tap] → tap → guest
  out: guest → tap ingress [fluxvm_egress policy, then: local guest? → its tap : NIC] → LAN
```

`bpf_redirect_peer` only targets a veth/netkit peer, so the hop *into* the tap is a plain
`bpf_redirect`; the guest→Pod hop uses `redirect_peer`, as Cilium does. "Not mine" is `TC_ACT_UNSPEC`,
never `TC_ACT_OK` (which ends a TCX chain and would hide the frame from the next VM's copy).

## 📈 Measured forwarding cost

<!-- RESULTS -->
Median of 6 interleaved rounds on Linux 7.0.0-31-generic x86_64 cpus=12 (load average at start 2.45 3.21 3.02), run 2026-09-19T19:18:54Z.
Source: [`direct-datapath-interleaved-20260919T191854Z.txt`](benchmarks/evidence/direct-datapath-interleaved-20260919T191854Z.txt) / [`.json`](benchmarks/evidence/direct-datapath-interleaved-20260919T191854Z.json).
A veth pair stands in for the tap in every row, so this is **host forwarding cost only**: no virtio, no QEMU.
The `+ fluxvm_egress` rows run the same real policy program the direct rows run, so the comparison is like for like.

| Topology | Devices | Ping p50 (ms) | Ping p99 (ms) | TCP (Gbit/s) | TCP run spread | 64 B UDP (Mpps) |
|---|---:|---:|---:|---:|---:|---:|
| floor (one veth pair, no bridge) | 2 | 0.0365 | 0.062 | 45.8 | ±17% | 0.428 |
| Pod, bridge chain (bare) | 8 | 0.0565 | 0.0955 | 36.6 | ±18% | 0.227 |
| Pod, bridge chain + `fluxvm_egress` | 8 | 0.062 | 0.107 | 37.1 | ±18% | 0.222 |
| **Pod, direct** | 4 | 0.0425 | 0.0725 | 43.4 | ±14% | 0.355 |
| Standalone, `vmbr0` (bare) | 5 | 0.051 | 0.0865 | 40.4 | ±16% | 0.291 |
| Standalone, `vmbr0` + `fluxvm_egress` | 5 | 0.057 | 0.097 | 40.8 | ±17% | 0.287 |
| **Standalone, direct (`l2-uplink`)** | 4 | 0.051 | 0.0895 | 43.5 | ±18% | 0.35 |

- **Pod direct vs the bridge chain with the same policy program:** -31% latency, +17% (within noise) TCP, +60% 64 B pps.
- **Standalone direct vs `vmbr0` with the same policy program:** -11% (within noise) latency, +6% (within noise) TCP, +22% 64 B pps.

How to read it: negative latency and positive throughput are improvements. The machine is a shared
Kubernetes node: a delta is marked "within noise" when it is no larger than the half-range of the runs on
either side, and those should not be read as improvements. Re-run
`BENCH_INTERLEAVE=1 ./scripts/bench-direct-datapath.sh` on a quiet box before quoting an exact figure.
These numbers say nothing about a real guest (`BENCH_TARGET_IP` measures one).
<!-- /RESULTS -->

**Takeaway.** Removing the bridge chain clearly helps where the chain is long: on the Pod path (8 devices → 4) latency drops by about
a third and small-packet throughput rises by about 60%, landing within roughly 15% of the no-bridge floor. Bulk TCP throughput is inside the
noise on this shared machine, so no TCP claim is made. The standalone path already had a short chain (5 → 4 devices), and only its
small-packet rate is clearly better. This is the cost of moving frames on the host, not of the guest, so a real VM will see a smaller
fraction of it once virtio and the VMM are included.

## 🧯 Linux 7.x verifier note

On 7.0.0-31 the VM-edge program was rejected (`processed 1000001 insns`, limit 1,000,000). The pod-policy
rule scan inlined the whole rule match on each of 64 loop iterations in both address-family paths. The
per-rule match is now a global BPF function, verified once (Linux ≥ 5.5), and the object uses about
17% of the limit. `scripts/test-verifier-budget.sh` fails above 50%.

## 🧪 Evidence

```bash
./scripts/evidence-direct-datapath.sh                        # static + unit/integration suites
sudo FLUXVM_DIRECT_KERNEL=1 FLUXVM_BPF_DIR=dist/bpf ./scripts/evidence-direct-datapath.sh
FLUXVM_DIRECT_LIVE=1 FLUXVM_CONTAINER_CNI_DATAPATH=direct ./scripts/evidence-direct-datapath.sh   # the gate for `auto`
sudo ./scripts/test-direct-datapath.sh                       # pod veth ⇄ tap ⇄ guest, policy, egress hook
sudo ./scripts/test-direct-uplink.sh                         # two VMs, one uplink (TCX and legacy tc)
sudo ./scripts/test-pod-policy-verdict.py                    # rule matching on the real object
sudo ./scripts/test-verifier-budget.sh                       # verifier complexity guard
sudo FLUXVM_BPF_DIR=dist/bpf ./scripts/bench-direct-datapath.sh
```

## 📚 Related

- [cilium-cni.md](cilium-cni.md) — the bridge-chain path this replaces when eligible
- [secure-containers-set14.md](secure-containers-set14.md) — Pod ingress/egress policy programs
- [network-fabric.md](network-fabric.md) — VM-edge dataplane
- [macvtap](../crates/fluxvm-network/src/lib.rs) — the older bridge-less mode (host netns only, no policy hook)
