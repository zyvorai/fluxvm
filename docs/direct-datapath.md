# ⚡ Direct (bridge-less) datapath (Secure Containers)

Cilium delivers to a Pod without the host stack: `bpf_host` does `bpf_redirect_peer(lxc*)` and
the packet lands in the Pod's `eth0`. A Secure Container's guest used to sit behind a bridge
chain after that. The direct datapath removes the chain: a TC redirect moves frames straight
between the Pod's veth and the guest's tap, and **Cilium keeps every hook it has** on the
host-side `lxc*` peer. FluxVM never writes Cilium maps ([cilium-cni.md](cilium-cni.md)).

## ✅ What works

| Piece | Behavior |
|-------|----------|
| Shim knob | `FLUXVM_CONTAINER_CNI_DATAPATH=bridge\|direct\|auto` (default `bridge`) |
| `auto` | Direct when every precondition below holds; otherwise the bridge chain, with the reason logged. A direct create the daemon rejects is retried **once** on the bridge chain |
| `direct` | Direct or the Pod fails to start (no silent fallback) |
| Preconditions | kernel ≥ 5.10 (`bpf_redirect_peer`), the primary interface is a `veth`, no Multus secondaries, no warm pool |
| Topology | `eth0` keeps its MAC; its addresses/routes move to the guest (restored on teardown). No host bridge, no extra veth pair, no in-Pod bridge |
| Tap | Created by the daemon **inside the Pod netns** and handed to QEMU as an inherited fd (QEMU runs in the host netns and cannot open it by name). Non-persistent: it disappears with the VMM |
| Policy | Guest→Pod still runs `fluxvm_egress` (allow-list, L4, rate, conntrack, stats) **before** the redirect. Pod→guest passes the tap's egress hook, so the Set 14 Pod-ingress program still runs |
| Recovery | The wiring is recorded per VM (`direct.json`), so repair, reconfigure, status and remove re-enter the right netns and re-apply the redirect config |
| Kernel 7.x | The VM-edge program is loadable on Linux 7.0 (see below) |

## ⚠️ What does not work (honesty bounds)

- **Default is still `bridge`.** Nothing here has run in a live Kubernetes pod with a real guest.
  What is verified: the netns/veth/tap topology with a userspace guest on the real kernel, the
  daemon's loader end to end, the shim's netns preparation and cleanup, and the decision logic.
  Flip the default to `auto` only after a live Cilium + KVM run with packet-flow and NetworkPolicy
  evidence.
- Multus secondary NICs and warm-pool claims use the bridge chain (`auto` falls back, `direct` fails).
  Warm pools need QMP fd-passing for a tap that lives in another netns.
- **Service Fabric is not applied to direct taps** (its attaches take a bare interface name).
- Cilium in **netkit** mode (or macvlan/ipvlan Pods) is not a veth → bridge chain.
- Requires the daemon's `sandbox.dataplane.mode = ebpf` or `cilium`; `legacy` is rejected because the
  redirect is the only forwarding path. A failed dataplane attach is **fatal** for a direct VM.
- Live migration of a direct VM is not validated.
- A failed create leaves a `Failed` VM record in the daemon (pre-existing behavior for any create failure).
- No performance claim yet: `scripts/bench-direct-datapath.sh` measured only the bridge topologies
  (host forwarding cost, veth standing in for the tap). Re-run it against the direct path before quoting numbers.

## 🛠️ Operator setup

```bash
# daemon: sandbox.dataplane.mode = "ebpf" (or "cilium"); objects in /usr/lib/fluxvm/bpf include
#   fluxvm_tc.bpf.o and fluxvm_direct.bpf.o  (scripts/build-ebpf.sh, scripts/enable-network-fabric-ga.sh)
export FLUXVM_CONTAINER_CNI_DATAPATH=auto     # or direct / bridge
```

An old `fluxvm_tc.bpf.o` without the `fluxvm_direct` map cannot serve a direct VM: the attach fails,
and `auto` falls back to the bridge chain.

Evidence (Linux root, no KVM):

```bash
sudo ./scripts/test-direct-datapath.sh          # node ⇄ veth ⇄ tap ⇄ guest, policy, egress hook
sudo ./scripts/test-pod-policy-verdict.py       # pod-policy matching on the real object
sudo ./scripts/test-verifier-budget.sh          # verifier complexity guard
FLUXVM_TEST_BPF_DIR=dist/bpf sudo -E cargo test -p fluxvm-network --test direct_loader
```

## 📡 Packet path

```text
in :  NIC → bpf_host → redirect_peer → eth0 ingress [fluxvm_direct_in] → tap → guest
                                                     (tap egress hook: Pod-ingress policy)
out:  guest → tap ingress [fluxvm_egress policy, then redirect_peer] → lxc* ingress → bpf_lxc → NIC
```

`bpf_redirect_peer` only targets a veth/netkit peer, so the hop *into* the tap is a plain
`bpf_redirect`; the guest→Pod hop uses `redirect_peer`, as Cilium does.

## 🧯 Linux 7.x verifier note

On 7.0.0-31 the VM-edge program was rejected (`processed 1000001 insns`, limit 1,000,000). The pod-policy
rule scan inlined the whole rule match on each of 64 loop iterations in both address-family paths. The
per-rule match is now a global BPF function, verified once (Linux ≥ 5.5), and the object uses about
17% of the limit. `scripts/test-verifier-budget.sh` fails above 50%.

## 📚 Related

- [cilium-cni.md](cilium-cni.md) — the bridge-chain path this replaces when eligible
- [secure-containers-set14.md](secure-containers-set14.md) — Pod ingress/egress policy programs
- [network-fabric.md](network-fabric.md) — VM-edge dataplane
