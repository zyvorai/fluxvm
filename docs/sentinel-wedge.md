# Sentinel wedge — policy Kata does not ship

**One sentence:** Secure Containers give every Pod its own guest kernel;
**Sentinel** adds a shared host↔guest eBPF policy schema so Kubernetes
`NetworkPolicy` reaches the VMM edge **and** (optionally) the guest — something
Kata’s namespace + seccomp + static policy-file model does not attempt.

## What buyers get

| Layer | What Sentinel does |
|---|---|
| Host (VMM edge) | TC/eBPF directional CIDR+L4 rules from in-cluster NetworkPolicy (Sets 14–19): `ipBlock.except`, SCTP, named/`endPort`, stateful Pod-ingress |
| Guest | Optional per-container `cgroup_skb` mirror of create-time + live CIDR/direction policy (Set 8S / Set 19) |
| Observe | Read-only Policy Observer + Prometheus scrape (`tools/fluxvm-policy-observer`, ServiceMonitor examples) |

## What it is not

- Not a TEE / confidential computing product (see Ragnarok for SNP/TDX).
- Not remote seccomp policy RPC (explicitly out of scope).
- Not “Kata-equivalent packaging.”

## Where to go next

- Supported profile: [secure-containers-supported-profile.md](secure-containers-supported-profile.md)
- Flip RuntimeClass: [secure-containers-flip-runtimeclass.md](secure-containers-flip-runtimeclass.md)
- Rollup + Set links: [secure-containers.md](secure-containers.md)
- Direct datapath (bridge-less Pod↔guest): [direct-datapath.md](direct-datapath.md)
