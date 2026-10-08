# Proof and status

We only claim what has been run. What is verified today, and the boundaries to know before you commit.

[Back to README](../README.md)

<a id="maturity-whats-real-today"></a>

## Proof & status

We only claim what has been run. Every row links to how it was verified.

| Verified today | Evidence |
|---|---|
| **Kubernetes operator** reconciles real VMs, self-heals out-of-band deletes, and cleans up with no leaked QEMU | 9/9 checks on a real k3s cluster — [`scripts/test-kube-operator.sh`](../scripts/test-kube-operator.sh) |
| **Multi-host fleet**: central registry with load-aware placement | Two real, physically separate hosts — [docs/operations.md](operations.md#distributed-node-agent) |
| **Storage**: qcow2/raw, LVM thin, NBD, Ceph RBD | RBD verified against a real Rook Ceph cluster |
| **Networking**: user-mode NAT, TAP+bridge, netns+DHCP, macvtap | All four SSH-verified end to end in the regression tests |
| **Network Fabric** (TC/eBPF, schema v4) | **GA, primary default** (`mode = "ebpf"`, `required = true`; nftables via explicit `mode = "legacy"`). Deny-by-default policy: `sudo ./scripts/enable-network-fabric-ga.sh --restart` — [docs/primary-ebpf.md](primary-ebpf.md), — [docs/network-fabric.md](network-fabric.md) |
| **Bridge-less direct datapath** cuts the forwarding path | Measured host forwarding cost vs the bridge chain with the same policy program: **−31% latency, +60% 64 B packet rate** (Pod case). A veth stand-in on a shared node, TCP deltas within noise, no real guest — [method and raw data](direct-datapath.md#-measured-forwarding-cost) |

**Know before you commit.** These are the boundaries, stated up front so you can size the fit:

- **Multi-tenant controls are opt-in, not a public-cloud boundary.** Create-path quotas use an O(1) ledger, `policy.require_catalog_names` rejects unsigned images, QEMU/Cloud Hypervisor children can take a log-mode seccomp filter (`FLUXVM_VMM_SECCOMP`), and AppArmor/SELinux profiles ship under `deploy/`. Per-tenant Firecracker uids need `[jailer] uid_range_start` / `uid_range_len`. Pause, resume, and delete do not hash images or scan the fleet. See [docs/PRODUCTION.md](PRODUCTION.md).
- **Secure Containers (containerd runtime-v2 shim) is GA**, not a Kata-equivalence claim. Supported profile + flip runbook: [docs/secure-containers-supported-profile.md](secure-containers-supported-profile.md), [docs/secure-containers-flip-runtimeclass.md](secure-containers-flip-runtimeclass.md). Allowlisted hostPath is a virtiofs export when `FLUXVM_HOSTPATH_ALLOW` is set at sandbox create (symlink escape fails closed). Multus on the direct datapath fails closed. Live lab pack: [docs/benchmarks/evidence/sc-hotcake-bundle-20260926.txt](benchmarks/evidence/sc-hotcake-bundle-20260926.txt). Broader second-CNI under load still prefers `FLUXVM_SECOND_CNI_KUBECONFIG` —
  [docs/secure-containers.md](secure-containers.md).
- **Not KubeVirt-compatible, by design.** `kubectl-fluxvm` is the console/exec/pause/resume plugin and deletes the CR (the operator finalizes the VM). `GuestImage` HTTP sources are staged on the node and are not CDI DataVolumes; unsigned downloads are not promoted to a trusted catalog name. QEMU has a target receiver at `POST /v1/migration/receivers` (`-incoming defer`); Cloud Hypervisor stays fire-and-forget, and direct-datapath migration is refused. See [FAQ](faq.md#faq).
- **Boot and density numbers are a method plus archived samples, not a sizing SLA.** See the capacity table in [docs/PRODUCT_OVERVIEW.md](PRODUCT_OVERVIEW.md) and [docs/benchmarks/evidence/sc-hotcake-bundle-20260926.txt](benchmarks/evidence/sc-hotcake-bundle-20260926.txt). `scripts/record-baseline.sh` writes per-host records under `docs/benchmarks/evidence/`.
