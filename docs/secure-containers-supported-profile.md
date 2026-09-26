# Secure Containers — supported production profile

**Name:** `fluxvm-sc-supported` (informal).  
**Status:** GA RuntimeClass with documented boundaries — **not** full Kata Containers compatibility.

This is the profile buyers can run in production without soft language. Outside this
matrix, stay on Kata/CoCo or treat the workload as lab-only.

## Supported matrix

| Constraint | Supported | Notes |
|---|---|---|
| VMM | **QEMU** (primary); Cloud Hypervisor allowed | Set `FLUXVM_CONTAINER_BACKEND=qemu` or `cloud-hypervisor` |
| Firecracker | Block-share path only | No live virtio-fs; Pod shares packed to ext4 at launch; needs `FLUXVM_CONTAINER_KERNEL` |
| CNI primary | Cilium, Calico, or Flannel | Auto-detect via `FLUXVM_CONTAINER_CNI_PROVIDER`; datapath `auto` (direct with bridge fallback) |
| Multus | Secondary NICs opt-in | Hybrid bridge default; `FLUXVM_CONTAINER_CNI_MULTUS_DATAPATH=direct\|auto` when ready |
| hostPath | Allowlist / broker only | `FLUXVM_HOSTPATH_ALLOW` and/or `FLUXVM_HOSTPATH_BROKER=1` (QEMU/CH hotplug) |
| Guest image | guestkit-baked Fedora or Ubuntu SC guest | Prefer signed catalog entries; token inject via guestkit (no virt-customize in the FluxVM path) |
| Policy | In-cluster `NetworkPolicy` → Sentinel | Host TC + optional guest `cgroup_skb` mirror; opt-in remote seccomp NOTIFY RPC (`mode=remote`) |
| Isolation extras | Opt-in `CLONE_NEWUSER`, SELinux `linux.mountLabel`, seccomp NOTIFY | Live evidence under `docs/benchmarks/evidence/sc-live-*.txt` |
| TEE / confidential | **Out of profile** | SC is **isolation without TEE**. SNP/TDX + attestation stays Ragnarok + Kata/KubeVirt |

## Parity vs Kata (decision table)

| Capability | FluxVM SC | Stay on Kata / CoCo when… |
|---|---|---|
| Pod → own guest kernel | Yes (RuntimeClass `fluxvm`) | You need Kata’s exact packaging / ecosystem tooling |
| OCI RuntimeClass drop-in | Yes (`runtimeClassName: fluxvm`) | You already standardized on `kata` RuntimeClasses cluster-wide |
| Live virtio-fs write-through | QEMU/CH yes; Firecracker no | You require FC + live virtio-fs |
| Unrestricted hostPath | No (allowlist / fail-closed) | You require arbitrary host binds |
| Remote seccomp policy RPC | Opt-in `mode=remote` | Guest→host AF_VSOCK; default deny; HTTP via `FLUXVM_SECCOMP_POLICY_RPC_URL` |
| Host + guest eBPF NetworkPolicy (Sentinel) | Yes — [sentinel-wedge.md](sentinel-wedge.md) | You only need Kata’s static policy files |
| SEV-SNP / TDX attestation | No | You need hardware TEE + attest-gated secrets |
| CDI / `virtctl` / KubeVirt API | No | You need that control plane |

## Non-goals (keep)

- Feature-for-feature Kata / CDI / `virtctl`
- Claiming remote seccomp RPC as a Kata-compatible policy file drop-in
- Claiming in-tree virtio-fs is as deep as Cloud Hypervisor under load (prefer CH for production shared-FS)
- Claiming SC as confidential / TEE

## Evidence

Live lab pack (dated): [benchmarks/evidence/sc-hotcake-bundle-20260926.txt](benchmarks/evidence/sc-hotcake-bundle-20260926.txt)  
Flip runbook: [secure-containers-flip-runtimeclass.md](secure-containers-flip-runtimeclass.md)  
Rollup: [secure-containers.md](secure-containers.md)
