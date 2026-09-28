# FAQ and fit

Is this for you, and the questions people ask first.

[Back to README](../README.md)

## Is this for you?

**A strong fit when you…**

- want VM lifecycle without a systemd/libvirtd dependency — direct netlink networking, JSON specs, a real REST API;
- run CI runners, sandboxed execution or per-branch environments and want cleanup you don't have to remember;
- are looking for a Kubernetes-native VM path that isn't KubeVirt (`DisposableVm`, `fluxvm-microvm`);
- want to adopt it standalone — no Fabric, Ragnarok or other Zyvor product required.

**Look elsewhere (for now) when you…**

- need a finished multi-tenant security boundary today ([details](proof-and-status.md#maturity-whats-real-today));
- need full Kata / CDI / non-QEMU Secure Containers VMM parity (Secure Containers is GA with documented scope boundaries);
- need KubeVirt/OpenShift compatibility (`virtctl`, CDI, live-migration parity);
- need published performance numbers for capacity planning.

---

## FAQ

**Is FluxVM production-ready?** For the core VM-lifecycle primitives (auth/RBAC, jailer, cgroups, netns), yes — with the caveats in [Proof & status](proof-and-status.md#maturity-whats-real-today). Turn on `policy.require_catalog_names`, the quota ledger, `FLUXVM_VMM_SECCOMP`, and the AppArmor or SELinux profile before exposing it to untrusted tenants. Secure Containers is GA with documented scope boundaries (not Kata-equivalent).

**How is this different from libvirt?** No libvirtd, no XML domain definitions — its own REST API, with netlink for networking. See [vs. libvirt/virsh](vs-libvirt.md#vs-libvirtvirsh).

**How is this different from KubeVirt?** A different model: FluxVM's `DisposableVm` and MicroVM paths run the VMM on the host under `fluxctl serve`, not inside a virt-launcher Pod. `kubectl-fluxvm` covers console, exec, pause, resume, and CR delete. `GuestImage` HTTP staging is not CDI. QEMU live migration has a target receiver; it is not KubeVirt migration parity. Full comparison: [docs/microvm.md](microvm.md#vs-disposablevm-and-kubevirt).

**Do I need Fabric or Ragnarok?** No. Clone it, build it, run `fluxctl create`. Fabric and Ragnarok are separate products that use FluxVM as their VM engine — see [Ecosystem](ecosystem.md#ecosystem).

**What storage backends are supported?** qcow2/raw, LVM thin, NBD and Ceph RBD — see [Bring-your-own storage backend](use-cases.md#bring-your-own-storage-backend).

**Are there published boot-latency or density numbers?** The measurement method is `scripts/record-baseline.sh`. Each evidence file is one host, and `avg_create_ms` is API create time, not guest init. It is not a sizing SLA until the same script has been repeated on a second host. Don't treat Firecracker's 125 ms target as a FluxVM number.

**How do I test security profiles without SNP/TDX hardware?** Run `./scripts/test-security-profiles.sh` (same suite as [CI](../.github/workflows/security-profiles.yml)). Measured evidence is always `software-test` — see [docs/guides/security-profiles-howto.md](guides/security-profiles-howto.md).

**What license is this under?** Apache License 2.0 for the whole repository, no dual licensing — see [License](../README.md#license).
