# AI-agent sandbox gaps

FluxVM is a **multi-VMM disposable-VM control plane** (QEMU, Cloud Hypervisor,
Firecracker, and the in-tree **FluxVM hypervisor**) with CLI/REST, warm pools,
and Kubernetes CRDs — a host-local libvirt/virsh-style lifecycle layer.

The FluxVM hypervisor track (`backend: "flux-vm"`) is the AI-agent sandbox path.

## Implemented on the FluxVm track

| Feature | Status |
|---------|--------|
| `BackendKind::FluxVm` + `fluxvm-hypervisor` UDS control API | Yes |
| Real guest boot via Firecracker engine under FluxVM control | Yes |
| **`fluxvm_engine = "kvm"`** — pure in-tree KVM (no Firecracker child) | Yes (opt-in) |
| Pause / resume / shutdown (proxied to guest engine) | Yes |
| **Memory+disk snapshot** (Firecracker `/snapshot/create` + FICLONE) | Yes |
| **Fast restore** via `/snapshot/load` (cold-boot fallback) | Yes |
| `/v1/sandboxes` + fs/process APIs | Yes |
| **Guest HTTP reverse proxy** (`/sandbox/{id}/…`, AutoResume) | Yes |
| **Multi-port proxy defaults** on sandbox create (`http_proxy_port(s)`) | Yes |
| AutoPause + activity tracking + wake-on-request | Yes |
| Egress allowlist + credential vault + live L7 proxy | Yes |
| **Sandbox dataplane** — Network Fabric **GA (schema v4)**: `legacy` nftables (default), `ebpf` TC IPv4/IPv6 L3+L4 + rate limits + groups/deny/CT, `cilium` coexistence, CNP/identities/observe, health/ipcache/refresh-dns, policy/status/stats/flows API, optional XDP, schema/fingerprint repair | Yes — [network-fabric.md](network-fabric.md), [network-groups.md](network-groups.md), [network-policy.md](network-policy.md), [production-dataplane.md](production-dataplane.md) |
| OCI → template export | Yes |
| **Redis shared sandbox index** (`FLUXVM_SANDBOX_STATE_URL`) | Yes |
| `/console` ops UI | Yes |
| **Benchmarks** — `scripts/bench-sandbox.sh`, [docs/benchmarks/README.md](../benchmarks/README.md) | Yes |

### Dataplane (summary)

- **Status: GA** — enable with `sudo ./scripts/enable-network-fabric-ga.sh --restart`
  or merge `configs/network-fabric-ga.toml`. Production profile:
  `configs/network-fabric-prod.toml` — [production-dataplane.md](production-dataplane.md).
- **Default (upgrade-safe):** `sandbox.dataplane.mode = "legacy"` (nftables).
- **`ebpf`:** TC program from `bpf/fluxvm_tc.bpf.c`; pins under `/sys/fs/bpf/fluxvm`;
  iface/schema/fingerprint meta under `/run/fluxvm/ebpf`; IPv4/IPv6 L3+L4
  allowlists (`allow_cidrs`, `allow_ports`); Mbps/PPS limits; stats/flows/events;
  schema **v4** maps (`fluxvm_gid`, `fluxvm_ct`, `fluxvm_deny4/6`);
  ARP/DHCP/NDP bootstrap always allowed; fallback to nftables unless
  `required = true` **and** a host-visible edge exists (user NAT / `mode=none`
  soft-skip; IPv6/rate never silently downgrade). Optional node XDP
  (`bpf/fluxvm_xdp.bpf.c`, meta under `/run/fluxvm/xdp/`) — disabled by default
  and refused in `cilium` mode.
- **`cilium`:** same FluxVM edge attach after verifying `/var/run/cilium/cilium.sock` +
  bpffs; **does not** write Cilium private maps (coexistence, not Cilium endpoint identity).
- **REST:** per-VM `GET/POST …/network/policy`, `…/status`, `…/stats`, `…/flows`,
  `…/effective`; fabric-wide `/v1/network/groups`, `/cnp`, `/identities`,
  `/observe`, `/health`, `/ipcache`, `POST /refresh-dns` (native modes;
  writes need admin when auth is enabled).
- **v3 GA path / schema v4:** dual-stack core ABI plus groups, CNP, deny CIDRs,
  conntrack, FQDN resolve-at-apply, ipcache, health; NDJSON flow exporter.

Applied on FluxVm create/start/restart on the host-visible interface (guest CIDR
optional for native). See [network-fabric.md](network-fabric.md),
[network-policy.md](network-policy.md), [production-dataplane.md](production-dataplane.md),
and README [eBPF / Cilium sandbox dataplane](../README.md#ebpf--cilium-sandbox-dataplane)
plus [architecture](../README.md#network-fabric-architecture-how-it-works).

## Remaining (optional hardening)

- Production-grade in-tree KVM guests (full virtio device live-state in snapshots)
- Hubble SID attribution for VM traffic beyond agent CEP enrichment
- Optional: scrape `MICROVM_METRICS_ADDR` (default `127.0.0.1:9108`) from Prometheus
- **In-tree KVM (`fluxvm_engine = "kvm"`) boot hang**: some Linux guests
  hang deterministically late in boot (confirmed not caused by CPU/
  paging setup — identical under both PVH and direct-64-bit boot).
  Real SMP (`--cpus N`) and PVH boot are implemented and working; a
  `--gdb` debugging stub (register/memory inspection + breakpoints) is
  available for continuing the investigation. See
  [`crates/fluxvm-hypervisor/README.md`](../crates/fluxvm-hypervisor/README.md#known-limitations).

Shipped: concurrent density (`scripts/bench-density.sh`), Cilium-agent CEP
identity enrich (no private maps), in-tree KVM `FLUXKVM1` memory snapshots,
MicroVM schedule→Running histograms.

## Host config

```toml
# config.toml
fluxvm_engine = "firecracker"   # default
# fluxvm_engine = "kvm"         # no Firecracker child — in-tree KVM thread

[sandbox]
http_proxy_default_port = 8080

# [sandbox.dataplane]
# mode = "ebpf"                 # GA: enable-network-fabric-ga.sh
# bpf_object = "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o"
# pin_root = "/sys/fs/bpf/fluxvm"
# required = true
# default_allow = false
# allow_cidrs = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
# allow_ports = ["tcp/443", "tcp/80", "udp/53"]
# max_egress_mbps = 250
# max_egress_pps = 100000
# sample_rate = 100             # 0 = off
# [sandbox.dataplane.xdp]       # leave disabled with mode = "cilium"
# enabled = false
# block_cidrs = ["198.51.100.0/24", "2001:db8:bad::/48"]
```

## Where FluxVM is ahead or different

- Three+ VMM backends and richer storage (LVM thin, NBD, Ceph RBD)
- virtiofs, macvtap, per-VM netns, image catalog Ed25519 signing
- Native TC/eBPF + safe Cilium coexistence without CNI lock-in
- Suite fit: GuestKit → FluxVM → h2kvm / Ragnarok
