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
| **Benchmarks** — `scripts/bench-sandbox.sh`, [docs/benchmarks/README.md](benchmarks/README.md) | Yes |

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
[ebpf-cilium.md](ebpf-cilium.md), and the
[packet-decision diagrams](network-fabric.md#packet-decision-and-control-plane-diagrams).

## Remaining (optional hardening)

- **Production-grade virtio device live-state** inside in-tree KVM snapshots (watermark only today; Firecracker remains production snap format)
- Hubble SID attribution for VM traffic beyond agent CEP enrichment
- Optional: scrape `MICROVM_METRICS_ADDR` (default `127.0.0.1:9108`) from Prometheus
- Ranked backlog (Sentinel Set 16 candidates, vhost bind, etc.): [NEXT-FEATURES.md](NEXT-FEATURES.md)
- SMP: 2+ vCPU boots with a full distro kernel cost a ~10s AP-wakeup stall (`do_boot_cpu failed`) before falling back to 1 CPU; not yet root-caused. Boot still completes.

**Resolved:** in-tree KVM late-boot hang (`init_zbud`) — fixed by matching Firecracker/CH TSS, boot MSRs, FPU, LAPIC lint, and serial irqfd/THRE semantics. Linux guests now mount `root=/dev/vda` (auto `virtio_mmio.device=` cmdline) through `/sbin/init`.

**Resolved:** the real control-plane boot path (`guest.rs`, what `fluxvm.service` uses for `fluxvm_engine = "kvm"`) had its vCPU execution silently freeze forever the instant the guest logged `Run /sbin/init` — a CLI demo/smoke-test convenience in `run_until()` was firing for production VMs too. Masked until now because the `init_zbud` hang meant no VM ever reached that point. **Verified end-to-end**: the real `fluxvm-guest-agent` (vsock ping/exec/shutdown) now actually starts inside the guest through the production boot path — `[ OK ] Started Zyvor FluxVM in-guest agent`. See [`crates/fluxvm-hypervisor/README.md`](../crates/fluxvm-hypervisor/README.md).

Shipped: concurrent density (`scripts/bench-density.sh`), Cilium-agent CEP
identity enrich (no private maps), in-tree KVM `FLUXKVM1` v2 memory snapshots
(all vCPUs), MicroVM schedule→Running histograms.

**Resolved:** the guest HTTP reverse proxy hung indefinitely for a
`tap`+`netns=true` sandbox. `guest_ip` there is only routable from inside
that VM's own network namespace — the daemon's default namespace has no
path to it, so the proxy's plain `reqwest::Client` (which always connects
from the calling thread's ambient namespace) silently hung until timeout.
vsock-based guest-agent calls (`exec`, fs read/write) were unaffected,
since vsock doesn't route through the guest's netns at all — a fully
working guest still looked completely unreachable over this one path. Fix:
a new `connect_in_netns()` `setns()`s a throwaway `std::thread` (never
`tokio::task::spawn_blocking`, whose pool reuses threads and would leak
the namespace change into unrelated work) before calling `connect()`, then
hands the connected socket back to the async runtime — a namespace only
governs which sockets a thread's *syscalls* create, not fds it already
holds. Since `reqwest` has no way to accept a pre-connected socket, the
proxy now speaks HTTP/1.1 directly over that stream via `hyper` instead.

**Resolved:** two more ways the same guest HTTP proxy could hang or return
a broken response, found immediately after the netns fix above while
auditing the same code path. First, every incoming header except `Host`
was forwarded verbatim to the guest — but `hyper`'s own body wrapper
computes and sets its own `Content-Length`, so forwarding the original
value duplicated the header; on any non-empty body, the resulting framing
conflict left the guest's HTTP server waiting on body bytes that were
never coming, hanging the request indefinitely instead of erroring
(`Transfer-Encoding` has the same problem for a chunked-transfer client) —
both are now stripped before forwarding, alongside `Host`. Second, the
connect and request-send steps were already timeout-bounded, but the
subsequent guest-response body read had no timeout at all — a guest that
accepted the request but never finished (or never sent) its response body
hung the whole proxy call forever; it now shares the same 30s
`tokio::time::timeout` pattern already used for connect/send. The proxy
also no longer forwards the guest response's `Connection`/`keep-alive`
headers onto the caller: those describe the handler's own short-lived,
one-shot connection to the guest (torn down right after this response
regardless of what it says), not the caller's connection to
`fluxvm-api`'s own server — forwarding them could make the caller's
connection pool try to reuse a connection axum's own server settings had
already closed, surfacing as a bare "connection closed before message
completed" with no indication why.

**Resolved:** a Firecracker guest kernel with no fast entropy source (no
RDRAND passthrough, no other virtio-rng) boots with `crng_init=0` —
anything that calls `getrandom()` before enough environmental noise
accumulates (in practice, the guest's own init/runtime startup) blocks
forever, indistinguishable from a hung process from the outside: alive, no
output, nothing listening. `firecracker_config()` now unconditionally
requests Firecracker's built-in entropy device on every boot, regardless
of what other boot options (tap, vsock) are set.

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
