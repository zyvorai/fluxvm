# FluxVM Set 6 — XDP Shield + TCP Intelligence

Set 6 adds a high-speed, VM-aware protection/observation layer without taking
ownership of Cilium, Fabric routing, or shared node network policy.

## XDP Shield ownership boundary

`fluxvm-shield` is **opt-in** and requires an explicitly selected interface.
The loader uses `XDP_FLAGS_UPDATE_IF_NOEXIST` and first queries native and
generic XDP ownership. It refuses to replace an existing program. That means a
Cilium-owned shared uplink is left untouched.

Use it on a dedicated VM ingress/uplink (for example a direct-attached veth,
macvlan/macvtap/SR-IOV representor under your control). On a shared Cilium
uplink, keep Set 6 XDP disabled and use FluxVM's VM-edge TC/TCX policy instead.

A policy example:

```json
{
  "mode": "enforce",
  "protected_ips": ["10.66.0.10", "2001:db8:66::10"],
  "allow_sources": ["10.0.0.0/8"],
  "deny_sources": ["198.51.100.0/24"],
  "syn_pps": 5000,
  "udp_pps": 20000,
  "icmp_pps": 2000,
  "other_pps": 50000,
  "burst_seconds": 2,
  "sample_rate": 1000,
  "xdp_mode": "auto"
}
```

`protect_all=true` is available only for a genuinely dedicated interface. The
userspace policy validator otherwise requires at least one protected IP.

Policy entries are keyed by a monotonically rotating generation. Userspace
populates the new generation first, then publishes the single config-map value
last. Old known policy entries are removed only after publication, so readers
never see a half-updated allow/deny generation.

Per-source SYN, UDP, ICMP and catch-all classes use token buckets. Their state
lives in a bounded regular HASH map because BPF spin locks are supported there.
If the source-state map is exhausted, enforce mode fails closed for protected
traffic and reports `bucket-exhausted`; audit mode reports the event but passes.

## TCP Intelligence

`fluxvm-tcpintel` attaches two passive `SCHED_CLS` programs to the same VM edge:

- ingress: guest -> remote;
- egress: remote -> guest.

TCX/BPF-link multiprogram attachment is preferred on Linux 6.6+. On older
kernels the helper falls back to a dedicated classic-TC handle/priority. The
observer always returns `TC_ACT_OK` and never makes policy decisions.

It records:

- guest- and remote-initiated SYNs;
- SYN retransmission signals;
- SYN -> opposite-direction SYN/ACK response latency;
- repeated payload sequence ranges in both directions;
- packet-observed data -> ACK RTT samples in both directions;
- FIN/RST counts;
- bounded LRU flow state and latency histograms;
- sampled JSONL ring-buffer events.

The RTT/retransmit values are deliberately exposed as **packet-level estimates**.
They are not claimed to be the guest kernel's TCP `srtt`, RTO, congestion-window
or authoritative retransmission counters. Sequence wrap, SACK and offload can
make a passive estimate differ from the guest stack's internal accounting.

## Commands

```bash
fluxvm-shield apply <vm-uuid> <iface> --policy shield.json
fluxvm-shield status <vm-uuid>
fluxvm-shield events <vm-uuid> 5 128
fluxvm-shield metrics <vm-uuid>
fluxvm-shield remove <vm-uuid>

fluxvm-tcpintel attach <vm-uuid> <iface> 100
fluxvm-tcpintel snapshot <vm-uuid> 128
fluxvm-tcpintel events <vm-uuid> 5 128
fluxvm-tcpintel metrics <vm-uuid>
fluxvm-tcpintel detach <vm-uuid>

fluxvm-netintel snapshot <vm-uuid>
fluxvm-netintel metrics
fluxvm-netintel serve 127.0.0.1:7792
```

The local API exposes:

- `GET /healthz`
- `GET /v1/netintel/vms/{uuid}`
- `GET /metrics`

No XDP or TCP observer is automatically attached by the service.
