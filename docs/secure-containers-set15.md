# Secure Containers Set 15 — Sentinel Policy Observability & Directional Health

## Purpose

Set 13 completion on FluxVM main introduced real Pod ingress policy alongside the
existing Pod egress dataplane. Set 15 hardens operations around that bidirectional
policy instead of rewriting the wire format again.

The two goals are:

1. never report a VM dataplane healthy when the Pod-ingress program is present
   but its TC/TCX hook is missing; and
2. expose the kernel's existing per-direction Pod-policy counters and compiled
   map pressure through a small read-only Prometheus exporter.

Reviewed upstream base: `7c7f19d1c772f4ea99066f99069d2738129d8230`.

## Core health fix

`crates/fluxvm-network/src/ebpf.rs::attachment_status()` previously validated
only the long-standing guest-egress program. Schema v8 also loads
`fluxvm_pod_ingress`, but losing that host-side egress hook could still leave
`NativeAttachmentStatus.attached=true`.

Set 15 adds:

- `pod_ingress_required` to `NativeAttachmentStatus`;
- `pod_ingress_attached` to `NativeAttachmentStatus`;
- exact program-ID validation for `links/tcx_pod_ingress` in TCX mode;
- exact program-ID validation for the host-side `tc egress` filter in legacy
  clsact mode; and
- aggregate health where `attached` is true only when the normal egress hook
  and every required Pod-ingress hook are both live.

Because the existing FluxVM ensure/reconcile path already repairs a VM when
`attachment_status.attached` is false, this turns a missing ingress hook into a
normal repair condition without adding a second lifecycle owner.

Older BPF objects remain compatible: if `progs/fluxvm_pod_ingress` is absent,
`pod_ingress_required=false` and the legacy one-direction attachment is judged
by its previous rules.

## Sentinel Policy Observer

New tool: `tools/fluxvm-policy-observer`.

It is deliberately read-only. It does not call `bpftool map update`, does not
add/delete TC filters, and does not write the FluxVM API.

The observer scans:

- `/sys/fs/bpf/fluxvm/vms/<vm>/progs/*`;
- `/sys/fs/bpf/fluxvm/vms/<vm>/links/*`;
- `/sys/fs/bpf/fluxvm/vms/<vm>/maps/fluxvm_ppstat{,_in}`;
- the Pod policy state maps `fluxvm_pspol{,_in}`;
- the exact-address, exact-port, CIDR and port-range maps for both directions;
- `/run/fluxvm/ebpf/vms/<vm>/` runtime metadata.

It recognizes dataplane schema v8 and exports Prometheus text on `:9091`.

### Primary metrics

- `fluxvm_sentinel_policy_packets_total{vm,pod_id,direction,verdict}`
- `fluxvm_sentinel_policy_hook_required{vm,pod_id,direction,mode}`
- `fluxvm_sentinel_policy_hook_attached{...}`
- `fluxvm_sentinel_policy_enabled{...}`
- `fluxvm_sentinel_policy_default_deny{...}`
- `fluxvm_sentinel_policy_audit_mode{...}`
- `fluxvm_sentinel_policy_rule_entries{vm,pod_id,direction,kind}`
- `fluxvm_sentinel_dataplane_schema_version{vm,pod_id}`
- `fluxvm_sentinel_dataplane_schema_compatible{vm,pod_id}`

Labels intentionally stop at VM UUID, numeric Pod identity, direction, verdict,
mode and bounded rule-kind values. Kubernetes Pod names/namespaces are not
queried, so no Kubernetes API token is required and Pod churn does not create an
additional high-cardinality label dimension.

### Counter source

The exporter does not invent counters. It reads the existing per-CPU
`fluxvm_ppstat` and `fluxvm_ppstat_in` maps and aggregates the 24-byte
`allowed/dropped/audited` value across CPUs.

### Rule pressure

Compiled entries are counted for the observed Pod identity only. CIDR LPM maps
use the schema-v8 key offset (`prefixlen` then `pod_id`); other Pod maps use
`pod_id` at offset zero. This keeps the metric correct if the implementation
later allows more than one Pod identity in a VM-owned map instance.

## Deployment

The supplied DaemonSet runs in the host network namespace and mounts only the
FluxVM bpffs and runtime metadata paths read-only. `bpftool` and `tc` are inside
the image. Linux BPF/TC inspection still requires kernel capabilities; the
manifest requests `BPF`, `PERFMON`, `NET_ADMIN` and `SYS_RESOURCE` rather than
making the container privileged.

Older kernels/runtime policies may require a different capability profile; that
is a deployment gate, not a reason for the observer to mutate host state.

## Performance

Set 15 includes Go microbenchmarks. During packaging, the Prometheus rendering
path was optimized after the first benchmark exposed avoidable allocation
pressure. The final benchmark result is recorded in `BENCHMARK_RESULTS.txt` and
`TEST_REPORT.md`.

The dominant real-node cost is expected to be `bpftool` process execution and
map dumping, not string rendering. A production node benchmark with realistic
VM/rule counts remains a required sizing gate.

## Validation boundaries

Portable validation covers Go tests, race detector, vet, gofmt, static
amd64/arm64 builds, shell/Python/YAML parsing and benchmark execution.

This packaging environment does not provide a live bpffs populated by FluxVM,
a host TCX link, `/dev/kvm`, or a Kubernetes Secure Containers cluster. Therefore
live counter movement, TC/TCX repair and end-to-end Prometheus scraping remain
explicit node/cluster gates.
