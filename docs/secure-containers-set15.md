# Secure Containers Set 15 — Sentinel Policy Observability & Directional Health

## Purpose

Set 13 completion originally introduced real Pod ingress policy alongside the
existing Pod egress dataplane; Secure Containers Set 14 later replaced that
design with a unified directional CIDR+L4 rule model. Set 15 hardens
operations around that bidirectional policy instead of rewriting the wire
format again, and this reconciliation updates it to match Set 14's actual
map/attachment layout rather than Set 13 completion's.

The two goals are:

1. never report a VM dataplane healthy when the Pod-ingress program is present
   but its TC hook is missing; and
2. expose the kernel's existing Pod-policy counters, flags, and compiled
   rule-map pressure through a small read-only Prometheus exporter.

Reviewed upstream base: `7c7f19d1c772f4ea99066f99069d2738129d8230`
(Secure Containers Set 14, commit `e65fadb`, merged after this Set's original
review; see "Reconciled for Set 14" below).

## Core health fix

`crates/fluxvm-network/src/ebpf.rs::attachment_status()` previously validated
only the long-standing guest-egress program. Schema v8 also loads
`fluxvm_pod_ingress`, but losing that host-side egress hook could still leave
`NativeAttachmentStatus.attached=true`.

Set 15 adds:

- `pod_ingress_required` to `NativeAttachmentStatus`;
- `pod_ingress_attached` to `NativeAttachmentStatus`;
- exact program-ID validation for the Pod-ingress program's host-side
  `tc egress` filter at its reserved pref/handle (49153/2) -- Set 14 attaches
  this separate object only via plain `tc`, never TCX, so unlike the main
  guest-egress program's own attachment check, this one does not branch on
  `attach_mode`; and
- aggregate health where `attached` is true only when the normal egress hook
  and every required Pod-ingress hook are both live.

Because the existing FluxVM ensure/reconcile path already repairs a VM when
`attachment_status.attached` is false, this turns a missing ingress hook into a
normal repair condition without adding a second lifecycle owner.

Older BPF objects remain compatible: if `progs/fluxvm_pod_ingress` is absent,
`pod_ingress_required=false` and the legacy one-direction attachment is judged
by its previous rules.

## Reconciled for Set 14

Set 15 was originally reviewed against the Secure Containers Set 13
completion architecture (`fluxvm_pod_ingress` embedded in `fluxvm_tc.bpf.o`,
attached via TCX-egress or a shared-pref legacy `tc` filter). Secure
Containers Set 14 replaced that architecture with a unified rule model and a
separate `fluxvm_pod_ingress.bpf.o` object, attached only via plain `tc` at
its own reserved pref/handle (49153/2), sharing the main program's pinned
maps (including `fluxvm_ppstat`/`fluxvm_pspol` -- there is no `_in`-suffixed
counterpart of either under Set 14). This reconciliation updates
`attachment_status()`'s Pod-ingress check and the policy observer's map
reads/rule-pressure counting to match that reality, and is reflected in the
"Sentinel Policy Observer" section below and in the code itself, not just
here.

## Sentinel Policy Observer

New tool: `tools/fluxvm-policy-observer`.

It is deliberately read-only. It does not call `bpftool map update`, does not
add/delete TC filters, and does not write the FluxVM API.

The observer scans:

- `/sys/fs/bpf/fluxvm/vms/<vm>/progs/*`;
- `/sys/fs/bpf/fluxvm/vms/<vm>/links/*`;
- `/sys/fs/bpf/fluxvm/vms/<vm>/maps/fluxvm_ppstat` and `fluxvm_pspol` (Set 14's
  separate Pod-ingress object shares these pinned instances with the main
  program rather than owning independent copies, so there is one counter and
  one flags record per VM covering both directions, not one per direction);
- the shared exact-address/exact-port maps, and the unified `fluxvm_prules`
  rich-rule map (which does carry a real per-entry direction, unlike the
  maps above);
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
`fluxvm_ppstat` map and aggregates the 24-byte `allowed/dropped/audited`
value across CPUs. Because Set 14's Pod-ingress program shares this same
pinned map with the main program, the exact same aggregate value is reported
under both `direction="egress"` and `direction="ingress"` -- that is a
faithful reflection of the underlying counter, not a bug: FluxVM does not
currently record allow/drop/audit counts separately per direction.

### Rule pressure

The four legacy exact-address/exact-port maps are counted for the observed
Pod identity only (`pod_id` at key offset zero) and reported once as
`shared_*`, since Set 14 shares them between directions -- they have no
independent per-direction split to report. The unified `fluxvm_prules` map
is scanned separately and its entries genuinely are counted per direction
(`egress_rules`/`ingress_rules`), since each entry's own `direction` field
makes that possible.

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

The Set 14 reconciliation additionally closed the live-node gate this section
used to describe as open: a real dual-object VM was built by hand on the
validation host (`fluxvm_tc.bpf.o`'s single program attached via plain `tc`
at pref 49152/handle 1, plus the separate `fluxvm_pod_ingress.bpf.o` loaded
with shared pinned maps and attached at pref 49153/handle 2), and the real
`fluxvm-policy-observer` binary was run against it with `--once`. Both
directions correctly reported `hook_required=1`/`hook_attached=1`; removing
the ingress `tc` filter and re-running correctly flipped only
`fluxvm_sentinel_policy_hook_attached{direction="ingress"}` to `0` while
leaving egress and `hook_required` untouched -- proving the observer
distinguishes "program present" from "program actually attached" against
the real kernel, not just its own mocked unit tests. A live Kubernetes
Secure Containers cluster and `/dev/kvm` remain out of scope for this pass.

## Remaining follow-ups after Set 15

1. prove live stateful conntrack bypass under a real TCP handshake (Set 14
   follow-up still open);
2. true per-direction `fluxvm_ppstat` (or equivalent) + rule-hit identity —
   today one shared counter covers both directions;
3. production sizing gate: realistic VM/rule counts for observer scrape cost;
4. scrape Policy Observer from cluster Prometheus alongside FluxVM metrics;
5. multi-node NetworkPolicy conformance (Cilium + ≥1 non-Cilium CNI).

See [NEXT-FEATURES.md](NEXT-FEATURES.md).
