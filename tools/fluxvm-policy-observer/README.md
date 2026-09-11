# FluxVM Sentinel Policy Observer

Node-local Prometheus exporter for Secure Containers NetworkPolicy enforcement.
It does not modify policy or kernel maps. It reads FluxVM-owned bpffs pins and
runtime metadata, verifies the directional TC hooks, and exports the
existing Pod-policy counters (Set 14 shares one `fluxvm_ppstat` for both
directions) plus hook/rule-pressure gauges.

## Metrics

- `fluxvm_sentinel_policy_packets_total{vm,pod_id,direction,verdict}`
- `fluxvm_sentinel_policy_hook_required{...}`
- `fluxvm_sentinel_policy_hook_attached{...}`
- `fluxvm_sentinel_policy_enabled{...}`
- `fluxvm_sentinel_policy_default_deny{...}`
- `fluxvm_sentinel_policy_audit_mode{...}`
- `fluxvm_sentinel_policy_rule_entries{vm,pod_id,direction,kind}`
- `fluxvm_sentinel_dataplane_schema_version{...}`
- observer scrape/error/readiness metrics

The exporter deliberately uses VM UUID + numeric Pod identity instead of Pod
name/namespace labels. It needs no Kubernetes API credentials, and avoids
unbounded label churn when Pods are recreated.

## Run on a FluxVM node

```bash
go run ./cmd/fluxvm-policy-observer \
  --pin-root /sys/fs/bpf/fluxvm \
  --meta-root /run/fluxvm/ebpf/vms \
  --listen :9091
```

Requirements: read access to FluxVM bpffs pins; `bpftool`; and `tc` plus the
host network namespace when legacy TC attachment health must be checked. TCX
health is read from pinned BPF links with `bpftool`.

Health endpoints:

- `/healthz` — process is alive
- `/readyz` — a recent collection cycle exists
- `/metrics` — Prometheus text exposition

## Security

The observer never performs `bpftool map update`, `tc filter add/del`, or any
FluxVM API write. The supplied DaemonSet mounts only the FluxVM bpffs and meta
paths read-only. Linux capabilities are still needed on many kernels to inspect
BPF objects and host TC state; tune the supplied capability set for your kernel
and runtime policy.
