# FluxVM Sentinel Set 12E — GA Hardening & Performance Certification

Set 12E turns the existing Sentinel feature stack into a release process. It
adds no packet-processing feature and does not automatically mutate a running
VM. Its job is to make compatibility, recovery, upgrade safety and performance
claims reproducible.

## What it certifies

Three versioned profiles live in `benchmarks/sentinel-ga-budgets.json`:

- **baseline** — minimum supported host contract: cgroup v2, bpffs and kernel BTF;
- **performance** — adds TCX and XDP as required datapath capabilities;
- **strict** — additionally requires BPF LSM and sched_ext.

AF_XDP remains optional because zero-copy depends on the NIC/driver/queue
combination and should not be used as a blanket host-support requirement.

The default budgets cover boot p95, runnable p99, block-I/O p99, network RTT
p99, packet loss, throughput, migration downtime and Sentinel ring-buffer loss.
They are release policy, not universal physics: tune them only by code review and
keep machine class / kernel / NIC / storage metadata alongside every result.

## Evidence first

Collect host evidence before running destructive tests:

```bash
scripts/sentinel-ga-evidence.sh /var/tmp/fluxvm-ga-evidence
python3 tools/fluxvm-sentinel-certify.py probe
```

The evidence directory includes kernel/CPU/mount/network/BPF inventory when the
corresponding commands are available plus `SHA256SUMS`. It does not scrape VM
disk contents, credentials or arbitrary process environments.

## Release gate

Merge measurement files from the dedicated workload harnesses and evaluate them:

```bash
scripts/sentinel-ga-merge-measurements.py /tmp/all.json \
  /tmp/network.json /tmp/storage.json /tmp/vm.json

python3 tools/fluxvm-sentinel-certify.py gate \
  --profile performance \
  --budgets benchmarks/sentinel-ga-budgets.json \
  --measurements /tmp/all.json \
  --require-all-metrics \
  --json-out /tmp/certification.json \
  --markdown-out /tmp/certification.md
```

A release pipeline should use `--require-all-metrics`; partial developer runs
may omit it and will report absent measurements as `missing` without pretending
they were measured.

## Stale bpffs recovery

Ownership manifests never live inside the bpffs tree they describe: a real
bpffs directory has no `create()` for plain files at all (confirmed against a
real kernel — only `mkdir` and BPF-object pins via `bpf_obj_pin` succeed; a
plain `open(O_CREAT)`/`write()` fails `EPERM`). Instead, `write-owner-manifest`
writes `.fluxvm-owner.json` into a separate, normal-filesystem tree
(`--manifest-root`, defaulting to `/run/fluxvm/sentinel-owners`) that mirrors
the bpffs target tree's structure — matching the same constraint FluxVM's own
Rust dataplane code already works around (`vm_meta_dir()` in
`crates/fluxvm-network/src/ebpf.rs` keeps interface/schema sidecar files on the
normal runtime filesystem for exactly this reason).

The reconciler is deliberately ownership-conservative. It removes a bpffs
directory only when all of these are true:

1. a manifest exists at the mirrored path under `--manifest-root`;
2. the manifest has `owner_magic=zyvor-fluxvm-sentinel-state-v1`;
3. the owner PID is no longer alive;
4. the manifest age exceeds the configured grace period.

The corresponding bpffs directory (under `--root`) is removed along with the
manifest itself; a manifest whose target directory is already gone is treated
as a no-op removal, not an error. Unknown/foreign state (wrong or missing
`owner_magic`) is skipped. The command is dry-run by default:

```bash
python3 tools/fluxvm-sentinel-certify.py reconcile --root /sys/fs/bpf/fluxvm
```

Mutation requires `--apply`. The optional systemd timer uses a 15-minute cycle
and a 15-minute minimum stale age.

## Failure injection

`scripts/sentinel-ga-failure-injection.sh` is **double gated**. It requires both:

- `FLUXVM_SENTINEL_FAILURE_INJECTION=1`; and
- a lab marker (default `/etc/fluxvm/sentinel-lab-host`).

It currently validates map-capacity failure behavior and owned-vs-foreign stale
state cleanup in a temporary bpffs subtree. CI runs it only on an explicitly
labeled self-hosted lab runner.

## Performance harnesses

`sentinel-ga-benchmark-network.sh` uses iperf3 + ping and emits throughput,
packet-loss and RTT JSON. `sentinel-ga-benchmark-storage.sh` uses fio and emits
4K mixed random-I/O p99 completion latency. VM boot, scheduler and migration
measurements should be emitted by the VM lifecycle test harness using the same
measurement schema so that the evaluator remains independent from how the
workload is generated.

## GA rule

A host may be called **Sentinel certified** only when:

- the selected capability profile passes;
- every required benchmark is present and inside budget;
- non-destructive recovery tests pass;
- the release's supported-kernel matrix has a real verifier/load test;
- any feature-specific privileged gate enabled for that profile passes;
- upgrade and rollback have been exercised from the previous released build;
- the evidence bundle and exact FluxVM commit SHA are retained with the result.
