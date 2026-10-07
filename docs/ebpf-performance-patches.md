# eBPF policy and telemetry performance patches

This series optimizes existing FluxVM-owned programs. It adds no new hook,
policy cache, map ABI, pinned-map schema or Cilium attachment. Existing TCX,
TC, XDP and AF_XDP ownership/coexistence behavior remains in place.

## Patch 2: rich-policy evaluation

Reject protocol and port mismatches before the 16-byte prefix-copy/comparison.
Wildcard protocol continues to ignore port fields. Consume the candidate
bitmap in slot order and stop once it is empty, preserving original rule
indices for hit attribution. Avoid looking up the wildcard bucket twice when
the packet protocol itself is zero. The authoritative rule slot is still
checked; a candidate bit never grants permission by itself.

Host tests execute the production header with mocked BPF map helpers and an
independent bit-by-bit reference matcher. They cover 125,952 matching cases
across IPv4/IPv6 prefixes, invalid prefixes, wildcard/exact protocols, port
boundaries and inverted ranges, plus 20,000 candidate scans covering bit 63,
empty masks, count clamping, audit/default deny, attribution, counters and
legacy/disabled/unisolated behavior. Host mocks do not test concurrent map
updates or the BPF verifier.

```sh
scripts/test-ebpf-performance-host.sh
SANITIZE=1 scripts/test-ebpf-performance-host.sh
```

The Network Fabric workflow runs these host tests before building BPF ELFs.
On restricted hosts where LeakSanitizer cannot inspect /proc tasks, run the
sanitizer check with `ASAN_OPTIONS=detect_leaks=0`; address and undefined-
behavior instrumentation remains active.

Full kernel validation still requires root, bpffs, bpftool and supported
kernel features. Run the repository's existing gates on the lab host:

```sh
scripts/build-ebpf.sh
sudo scripts/test-pod-policy-verdict.py
sudo scripts/test-vm-edge-verdict.py
sudo scripts/test-verifier-budget.sh
sudo scripts/test-direct-datapath.sh
sudo scripts/test-direct-uplink.sh
```

Compare guest throughput, CPU per Gbit/s, p99 latency and BPF map memory before
and after on identical hosts. Host behavior tests establish verdict semantics;
they do not establish a production throughput gain.
