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
empty/missing index buckets, count clamping, audit/default deny, attribution, counters and
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

## Patch 3: flow telemetry helpers

Flow aggregation and an emitted event now share one monotonic timestamp per
packet rather than calling bpf_ktime_get_ns twice. Full-observation mode
(sample_rate=1) always emits allowed-flow events without PRNG/modulo helpers.
Sample rate zero still suppresses allowed-flow events; drops always attempt
an event, and rates above one keep their original random modulo sampling.
Packet/byte accounting remains unsampled. Map allocation failures and ring
buffer exhaustion preserve their existing behavior. Timestamps now represent
one packet-observation instant rather than two separate helper instants.

The production function lives in a shared header so host tests execute the
same body included by the TC program. Tests extract flow ABI structs from the
TC source and exercise 672 combinations of address family, verdict, sample
rate, PRNG value, existing/new flow, failed map insert and ring-buffer failure.
They verify counters, tuple fields, event payload, single clock-helper call
and no PRNG call at rate one. The existing flow-map ABI is unchanged.

## Local validation for the complete series

- Host behavior tests: all 146,624 cases passed with GCC -O2 -Wall -Wextra
  -Werror, and again with AddressSanitizer/UndefinedBehaviorSanitizer
  (LeakSanitizer disabled because this container cannot inspect /proc tasks).
- Full scripts/build-ebpf.sh: all 19 TC, direct, ingress, XDP, intelligence,
  QEMU and service tier objects compiled with Clang 18.1.3, -target bpf -O2 -g
  -Wall -Werror. Build outputs were kept outside the source tree.
- Shell syntax, workflow YAML parsing and git diff whitespace checks passed.
- Kernel object-load attempt failed creating the fluxvm_v4 LPM map with
  Operation not permitted. No programs were attached. Verifier, kernel
  BPF_PROG_TEST_RUN, live TCX/Cilium coexistence and guest throughput tests
  therefore remain pending on the privileged lab/CI host.

This series is ready for review as a draft; successful ELF compilation is not
proof that the kernel verifier accepts all paths. No eBPF throughput or VM
memory-density percentage is claimed from these host behavior checks.
