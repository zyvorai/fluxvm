# Native virtio I/O performance

The native KVM engine now reuses bounded bounce buffers while servicing a
queue notification. These changes affect the in-tree virtio-blk and virtio-net
implementations, rather than the QEMU, Firecracker or Cloud Hypervisor backends.

## Changes

- Block requests share a grow-on-demand buffer for the notification batch,
  capped at 1 MiB. Large descriptors are copied in chunks instead of creating
  a descriptor-sized allocation. Small requests allocate only what they need.
- Block requests seek once and stream consecutive descriptors. Descriptor
  cycle detection uses a fixed stack array instead of a per-request HashSet.
- TX packets reuse one vector across the batch and copy descriptors directly
  into it, removing per-descriptor temporary vectors. Logical length is capped
  at 65,536 bytes plus the 12-byte virtio header; reserve_exact avoids geometric
  over-allocation beyond that bound.
- TX checks descriptor indices, cycles, direction, indirect flags, length and
  guest address ranges before buffer growth. Unsupported chains return errors.
- Block read errors now produce IOERR rather than silently returning success
  with synthesized zero data. Total block input/output length must fit the
  32-bit used-ring length including the status byte.

Buffers are released at the end of the notification, rather than retained for
idle disks or interfaces. The block path keeps a bounce copy so host I/O does
not hold a Rust reference directly into RAM being modified by running vCPUs.

## Host measurements

Baseline: commit `d5824f2b7d4acdb499acf5bc44057bc324462915`.
Linux 6.18.44, AMD EPYC 9V74, Rust 1.99.0, optimized rustc test binaries.
Five alternating baseline/patched runs; values below are medians.

| Host microbenchmark | Baseline | Patched | Change |
|---|---:|---:|---:|
| Fragmented TX, packets/s | 4,008,502 | 12,311,341 | 3.07x |
| Block read, MiB/s | 6,839.8 | 7,530.2 | +10.1% |
| Block benchmark peak RSS, KiB | 34,292 | 18,920 | -44.8% |

TX uses 10,000 notification batches of 64 zero-filled synthetic packets, each
split across four descriptors (12 + 500 + 500 + 500 bytes), without TAP I/O.
Block reads a sparse 16 MiB file 64 times after four warmup reads, without a
flush. The patched block benchmark reuses the buffer across iterations to
isolate copying/allocation effects; a real notification frees it after its
batch. The memory result includes guest RAM, the test runtime and scratch
memory; it is not a production VM density measurement. A 16 MiB descriptor
needs at most 1 MiB of block scratch instead of 16 MiB (93.75% less).

The shared host shows timing variance. These results measure host device code,
not guest network throughput, disk durability, p99 latency or total VMM RSS.
They do not establish an end-to-end performance multiplier.

## Validation and reproduction

- `cargo fmt -p fluxvm-hypervisor -- --check`: passed.
- `git diff --check`: passed.
- Isolated host-source harness: 23 tests passed, two benchmark tests ignored
  during the correctness run. It included the actual block/network modules,
  GuestMemory, FFI, TAP, rate limiter and C host helpers. Virtio state definitions
  were extracted from the source; tempfile fixtures and the minimal libc
  declarations were provided by the harness. This is narrower than a Cargo
  crate build and does not validate full workspace integration.
- Full `cargo test --locked -p fluxvm-hypervisor --lib`: blocked during dependency
  fetching. An offline retry confirmed `aho-corasick 1.1.5` was not cached.
- No `/dev/kvm` was available locally; guest boot, real block/network I/O and
  multi-vCPU checks remain for the repository CI/lab.

On a host with the repository's sibling GuestKit checkout and dependencies:

```sh
cargo test --locked -p fluxvm-hypervisor --lib
cargo test --release -p fluxvm-hypervisor --lib bench_block_bounce_buffer -- --ignored --nocapture
cargo test --release -p fluxvm-hypervisor --lib bench_network_tx_batch -- --ignored --nocapture
```

The added correctness cases check multi-chunk block read/write round trips,
fragment ordering, scratch capacity/reuse, truncated backing files, TX buffer
reuse and malformed descriptors rejected before allocation. When a PR is opened, the existing
native-kvm and workspace CI workflows cover these changed paths. Their
results must be checked before merging; keep the PR in draft until full build
and native guest checks succeed.

## Network datapath: vhost-net, userspace pump and multiqueue

The sections above are host microbenchmarks of the device code. This section
is about end-to-end guest networking on the in-tree KVM engine, and its numbers
must never be mixed with those: the microbenchmarks have no TAP, no guest and no
kernel networking stack, so they say nothing about guest throughput or host CPU.
Report the two kinds in separate tables.

### Datapaths

| Mode | Selected by | Who moves packets |
|---|---|---|
| `vhost` | default (`vhost_net` on) | kernel vhost-net, one queue pair |
| `userspace` | `FLUXVM_VHOST_NET=0` (or `--no-vhost-net`) | the queue-service thread reads and writes the TAP |
| `mq` | `FLUXVM_NET_QUEUE_PAIRS=N` or `--net-queue-pairs N`, with vhost-net | kernel vhost-net, N queue pairs, one multi_queue TAP queue per pair |

Multiqueue is off by default (one pair). With one pair the device model, feature
bits and queue layout are the same as before; the new bits
(`VIRTIO_NET_F_MQ`, `VIRTIO_NET_F_CTRL_VQ`, `max_virtqueue_pairs` and the control
queue) exist only when more than one pair is requested. Multiqueue needs vhost-net
and a TAP; if either is missing the VM is built with one pair. It also needs a TAP
that can be opened multi_queue (`ip tuntap add ... multi_queue`, or let the first
open create it), and the userspace pump serves only the first pair, so a guest that
asks for more pairs is refused (`VIRTIO_NET_ERR`) unless vhost-net owns all of them.

A vhost-net file descriptor serves exactly one RX/TX pair, so N pairs means N
`/dev/vhost-net` instances, each bound to its own TAP queue.

### Which datapath is live

Do not assume the requested mode is the active one. The hypervisor reports it:

- log line `[net] datapath <label> pairs=<n> (<reason>)` at boot, when the rings are
  bound, on a fallback and after a snapshot restore;
- the control API `Metrics` response field `net_datapath` (in-tree KVM guests only),
  with the same text;
- `scripts/test-kvm-net.sh` and `scripts/bench-kvm-vhost.sh` print it per run, and the
  benchmark JSON stores it per mode.

`<label>` is `vhost-net` only when the kernel datapath owns every queue pair;
otherwise it is `userspace-pump` and the reason says why (disabled by config or
`FLUXVM_VHOST_NET`, open or bind failure, waiting for the guest rings). A result
for mode `vhost` whose reported datapath is `userspace-pump` is a measurement of
the fallback and must not be published as a vhost result.

After a snapshot restore the restored rings are already live, so vhost-net is
re-bound immediately (and every queue kicked) instead of waiting for a guest notify.

### Method

Run on a lab host as root (`/dev/kvm`, netns, dnsmasq, the golden agent image):

```sh
FLUXVM_KVM_BENCH=1 sudo -E scripts/bench-kvm-vhost.sh
# MODES="vhost userspace mq" RUNS=3 VCPUS=4 DURATION=15 STREAMS=4 MQ_PAIRS=4 \
#   OUT=bench-kvm-vhost.json
```

Per mode and run it boots a fresh guest on a TAP in a throwaway namespace and
measures, with `STREAMS` parallel streams for `DURATION` seconds each:

- guest to host and host to guest TCP throughput;
- guest to host and host to guest UDP throughput and loss (needs iperf3 on both
  ends; without it TCP falls back to an HTTP transfer and UDP is skipped, which the
  JSON records);
- host CPU while each case runs: hypervisor process cores, `vhost-<pid>` kernel
  thread cores, whole-host busy percentage, from `/proc` deltas, plus raw
  `mpstat`/`pidstat` output beside the JSON when those tools are installed;
- throughput per datapath core (hypervisor plus vhost threads), the figure that
  shows CPU saved at equal throughput.

Output is one JSON document (`bench-kvm-vhost.json`, raw samples in
`bench-kvm-vhost.raw/`). Use medians over the runs, keep the host otherwise idle,
pin nothing differently between modes, and record host kernel, CPU model, vCPUs
and guest kernel next to the table. Guest-to-guest runs use two guests on the same
bridge and are not covered by this script yet.

### End-to-end results

No results have been recorded yet. Fill this table from `bench-kvm-vhost.json` on
the lab host; leave a cell empty rather than estimating it.

Host: `<cpu model, cores>`, kernel `<host kernel>`; guest: `<vcpus>` vCPU,
`<guest kernel>`; `<streams>` streams, `<duration>` s, `<runs>` runs, medians.

| Case | `userspace` | `vhost` | `mq` (`<N>` pairs) |
|---|---:|---:|---:|
| Reported datapath | `<from Metrics>` | `<from Metrics>` | `<from Metrics>` |
| TCP guest to host, Mbit/s | `<tbd>` | `<tbd>` | `<tbd>` |
| TCP host to guest, Mbit/s | `<tbd>` | `<tbd>` | `<tbd>` |
| UDP guest to host, Mbit/s / loss % | `<tbd>` | `<tbd>` | `<tbd>` |
| UDP host to guest, Mbit/s / loss % | `<tbd>` | `<tbd>` | `<tbd>` |
| Hypervisor cores (TCP g2h) | `<tbd>` | `<tbd>` | `<tbd>` |
| vhost thread cores (TCP g2h) | n/a | `<tbd>` | `<tbd>` |
| Mbit/s per datapath core (TCP g2h) | `<tbd>` | `<tbd>` | `<tbd>` |

Multiqueue stays opt-in until this table shows a win over the single-pair vhost
column on the workloads that matter.

### Host microbenchmarks

Keep these in the "Host measurements" table above. They compare device code only
and are not a substitute for the end-to-end table.

### vhost-net bring-up order

The kernel accepts the vhost-net setup in one order only. `VhostNet::program_vrings`
runs it, and a small `BindOrder` state machine refuses any out-of-order step
(a unit test checks that `SET_BACKEND` before the rings is rejected):

1. `VHOST_SET_OWNER`
2. `VHOST_SET_FEATURES` with `vhost_feature_mask(driver_features)`
3. `VHOST_SET_MEM_TABLE`: one region mapping guest RAM, GPA 0 to the host address
4. per queue: `VHOST_SET_VRING_NUM`, `_BASE`, `_ADDR`, `_KICK`, `_CALL`
5. start the IRQ relay (an epoll thread, `vhost-irq-relay`) over every call eventfd
6. `VHOST_NET_SET_BACKEND` per queue, attaching the TAP

Earlier code bound the backend before the rings were programmed (the kernel
answers `EFAULT`), never called `SET_FEATURES`, and never turned the call eventfd
into a guest interrupt, so the guest would not have seen used-ring updates. The
order above fixes all three. The relay must be running before the backend is
attached because vhost can complete a buffer the moment the backend is set.
`kernel_datapath()` is true only when the backend is bound, the rings are
programmed and the relay exists.

Feature mask (`vhost_feature_mask`): of what the guest driver negotiated, only
`VIRTIO_NET_F_MRG_RXBUF`, `VIRTIO_RING_F_INDIRECT_DESC`, `VIRTIO_RING_F_EVENT_IDX`
and `VIRTIO_F_VERSION_1` are passed on, plus `VHOST_NET_F_VIRTIO_NET_HDR` (the TAP
is opened without `IFF_VNET_HDR`, so vhost must handle the virtio-net header
itself). MAC, STATUS, MQ and CTRL_VQ are device-model bits that vhost-net
rejects, so they are masked out.

Toggles: `FLUXVM_VHOST_NET=0` (also `off`, `false`, `no`) forces the userspace pump
even when the config asks for vhost-net; the default config has vhost-net on and
`--no-vhost-net` also turns it off. `FLUXVM_NET_QUEUE_PAIRS=N` overrides
`--net-queue-pairs N` (the engine path has no flag, so the variable is what an A/B
run uses). The value is clamped to 1..=4 (`NET_MAX_QUEUE_PAIRS`); the command-line
flag is rejected outside that range.

### Not verified yet

Nothing in this section has been run against a guest. The bring-up order above is
type-checked and the feature mask, bind-order state machine and control-queue
command parsing have unit tests. Still needed on a lab host:

- Confirm `net_datapath` reports `vhost-net` (not `userspace-pump`) after boot, and
  that guest traffic actually flows with the IRQ relay (DHCP, ping, a TCP transfer).
  `scripts/test-kvm-net.sh` is the first check.
- Confirm the restore re-bind: after a snapshot restore the rings are live, so
  vhost-net is bound immediately and every queue kicked.
- Multiqueue: N `/dev/vhost-net` instances, one multi_queue TAP queue each, the
  control queue and `max_virtqueue_pairs` negotiation with a real guest driver.
- Every number in the end-to-end table above (all currently empty) and any claim
  that vhost-net or multiqueue is faster. The previous userspace pump has been
  verified live (see NEXT-FEATURES H3); the kernel datapath has not.
