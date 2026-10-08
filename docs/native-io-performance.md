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
