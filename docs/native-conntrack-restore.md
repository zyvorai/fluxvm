# Native conntrack restore

## Problem and change

The previous restore loop spawned bpftool once per conntrack entry. A 10,000
entry restore therefore created 10,000 helper processes. This patch opens the
existing pinned map once using BPF_OBJ_GET, reads its stable metadata prefix
with BPF_OBJ_GET_INFO_BY_FD, then writes entries using BPF_MAP_UPDATE_ELEM.
No new Rust dependency, BPF program, map layout, or dataplane schema is added.

Only ordinary HASH and LRU_HASH maps are accepted. Kernel metadata validates
the key/value lengths before pointers are passed to the kernel. Conntrack must
have the existing 44-byte key and 8-byte value ABI. Snapshots must fit both the
32,768 entry contract and the actual map capacity. The whole snapshot is
validated before any map writes or persistence of a deferred restore. State
metadata is limited to 64 bytes. File descriptors close on all exit paths.

Restores keep the existing per-entry BPF_ANY behavior and monotonic timestamps.
They are not transactional: a kernel failure after some updates can leave a
partial restore, as before; the returned error reports completed entry count.
The daemon itself needs the kernel BPF permissions used by its dataplane; no
fallback launches a privileged helper to bypass an authorization failure.

## Validation

Rust 1.99.0, Linux amd64:

* 185 network-crate unit tests passed; one privileged syscall test was ignored.
* 30 integration tests passed (215 passing tests in total).
* cargo check for the library and tests passed.
* Formatting and diff checks passed.

These runs used an isolated workspace containing unchanged copies of the real
fluxvm-network, fluxvm-core, and fluxvm-cgroup sources, plus the tested patch.
Every resolved dependency version matches the repository Cargo.lock. The full
FluxVM workspace requires a sibling guestkit checkout absent in this environment;
its complete daemon build was not validated. Clippy was unavailable. Existing
unused-import/dead-code warnings remain outside this patch's scope.

The environment lacks CAP_BPF and CAP_SYS_ADMIN, so the actual kernel syscall
round-trip was not run. ABI layout, input lengths, capacity limits, malformed
late entries, and deferred-restore rejection are tested without kernel access.
No measured conntrack-restore throughput or downtime improvement is claimed.

On a checkout with the sibling GuestKit dependency available:

```sh
cargo test -p fluxvm-network --locked
cargo check -p fluxvm-network --lib --tests --locked
# On a host that permits BPF_MAP_CREATE:
cargo test -p fluxvm-network --lib --locked bpf_map::linux::tests::kernel_hash_map_roundtrip -- --ignored --exact
```

For production validation, run a live VM migration with 100, 1,000, and 10,000
TCP/UDP/SCTP entries. Compare restore wall time and process creation counts,
check established connections survive, test malformed snapshots and incompatible
maps, and measure host CPU plus userspace and BPF-map memory. A lost BPF
permission or incompatible map must surface as an error before successful
migration is reported.
