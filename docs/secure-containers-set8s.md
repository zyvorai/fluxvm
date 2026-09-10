# FluxVM Secure Containers — Set 8 (Sentinel): in-guest per-container network policy

Set 8 (Sentinel track) is the first genuinely novel piece of the roadmap —
not something Kata attempts. Through Set 7, nothing stopped one container in
a multi-container Pod from reaching another container's local ports: the
only network enforcement was Set 6S's Pod-wide policy at the VM edge, which
by definition can't see traffic that never leaves the guest. Set 8S closes
that gap with per-container `cgroup_skb` programs enforced *inside* the
guest kernel.

## The build/tooling exception: `aya`

The project-wide rule (`crates/fluxvm-network/src/ebpf.rs`: "bpftool+tc, not
aya/libbpf") is scoped to avoid linking libbpf into the shared host
dependency graph. `fluxvm-container-agent` is the opposite case: a single,
purpose-built binary the shim uploads fresh into the guest on every boot
(`docs/secure-containers.md`), not part of that shared graph — and the
minimal guest image cannot be relied on to have `bpftool`/`iproute2`/kernel
headers installed the way the host always does. This crate is a deliberate,
narrowly-scoped exception: it depends on `aya` (a pure-Rust eBPF loader) to
attach `bpf/fluxvm_guest_cgroup.bpf.c` — compiled with the *exact same*
clang/BTF-map conventions as every other `bpf/*.bpf.c` object in this repo,
not written in Rust against `aya-ebpf`.

That combination (C-compiled object, Rust-based loader) is not `aya`'s
primary documented workflow, and an old GitHub issue suggested clang objects
might not load cleanly. **Verified empirically rather than trusted from
that issue's age**: a minimal clang-compiled, BTF-defined-map `cgroup_skb`
object was loaded, submitted to the real kernel verifier, attached to a
live cgroup, and round-tripped through a map — all successfully — using
`aya` 0.13.1 on a real Linux 6.8 host. The full Set 8S integration was then
built and tested the same way, not assumed to work by analogy.

## What was built

- **`bpf/fluxvm_guest_cgroup.bpf.c`**: two programs, `cgroup_skb/egress` and
  `cgroup_skb/ingress`, both keyed by `bpf_get_current_cgroup_id()` (the
  attached cgroup's inode number). Maps: `fluxvm_cpol` (per-container policy
  flags), `fluxvm_cid4`/`fluxvm_cid6` (peer allow/deny, mirroring Set 6S's
  `fluxvm_pid4`/`fluxvm_pid6` shape), `fluxvm_cdrops` (per-container drop
  counters).
- **Fail-closed by default — the opposite of Set 6S's "unconfigured = allow"
  default.** Set 6S's default exists for backward compatibility with the
  large existing population of VMs that never opt into Pod-scoped policy at
  all. There's no equivalent concern here: a container's cgroup only ever
  gets these programs attached because Set 8S is in use for it, so an
  unconfigured `fluxvm_cpol` entry denies non-loopback traffic rather than
  allowing it.
- **One shared loaded instance per Pod VM.** `fluxvm-container-agent` loads
  `fluxvm_guest_cgroup.bpf.o` (compiled at `cargo build` time by
  `crates/fluxvm-container-agent/build.rs` via `scripts/build-ebpf-guest.sh`
  and embedded with `include_bytes!`, so the uploaded binary stays a single
  self-contained file) once, on the first container's creation, then
  `attach()`s the same already-loaded programs again for every later
  container's own cgroup — safe because the maps are keyed by cgroup id.
- **Attach point**: `create_container_cgroup` in `fluxvm-container-agent`,
  right before the process is spawned, so policy is live from the
  container's first packet. Best-effort like the resource-limit cgroup
  itself: a guest kernel missing `cgroup_skb`/BTF support still runs the
  container, just without this layer (a platform-capability gap, not the
  fail-closed-policy-content design, which only governs what an *attached*
  program does when unconfigured).
- **`ContainerNetworkPolicy`** (`fluxvm-container-protocol`): a new,
  optional field on `ContainerRequest::Create` — `default_allow`,
  `audit_mode`, `allow_addresses`, `deny_addresses`. Cleaned up on container
  delete (`forget_container_policy`) so the shared maps don't grow
  unboundedly across a long-lived Pod VM's container churn.

## Deliberately out of scope for this Set

**The shim does not yet fetch a Pod's Set 6S policy and forward it per
container.** Every container today gets Set 8S's fail-closed-by-default
enforcement attached unconditionally, but with an empty policy
(`network_policy: None` from the shim) until that wiring lands — matching
Set 6S's own precedent of shipping the mechanism ahead of its primary
population source. The natural next step, once a Kubernetes `NetworkPolicy`
watcher exists (Set 6S's own open item) or as a standalone piece before
that: the shim queries `GET /v1/vms/{id}/network/pod-policy` and passes the
result into each container's `Create` call.

## Validation performed

- **Compatibility probe** (see above): a standalone clang-compiled
  `cgroup_skb` object, loaded/attached/map-tested via a minimal `aya`
  program on a real Linux 6.8 host.
- **Kernel verifier**: both real programs (`fluxvm_guest_egress`,
  `fluxvm_guest_ingress`) pass `bpftool prog load` independently of the aya
  path, confirming the C code itself is correct regardless of loader.
- **Full Rust integration, end-to-end, not mocked**: a new
  `#[test] guest_cgroup_policy_attaches_and_enforces` in
  `fluxvm-container-agent` (root-only, self-skips otherwise) creates a real
  throwaway cgroup, calls the actual `attach_guest_network_policy`/
  `configure_container_policy`/`forget_container_policy` functions, moves
  the test process into the cgroup, and proves real enforcement: a
  non-loopback connect is blocked under a default-deny policy, a loopback
  connect (through the same process's own egress *and* ingress, both in the
  policed cgroup) succeeds, and cleanup leaves no stale map entries. Run
  with `sudo` on a real Linux host to exercise it.
- `cargo build`/`cargo test` and a full workspace build pass for every
  touched crate on a real host.
- `.github/workflows/secure-containers.yml` now installs `clang` (previously
  not needed there) since `fluxvm-container-agent`'s `build.rs` compiles a
  BPF object at `cargo build` time.
- **Not yet run**: a live multi-container Pod e2e test proving container B
  is denied from reaching container A's port by policy — the mechanism this
  would exercise is the same one the root-only unit test above already
  validates directly; the multi-container Pod scenario additionally needs a
  live Kubernetes cluster with the `fluxvm` RuntimeClass installed, which
  wasn't set up against the already-running FluxVM host used for other
  Set 6/7/8 validation.

## Remaining gates

- Wire the shim to fetch and forward a Pod's Set 6S policy per container
  (see "Deliberately out of scope" above).
- A live multi-container Pod e2e test (see "Not yet run" above).
- `CLONE_NEWUSER`/full namespace isolation (Set 6R) and this Set's cgroup
  scoping are complementary, not sequenced — Set 6R's own doc already notes
  where a future per-container LSM identity model would hook in; this Set's
  cgroup-id-keyed scoping needs no changes when that lands.
