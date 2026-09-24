# Changelog

## 0.4.0 (unreleased)

### Added
- **Host admission, confinement, and QEMU migration receivers.** O(1) host quota ledger
  (including untracked migration receivers), `policy.require_catalog_names`, symlink-aware
  `allowed_image_dirs` / hostPath broker, optional `FLUXVM_VMM_SECCOMP` for QEMU/Cloud Hypervisor,
  AppArmor/SELinux packaging under `deploy/`, and `POST /v1/migration/receivers` for QEMU
  `-incoming defer`. `kubectl-fluxvm` covers console/exec/pause/resume/delete with SSH node
  hostname validation. Evidence: `scripts/record-baseline.sh`, `scripts/test-migration-receiver.sh`.
- **Phase 6 security profiles.** `CreateVmRequest.security_profile` (`standard` /
  `measured` / `confidential-snp` / `confidential-tdx`) with distinct requested vs
  achieved evidence, host capability discovery, fleet admission that still gates
  an explicit `node`, QEMU SNP/TDX providers, and measured software-test secret
  release. Hardware-free CI: `./scripts/test-security-profiles.sh` /
  [`.github/workflows/security-profiles.yml`](.github/workflows/security-profiles.yml).
  Docs: [docs/security-profiles.md](docs/security-profiles.md),
  [docs/guides/security-profiles-howto.md](docs/guides/security-profiles-howto.md).
  Measured never claims host-memory protection; `*_launch_verified` stays false
  until a real hardware run.
- **Firecracker sandbox templates.** Operator-authored templates with
  `"backend": "firecracker"` are no longer coerced to the in-tree FluxVm backend
  (volumes remain QEMU-only; Firecracker cells cannot use virtiofs).
- **Persistent sandbox volumes.** `POST /v1/sandboxes` accepts `volumes: [{name, guest_path, read_only?}]`.
  Each volume is a host directory under `sandbox.volumes_dir` (default `<state_dir>/volumes`), scoped per
  tenant, shared into the guest over virtiofs and mounted through an fstab line, so it survives sandbox
  replacement. A volume can be attached to one VM at a time. Volumes need a QEMU-backed sandbox: an
  operator-authored template whose `spec.json` says `"backend": "qemu"` is now honoured instead of being
  coerced to the in-tree backend (a client-supplied `spec` is still always the in-tree backend, so a client
  cannot pick QEMU or its `extra_args`). Guest paths are limited to `/home`, `/mnt`, `/data`, `/srv`, `/opt`,
  `/workspace`, `/root` and to `[A-Za-z0-9/_.-]` because they reach generated cloud-init commands.
  `GET /v1/sandboxes` now also lists QEMU-backed sandboxes. There is no size quota: the directory is only as
  bounded as its host filesystem. Snapshot and AutoPause remain in-tree-backend features.

### Fixed
- **Dataplane resume after failed/cancelled migration.** Quiesce from `migrate start` is cleared when
  start returns an error, when QEMU reports `Failed`/`Cancelled`, on later terminal status polls, and on
  `migrate cancel` — so abandoned migrations no longer leave the VM edge stuck rejecting new flows.
- **`kubectl-fluxvm` SSH option injection.** `DisposableVm.spec.node` / MicroVM runtime node must be a
  plain hostname and is passed as `ssh -- <node> -- …`.
- **Pod identities were never released.** `pod_identity::forget` had no caller, so every Secure Containers
  Pod left its `pod_uid` -> `pod_id` entry in `pod-ids.json` for the node's lifetime (110 entries had built up
  on the lab node). VM delete now releases it, unless another VM still carries the same Pod UID (a failed
  sandbox create is retried on a new VM that may already be running). Verified live, warm-pool and cold: the
  entry appears while the Pod runs and is gone after it is deleted.
- **A bridge-hotplugged NIC leaked its tap.** `hotplug_nic` (the warm-pool bridge-chain path) never set the
  VM's `tap_name`, and stop/delete clean the network only for a record that names its primary tap, so the
  `hn0…` tap outlived every claimed VM (found live: one stray tap after a warm-pool bridge Pod). It is now
  recorded with the first hotplugged NIC; verified live (no links left after delete).
- **Secure Containers: a Pod could not be deleted.** On a live k3s + Cilium node `kubectl delete pod`
  left Pods `Terminating` indefinitely (in `direct` and `bridge` mode alike). Three causes, all found on a
  clean, freshly restarted containerd:
  1. `fluxvm-container-agent` moved only the outer (reaper) process into the container cgroup, after it had
     already forked the workload, so the workload stayed in the agent's own cgroup. `Kill(all)` by cgroup missed
     it, the wrapper died on SIGTERM and orphaned it, and it kept the stdio pipes open, so containerd's
     `task.Delete` waited for EOF forever. The outer process now joins the cgroup before forking, and forwards
     SIGTERM/SIGINT/SIGHUP/SIGQUIT/SIGUSR1/SIGUSR2 to the workload (as runc's init does). This also means cgroup
     limits, the device policy and the in-guest network policy now actually apply to the workload.
  2. That in-guest policy (`bpf/fluxvm_guest_cgroup.bpf.c`) keyed inbound packets by
     `bpf_get_current_cgroup_id()`, the interrupted task's cgroup, so once workloads really were in their cgroup all
     inbound traffic was dropped (fail-closed). It now uses `bpf_skb_cgroup_id()`.
  3. containerd runs the shim's `delete` subcommand whenever one container's connection closes; it destroyed the
     whole Pod VM, powering the guest off under the still-running sandbox (StopPodSandbox then failed forever
     against a vanished VM). It now only destroys the VM when no other task remains.
  4. The shim process itself stayed behind after every Pod (one idle process per Pod). containerd closes the
     connection ~3 s after `Shutdown`, and ttrpc then drops the in-flight handler; the handler awaited the
     daemon's VM delete (a graceful guest power-off takes far longer), so it was cancelled before it signalled the
     shim to exit, and the VM record, CNI netns alias and shim were all left. The teardown now runs on a detached
     task, so it completes and the shim exits.
  5. Found while exercising the direct datapath live: two Pods created at the same instant raced on one fixed
     `pod-ids.json.tmp` (bare ENOENT, so the VM create was rejected and `auto` silently fell back to the bridge
     chain); the pod-id and ipcache stores now use a lock and unique temp files.
  6. `VmStore::update` was an upsert, so a late writer could resurrect a VM that `delete` had just removed; it now
     only replaces an existing record.
  7. A rejected direct create left a `failed` VM record behind on every `auto` fallback; the shim now removes it.
  8. With workloads truly inside their cgroup the OCI device policy is enforced, and containerd's default
     "deny all" would leave containers unable to open the standard devices; the agent now adds runc's default
     allowed-device list (unit-tested).
  8b. `/dev` inside a Secure Container was the image's empty directory, so `/dev/null`, `/dev/zero` and
     `/dev/urandom` did not exist (`iperf3`: "failed to open /dev/urandom"; `dd if=/dev/zero` failed). This
     predates the cgroup change (an A/B against the pre-fix agent behaves the same). The agent bind-mounted the
     container rootfs onto itself *non-recursively* before `pivot_root`, which dropped the `/dev` tmpfs the OCI
     mounts had just placed under it; the self-bind is now recursive. The nodes are also `chmod`ed after `mknod`,
     since `mknod` applies the umask. Verified live: `/dev/null` (writable by a non-root user), `/dev/zero` and
     `/dev/urandom` work, and `/dev`, `/dev/shm`, `/proc`, `/sys`, ConfigMap volumes and `resolv.conf` all survive
     the pivot.
  9. A NIC hotplugged into a warm-pool VM is enumerated by the guest a moment after `device_add` returns; the shim's
     guest network script now waits for it instead of failing with an empty "exit=1".
  Live result: a Pod is fully deleted in ~13 s with nothing left behind (no tap/veth links, netns aliases,
  QEMU, VM records, shim processes).

### Added
- **Warm-pool Pods can run containers.** A pool member keeps the virtiofs shares its template was created with,
  so a Pod's container rootfs (staging directory, kubelet volumes) could not be delivered and a warm-pool Pod
  never became Ready. New:
  `CreateVmRequest.shared_memory` (boot with shareable memory so shares can be hot-added; set it on pool
  templates), and `POST /v1/vms/{id}/hotplug/share` (admin, QEMU): starts a `virtiofsd` for a host directory and
  hot-plugs a `vhost-user-fs-pci` device onto one of the reserved top PCIe root ports (`fs{N}`, N = share
  index; the `virtiofsd` is respawned per port attempt because it serves one connection). With
  `FLUXVM_CONTAINER_WARM_POOL` the shim hot-adds the Pod's shares right after the NIC. Live: a Pod claimed from a
  warm pool was Ready in **7 s** (a cold Pod takes ~140 s), with the container started, `logs`, `exec`, a
  ConfigMap volume and `/dev` working; two shares hot-added, mounted, read and written from the guest.
  Pool templates must have no `shared_folders` of their own: the shim expects the Pod's shares to be `fs0…`.
- **Warm-pool Pods get their eBPF Pod identity.** A pool member is booted before any Pod exists, so a
  claimed VM never carried `pod_uid` and Pod-scoped network policy (`/v1/vms/{id}/network/pod-policy`,
  "VM has no associated Pod identity") could not apply to it. `POST /v1/pools/{name}/claim` now takes a
  `pod_uid` (validated: 1–128 of `[A-Za-z0-9._-]`, checked before a member is taken), the shim sends the Pod's
  UID with `FLUXVM_CONTAINER_WARM_POOL`, and the identity is minted when the NIC is hot-added. A bridge-chain
  hotplug (`hotplug_nic`) now also attaches the dataplane when the VM has a Pod identity (the direct hotplug
  already did). Live, direct and bridge: the record carries the Pod's UID, the eBPF meta `pod_id` equals the
  `pod-ids.json` entry, and setting a Pod-scoped policy on the claimed VM returns 200. Enforcement against
  peer traffic was not exercised.
- **Multus secondaries exercised live.** With Multus in the CNI chain (a reversible rename; Cilium's
  `cni-exclusive` had to be relaxed while testing and was restored), a Secure Container Pod annotated with a
  NetworkAttachmentDefinition got `net1`, with `auto` using the bridge chain and reporting why, `direct` refusing
  as documented, and host ⇄ guest `net1` reachable (3/3 both ways). Ordinary Pods keep working through
  Multus → Cilium.
- **Cilium CNI (Secure Containers)** — shim `FLUXVM_CONTAINER_CNI_PROVIDER`
  (`auto`/`cilium`/`generic`) with Multus-safe `netN` filtering, eth0-preferring
  L2 handoff, `configs/cilium-cni.toml`, `docs/cilium-cni.md`,
  `deploy/k8s/cilium/`, and `scripts/evidence-cilium-cni.sh`. Does not write
  Cilium private maps.
- **Direct (bridge-less) datapath** — an eBPF redirect between the outer device and the
  VM's tap in place of a bridge, with Cilium's `lxc*` hooks untouched
  (`docs/direct-datapath.md`). Secure Containers: shim
  `FLUXVM_CONTAINER_CNI_DATAPATH=bridge|direct|auto` (default `auto`; live
  Cilium + KVM evidence passed, `docs/benchmarks/evidence/direct-datapath-live-20260919T202359Z.txt`), tap created inside the Pod netns and handed to
  QEMU as a descriptor, warm-pool NICs via QMP `getfd`. Standalone: `network.direct`
  with `l2-uplink` (shared per-uplink steering maps, ARP steering by `guest_ips`,
  several VMs on one unbridged NIC), `MicroVM.spec.networkMode: direct`,
  `POST /v1/vms/{id}/hotplug/nic` `direct` body. Also: `redirect_peer` capability
  probe, packet-flow hop view for bridge-less VMs, `scripts/bench-direct-datapath.sh`
  (bridge vs direct forwarding cost), `scripts/evidence-direct-datapath.sh`.
- **S1 depth** — `scripts/e2e-networkpolicy-s1-depth.sh` proves mid-flow TCP
  kill after CT-clear revoke and SYN anti-replay under reconnect churn.
- **S2** — `scripts/evidence-networkpolicy-second-cni.sh` (second kubeconfig or
  nftables policy-engine stand-in) alongside `REQUIRE_MULTI_NODE=1` Set 17.
- **S9** — Kata P0/P1 matrix (`scripts/evidence-kata-p0p1-matrix.sh`,
  `tests/oci-fixtures/`), hostPath allowlist broker
  (`fluxvm.io/hostpath-allow` / `FLUXVM_HOSTPATH_ALLOW`), and
  `SECCOMP_IOCTL_NOTIF_ADDFD` notify mode (`io.zyvor.seccomp.notify.mode=addfd`).
- **S10 / S11** — `scripts/evidence-fleet-multihost.sh` and
  `scripts/evidence-migration-attached-vm.sh` wired into the Set 19 GA gate.
- **H2** — virtio-pci ECAM device at `00:01.0` with BAR0 sizing + ACPI MCFG.
- **H3** — vhost-net mem-table + VRING NUM/ADDR/BASE/KICK/CALL; kernel datapath
  kicks when rings are programmed (userspace pump remains fallback).

### Changed
- **CLI rename: `fluxvm-cli` → `fluxctl`** — crate path `crates/fluxctl`,
  package `fluxctl`, binary `/usr/local/bin/fluxctl` (clap name `fluxctl`).
  `fluxctl serve` is the control-plane daemon. Deploy/Makefile also install a
  `fluxvm` → `fluxctl` symlink for one release of command compatibility;
  prefer `fluxctl` in new scripts and docs.
- **README and social preview rewritten** — benefit-led hero, a "Proof & status" section
  tying each claim to its evidence, and a refreshed 1280×640 social image
  (`docs/assets/social-preview.svg` → `.png`). Every existing README anchor is preserved.

### Fixed
- **VM-edge eBPF program rejected on Linux 7.x** — `fluxvm_tc.bpf.o` exceeded the
  verifier's 1,000,000-instruction limit on 7.0 (the pod-policy rule scan inlined
  the whole rule match on each of 64 iterations, in both address-family paths). The
  per-rule match is now a global BPF function verified once (needs Linux >= 5.5);
  the object uses ~17% of the limit. `scripts/test-verifier-budget.sh` guards it,
  `scripts/test-pod-policy-verdict.py` proves matching is unchanged, and
  `scripts/test-ebpf-smoke.sh` (stale since Set 19: no `fluxvm_pridx` writes or
  binding) passes again.
- **Attempted the Set 9S guest `aya` ELF-parse fix** —
  `docs/secure-containers-set9s.md` hypothesized the guest LSM MAC test's
  intermittent "error parsing ELF data" failure as a version/feature-
  unification mismatch between `aya` 0.13.1 and the workspace's pinned
  `object 0.36.7`, naming a newer `aya`/`aya-obj`/`object` pin as the
  likely fix. Bumped `fluxvm-container-agent`'s `aya` dependency to
  `"0.14"` (pulling `aya-obj` to 0.3.0 and `object` to 0.39.1). `cargo
  build`/`cargo test -p fluxvm-container-agent` (30 tests) pass clean, no
  API breakage from the two non-patch bumps, and Set 8S's own
  `aya`-loaded `cgroup_skb` test was confirmed to genuinely execute under
  real root and pass. **Honest limit**: Set 9S's own test — the one that
  actually exercises the failing code path — could not be run at all on
  the available build host, even as root, because that host's kernel has
  no `bpf` in its active `lsm=` boot parameters. This means the bump has
  *not* been validated against the real failure mode; there is no more or
  less confidence it's fixed than before, only that it doesn't regress
  anything else. See `docs/secure-containers-set9s.md` for the full
  account — not yet root-caused to a confirmed fix.
- Fixed a stale Secure Containers CI gate: `secure-containers-coverage.yml`'s
  `go-controller`/`go-observer` jobs were still pinned to Go 1.23 via
  `actions/setup-go`, even though both
  `controllers/fluxvm-networkpolicy-controller` and
  `tools/fluxvm-policy-observer` require `go 1.27` in their own `go.mod` —
  every run failed outright at the toolchain-version check, before a
  single test ran. Switched both jobs to `go-version-file` pointing at
  each module's own `go.mod`, so this can't silently drift again.
- **`enforce_token_quotas` counted every VM on the node, not just the calling
  token's own, against `max_vms_per_token`/`max_memory_mib_per_token`** — the
  function's own prior comment called this "conservative," but with two
  tokens both configured with a quota of 10, the first token to reach 10 VMs
  blocked every *other* token from creating any more: a quota meant to
  contain one noisy tenant instead let that tenant deny service to every
  other tenant, the opposite of what a per-token quota is for. Fixed by
  stamping a new `CreateVmRequest.created_by_token` server-side in
  `create_vm`/`create_sandbox` from the authenticated caller (never trusted
  from the request body) and filtering by it. Deliberately *not*
  `skip_deserializing`: `fluxvm-storage::Store` round-trips every `VmRecord`
  through the same serde codec on every `list()`/`get()`, so a
  `skip_deserializing` field silently comes back `None` after the first
  storage round trip — this broke quota enforcement outright during
  development (caught by a failing regression test) before being fixed by
  relying on the handler's unconditional overwrite instead, proven by a
  dedicated spoofing test. `enforce_token_quotas` also moved from
  `fluxvm-api` into `VmManager` (`fluxvm-scheduler`) so `create_vm` and
  `create_sandbox` share one implementation — `create_sandbox` previously
  skipped quota enforcement entirely, a second real gap this closes. 3 new
  tests: cross-token isolation, request-body spoofing resistance, and a
  serde round-trip proving the persistence path the `skip_deserializing`
  attempt broke.
- **The sandbox HTTP proxy had no cap on the guest's response body** —
  `sandbox_proxy_inner` capped the *request* body at 16 MiB but the
  *response* read from the guest (`up.into_body().collect()`) had only a
  30s timeout, no size limit at all: a malicious or compromised guest could
  stream an effectively unbounded response for up to 30s per request, a
  straightforward host-memory-exhaustion primitive from inside any tenant's
  own sandbox. Fixed with one named constant,
  `SANDBOX_PROXY_MAX_BODY_BYTES` (16 MiB), now shared by both the existing
  request cap and a new response cap via
  `Limited::new(up.into_body(), SANDBOX_PROXY_MAX_BODY_BYTES).collect()`.
  Factored the handshake/send/receive half of `sandbox_proxy_inner` into a
  new `proxy_over_tcp` helper, testable without `CAP_SYS_ADMIN`/
  `connect_in_netns`: `oversized_guest_response_body_is_rejected_not_fully_buffered`
  streams a genuine over-cap response from a real loopback `TcpListener`
  standing in as the guest and asserts the proxy doesn't return it fully
  buffered.
- **The sandbox HTTP proxy routes had no role check at all** —
  `sandbox_http_proxy`/`sandbox_http_proxy_default_port` took no
  `Extension<Role>` parameter, unlike every other guest-reaching route
  (`sandbox_fs_read`, `sandbox_process`, `agent_exec`, `qga_exec`, ...),
  which all gate on `require_admin(role)?`. Since the route is registered
  with `any(...)`, a `read-only` token could issue arbitrary HTTP methods
  into a tenant's guest through it — the same shape as the already-fixed
  `POST /v1/egress/check` gap above, missed by that earlier audit because
  these two handlers return a bare `Response`, not `ApiResult<T>`, so the
  `require_admin` error needs `.into_response()` instead of `?`. Fixed by
  adding the same gate both handlers' siblings already have. 2 new tests
  (`readonly_token_cannot_call_sandbox_proxy`/
  `admin_token_can_reach_sandbox_proxy_role_gate`).
- **A real, currently-exploitable cross-tenant bypass on the short-form
  sandbox proxy route** — `extract_vm_uuid` only recognized `/v1/vms/` and
  `/v1/sandboxes/` path prefixes; `tenant_guard_middleware` silently no-ops
  when it returns `None`. The router registers a third, separately-named
  proxy route matching neither prefix, `/sandbox/{id}/{*path}`
  (`sandbox_http_proxy_default_port`) — the actual AI-agent-facing entry
  point per `docs/agent-sandbox-gaps.md`'s "Guest HTTP reverse proxy"
  description, distinct from the already-correctly-scoped long-form
  `/v1/sandboxes/{id}/http/{port}/{*path}` route. Any authenticated caller
  who knew or guessed another tenant's sandbox UUID could proxy HTTP
  traffic straight into that tenant's guest through this specific route.
  Fixed by teaching `extract_vm_uuid` the third prefix — no handler changes
  needed, `tenant_guard_middleware` already wraps the whole router as an
  outer layer. New test,
  `short_form_sandbox_proxy_route_is_tenant_scoped`, mirroring the existing
  `sandbox_id_routes_are_tenant_scoped_like_vm_routes` test exactly.
- **A wedged `fluxvm-hypervisor` child could hang `pause`/`resume`/`shutdown`/
  snapshot control requests forever** — `control::request` had no timeout on
  its Unix-socket round trip, so a stuck vCPU thread still holding `VmState`'s
  lock, or a hung KVM ioctl inside `dispatch()`, left the caller's
  `next_line().await` blocked with no way to notice or recover — the same
  class of "no timeout on I/O to something outside this process's control"
  bug already fixed for the sandbox HTTP proxy, below, just one layer down:
  the peer here is the hypervisor subprocess itself, not a guest. Every
  request kind now gets a default 15s bound, with snapshot save/restore
  (which chain pause + snapshot I/O + resume inside one call) given 45s of
  headroom. 4 new tests, including a regression test that reproduces the
  exact wedge (server accepts and reads the request, then never answers).
- **A `tap`+`netns=true` sandbox's HTTP proxy hung indefinitely instead of
  reaching the guest** — `sandbox_proxy_inner` connected via a plain
  `reqwest::Client`, which always dials from the calling thread's ambient
  network namespace; a netns-sandboxed guest's `guest_ip` is only routable
  from inside that VM's own namespace, so every request over this path
  silently hung until timeout (vsock-based guest exec/file access was
  unaffected, since vsock doesn't route through the guest's netns at all —
  a fully healthy guest looked completely unreachable over HTTP alone). New
  `connect_in_netns()` `setns()`s a throwaway `std::thread` (never tokio's
  blocking pool, which reuses threads and would leak the namespace change
  into unrelated work) before calling `connect()`, then hands the connected
  socket back to the async runtime; since `reqwest` has no way to accept a
  pre-connected socket, the proxy now speaks HTTP/1.1 directly over that
  stream via `hyper`. Two related framing/hang bugs surfaced once this path
  was actually exercised end-to-end and fixed alongside it: forwarding the
  inbound `Content-Length`/`Transfer-Encoding` headers onto hyper's own
  `Full` body (which computes its own) duplicated them, leaving the guest's
  HTTP server waiting on body bytes that were never coming on any non-empty
  request; and the guest-response body read had no timeout of its own,
  so a guest that accepted a request but never finished its response body
  hung the whole proxy call, while forwarding the guest response's
  `Connection`/`keep-alive` headers onto the caller's own connection made
  the caller's pool try to reuse a connection axum had already closed,
  surfacing as an unexplained "connection closed before message completed".
- **A Firecracker guest kernel could block forever on `getrandom()` before
  its CRNG was seeded** — with no fast entropy source (no RDRAND passthrough,
  no virtio-rng), a guest boots with `crng_init=0`, and anything that calls
  `getrandom()` before enough environmental noise accumulates — in practice,
  the guest's own init/runtime startup — blocks indefinitely, indistinguishable
  from a hung process from the outside: alive, no output, nothing listening.
  `firecracker_config()` now unconditionally attaches Firecracker's built-in
  entropy device, and `FluxVmBackend`'s default kernel command line adds
  `random.trust_cpu=on rdrand=force` so the guest trusts RDRAND directly and
  seeds fully at boot even without a virtio-rng driver built into its kernel.
- **`start_from_snapshot` silently ignored a `loadvm_tag` on `Firecracker`/`FluxVm`
  VMs instead of rejecting it** — `create_vm_snapshot` (the save side) already
  correctly bails with "snapshot not supported for backend ..." for every
  backend but `Qemu`/`CloudHypervisor`, but `start_from_snapshot` (the
  restore side) had no matching check of its own: it set `loadvm_tag` on the
  launch request and called `start_impl` unconditionally. Neither
  `FirecrackerBackend`'s nor `FluxVmBackend`'s `launch` ever reads
  `req.loadvm_tag` at all, so a `start_from_snapshot` call against either
  backend silently produced an ordinary cold boot instead of a restore —
  the caller believed they got a VM resumed from saved state when they
  silently didn't, with no error naming the mismatch. New
  `snapshot_backend_error` is now shared by both the save and restore
  paths so they can never drift apart again. 2 new tests.
- **`fluxvm-cloud-hypervisor`'s `snapshot_save` had the exact same
  resume-failure-discard bug as `fluxvm-qemu`'s, below** — found while
  auditing every other `let _ = ...`-discarded `Result` across the crates
  that fix didn't already cover. `snapshot_save` pauses (`ch-remote pause`),
  takes the snapshot (`ch-remote snapshot`), then resumes
  (`ch-remote resume`) — but the resume call's result was also a bare
  `let _ = ...`, so a resume failure *after a successful snapshot* still
  returned `Ok(())`, leaving the VM silently paused with no error surfaced.
  Fixed the same way: both failure combinations are now reported
  explicitly. 4 new tests against a scripted fake `ch-remote` shell script
  (this backend shells out to a real binary rather than a QMP socket),
  covering the success path, resume-fails-after-save-succeeds, both-fail,
  and snapshot-fails-but-resume-succeeds.
- **`fluxvm-qemu`'s internal-snapshot resume failure was silently discarded** —
  `snapshot_save` pauses a running VM (QMP `stop`), takes the internal
  `savevm` snapshot, then resumes it (QMP `cont`) — but the `cont` call's
  result was a bare `let _ = ...`, so a resume failure *after a successful
  snapshot* still returned `Ok(())`. A caller acting on that `Ok` believed
  the VM was still running when it had actually been left paused, with no
  error surfaced anywhere to explain why. Fixed: both failure combinations
  (snapshot failed and/or resume failed) are now reported explicitly,
  naming which one happened; a snapshot that saved fine but failed to
  resume now returns an error saying exactly that, rather than a clean
  `Ok(())`. 4 new tests against a scripted fake QMP socket, covering the
  success path, resume-fails-after-save-succeeds, both-fail, and the
  already-paused VM (never told to `stop`/`cont` at all) case.
- **Warm pools (`/v1/pools`) had no tenant scoping at all** — the same gap
  as sandboxes above, in the same audit pass: `list_pools` had no tenant
  filter, `get_pool`/`delete_pool`/`claim_pool` (name-keyed, so
  `tenant_guard_middleware`'s UUID-based extraction never covered them
  either way) had no tenant check, and `create_pool` never forced the
  caller's own token `tenant` onto `spec.template.tenant`. The last one
  is the most consequential: every member ever backfilled from an
  untenanted pool inherits `template.tenant` unchanged, so a tenant-scoped
  admin token creating a pool without this fix would have produced members
  no tenant-scoped token — including its own creator, after claiming one —
  could ever reach via `/v1/vms/{id}/...`. Fixed: `create_pool`
  inherits/rejects the token tenant on `spec.template` exactly like
  `create_vm`; `list_pools` filters by tenant like `list_vms`;
  `get_pool`/`delete_pool`/`claim_pool` 404 for a mismatched tenant before
  reaching the underlying `VmManager` call; `claim_from_pool` additionally
  rejects (and cleans up, matching its own existing resume-failure
  cleanup) a claim whose resumed member's tenant doesn't match the
  claiming token's. 6 new tests.
- **Sandboxes (`/v1/sandboxes`) had no tenant scoping at all** —
  `tenant_guard_middleware` only ever recognized `/v1/vms/{id}...` paths, so
  every `/v1/sandboxes/{id}/...` route (snapshot, `fs/read`, `fs/write`,
  `process`) was reachable by any tenant-scoped token for any tenant's
  sandbox by UUID, not just its own; `list_sandboxes` had no tenant filter
  at all, unlike `list_vms`; and `create_sandbox` never forced the caller's
  own token `tenant` onto the resolved spec the way `create_vm` already
  does, so a tenant-scoped admin token could create a sandbox with no
  tenant at all, or an explicit `spec.tenant` naming a *different* tenant
  outright — either would have made the per-record tenant check
  meaningless for that sandbox from the moment it was created. Found by
  auditing tenant-scoping coverage across every `VmRecord`-backed id space,
  not just `/v1/vms`, following the same "audit every X for a Y" method
  that already found the `egress/check` gap below. Fixed: `extract_vm_uuid`
  now also recognizes `/v1/sandboxes/{id}...` (a sandbox is a `VmRecord`
  like any other); `list_sandboxes` filters by the caller's token tenant
  exactly like `list_vms`; a new `enforce_sandbox_tenant`
  (`fluxvm-scheduler::sandbox`) inherits/rejects the token tenant on the
  resolved spec, covering both the `template` and explicit-`spec` paths
  uniformly. 6 new tests (4 pure unit tests on `enforce_sandbox_tenant`, 2
  router-level regression tests proving cross-tenant list/id-route access
  is denied).
- **`POST /v1/egress/check` had no role check at all** — every other mutating
  route calls `require_admin`, but this one never did, so a `read-only`
  bearer token could call it directly and get back a real secret: when the
  checked host matches a configured `[sandbox] credential_vault` entry, the
  response includes that entry's plaintext `inject_authorization` value,
  which only an `admin` caller should ever see. Found by auditing every
  mutating route in `fluxvm-api::router` for a `require_admin` call — this
  was the only one missing it. Now returns 403 for `read-only` tokens,
  matching `docs/api.md`'s own documented RBAC contract ("any mutating
  route ... returns 403"). 2 new tests
  (`readonly_token_cannot_call_egress_check`/
  `admin_token_can_call_egress_check`).

### Added
- **F1 Hubble SID attribution** — `packetflow::from_flow_record_attributed`
  overlays CEP / Cilium-agent SecurityIdentity onto hubble observe flows
  (source + peer-VM destination); Fabric CT id remains the fallback. Never
  writes Cilium private maps.
- **F2 Prometheus scrape for `:9108`** — microvm node-agent exposes
  `MICROVM_METRICS_ADDR=0.0.0.0:9108` with scrape annotations;
  `deploy/k8s/microvm/servicemonitor.yaml` + `deploy/prometheus/fluxvm-scrape.yaml`.
- **S8 Observer evidence path** — `scripts/evidence-policy-observer-scrape.sh`
  archives `/metrics` + RSS into `docs/benchmarks/evidence/`.
- **H1 FLUXKVM1 v3 virtio live-state** — snapshot packs/restores virtio queue
  rings + status/features; disk/TAP paths still from boot config.
- **H3 vhost-net partial bind** — `VHOST_SET_OWNER` + `VHOST_NET_SET_BACKEND`
  for queues 0/1; VRING GPA / mem-table programming remains follow-up.
- **Firecracker capability-figure adoption** — [docs/capability-figures.md](docs/capability-figures.md)
  maps FC design/SPEC targets (≤5 MiB overhead, ≤125 ms boot, 5 microVMs/core/sec)
  onto FluxVM benches and threat-containment layers. `[jailer] enforce` (or
  `auth.require` + non-loopback listen) fail-closes serve/launch unless jailer
  is enabled; jailed boots default to `8250.nr_uarts=0`. Create fields
  `net_mbit_limit` / `net_pps_limit` / `blk_mbit_limit` / `blk_ops_limit` wire
  Firecracker virtio `rate_limiter` JSON. Benches report
  `mutation_per_core_sec`, `boot_to_ready_ms`, optional VMM RSS.
- **Positioning** — FluxVM is no longer framed as a “Disposable Compute Engine”;
  it is a general Rust-native VM control plane. Disposable / short-lived
  workloads remain a supported use pattern (optional TTL, CoW), not the product
  identity. `DisposableVm` CRD name unchanged.
- **Firecracker adoption reframed for general CP** — [docs/capability-figures.md](docs/capability-figures.md)
  splits Track A (production isolation for all guests) vs Track B (optional
  microVM density). Virtio rate limits now propagate through `fluxvm-hypervisor`
  BootConfig as well as the plain Firecracker backend; added
  `configs/production-hardening.toml` and NEXT-FEATURES FC1–FC3.
- **FC1–FC3 complete (multi-backend)** — oversub policy defaults +
  [docs/oversubscription.md](docs/oversubscription.md); static `cpu_template`
  for Firecracker/FluxVm-firecracker; `/v1/vms/{id}/snapshot` for Firecracker
  and FluxVm (CH/QEMU already supported).
- **`GET /fleet/nodes/{name}`** — exactly one node's own fleet record
  (`healthy`/`cordoned`/`labels`/free-capacity), without a caller having to
  fetch and filter the whole `GET /fleet/nodes` list just to check one
  node's state in isolation. `404` for a name that was never registered,
  matching the status `cordon`/`uncordon`/`deregister` already use for the
  identical case on this same path segment (unlike
  `GET /fleet/nodes/{name}/vms`'s `400`, since that route's unknown-name
  case is a bad *proxy target*, not a missing *resource*). `fluxctl fleet
  node NAME` is the matching CLI form.
- **Label/`nodeSelector`-aware placement for the fleet registry** —
  automatic `POST /fleet/vms` placement was purely capacity-based
  (`pick_best_capacity` scored nodes only on residual vCPU/memory), with no
  way to express "only nodes in zone X" or "only nodes with a GPU" short of
  pinning an exact `--node`, which throws away all failover. `NodeInfo`/
  `RegisterRequest` gain a `labels: HashMap<String, String>` (serde-default,
  backward compatible with an older node agent that predates labels);
  `fluxvm-agent node` gains a repeatable `--label key=value` flag, carried
  on every heartbeat. `POST /fleet/vms` accepts an optional `"nodeSelector"`
  object; placement now filters candidates to nodes whose labels are a
  superset of it (Kubernetes `nodeSelector` semantics) before scoring
  capacity, threaded through every retry of the failover loop below, not
  just the first pick. An unmatched selector fails with a clear 503 naming
  it. An explicit `"node"` target still bypasses the selector entirely,
  same as it bypasses cordoning. `GET /fleet/nodes` now reports each node's
  labels; `fluxctl fleet create --node-selector key=value` is the matching
  CLI form. 10 new tests.
- **Automatic fleet-wide VM placement now fails over to the next-best node
  when the first pick is unreachable**, instead of hard-failing the create
  outright. `pick_best_capacity` chooses the highest-residual-capacity node
  using only heartbeat data; a node only gets excluded once its heartbeat
  has gone stale past `HEALTHY_WINDOW_SECS` (30s), so a node that crashed,
  hung, or dropped off the network moments after its last heartbeat still
  looked "healthy" and got picked, hard-failing the create even while other
  schedulable nodes sat idle. New `pick_best_capacity_excluding` (exclusion-
  set variant; `pick_best_capacity` is now a thin wrapper, so existing call
  sites/tests are unaffected) and a `DispatchError::{Unreachable,Rejected}`
  split: an unreachable node (connection failure, or a response that isn't
  valid JSON) is excluded and the next-best remaining candidate tried,
  looping until one accepts the create or every schedulable node has been
  tried; a node that reached its own `fluxctl serve` and explicitly rejected
  the request (bad fields) is never retried elsewhere, since every other
  node would reject the identical body identically. An explicit `"node"`
  target is unaffected — still a single, non-retried attempt, so a caller
  who pinned a node gets an honest failure instead of a surprise landing
  somewhere else. 4 new tests.
- **`fluxctl fleet` — CLI parity for the fleet registry's REST API**
  (`nodes`, `cordon`, `uncordon`, `deregister`, `capacity`, `create`,
  `vms`, `node-vms`, `delete`, `node`). Every fleet operation used to mean
  a raw `curl` call; this gives `fluxvm-agent central`'s multi-host fleet
  registry the same CLI-parity treatment `migrate`/`ping`/`copy-to` already
  gave the per-node REST API, just against the central registry instead of
  a node's own `fluxctl serve`. New `crates/fluxctl/src/fleet_client.rs`,
  a thin `reqwest`-based client speaking the same opaque-JSON boundary
  `fluxvm-agent::central` itself uses (it treats `CreateVmRequest`/
  `VmRecord` bodies as opaque JSON rather than depending on `fluxvm-core`,
  and this client sits on the other side of exactly that boundary). Real
  integration tests spin up the actual `fluxvm-agent::central` router, not
  mocks.
- **`GET /fleet/capacity`** — a fleet-wide aggregate distinguishing total,
  free, and schedulable capacity (a cordoned or unhealthy node still counts
  toward total/free but not schedulable), closing the gap between
  `GET /fleet/nodes` listing per-node numbers and there being any single
  answer to "how much room is left in the fleet right now."
- **`fluxctl resources` — CLI parity for the cgroup resource patch.**
  `POST /v1/vms/{id}/resources` has existed since cgroup v2 resource control
  landed, but was explicitly left REST-only when `freeze`/`thaw`/`frozen`
  closed the rest of this section's CLI gap (see that entry above): it takes
  a multi-field `ResourcePatch` that deserved real flag design instead of a
  JSON blob shoved onto the command line. `fluxctl resources <id>
  [--cpu-quota-percent N] [--memory-max-bytes N] [--io-weight N]
  [--pids-max N] [--cpuset-cpus SPEC]` maps one flag per `ResourcePatch`
  field and preserves its "only touch what's set" contract exactly — a
  field omitted from the command line is left alone, not reset — with the
  CLI itself refusing a bare `fluxctl resources <id>` with no flags at all
  (a plain `bail!` in the match arm; clap's own `Option`-only shape has no
  way to express "at least one of these" at the parser level) rather than
  silently issuing a no-op `POST`. `--cpuset-cpus` accepts the exact set
  syntax `cpuset.cpus`/`cpuset.cpus.effective` themselves read back in
  (`"0-3"`, `"0,2,4"`, `"0-1,4-5"`, per `fluxvm_cgroup::cpuset`'s own
  `parse_set`/`format_set`), via a new, independent `parse_cpuset_spec` that
  additionally rejects an empty string (ambiguous here, since "leave
  cpuset pinning untouched" is already expressed by omitting the flag) and
  a reversed range like `"5-2"` — which the existing cgroup-side parser
  would silently expand to an empty range under plain `start..=end` and
  apply as "pin this VM to no CPUs at all," a typo failing open into a
  much worse outcome than a parse error. 17 new tests: CLI-argument-parsing
  coverage per flag and for all five together, the "parses fine at the
  clap layer but the match arm still refuses zero flags" split, a
  distinctness check against `freeze`/`pause`, and dedicated
  `parse_cpuset_spec` coverage of every accepted and rejected shape.
  Verified building, `cargo test -p fluxctl` (50/50), `cargo clippy -p
  fluxctl --no-deps` (clean against this change), and `cargo fmt -p
  fluxctl -- --check` on the Linux remote (this crate doesn't build on
  macOS, same as always). `set_resources` itself is unchanged and was
  already verified against real `memory.max`/`cgroup.procs` files by
  `scripts/test-cgroup-resources.sh` when the REST route first landed —
  this only adds a CLI front end for it.
- **`fluxctl freeze`/`thaw`/`frozen` — CLI parity for the cgroup v2 freezer.**
  `POST /v1/vms/{id}/freeze`, `POST .../thaw`, and `GET .../frozen` have
  existed since cgroup v2 resource control landed (see "Resource control
  (cgroup v2)" further down this changelog), but — like `resources`,
  `stats`, and `pressure` alongside them — there was no CLI form at all;
  triggering one meant a raw `curl` call. This one mattered more than the
  other three cgroup routes because it's easy to reach for by mistake:
  `freeze`/`thaw` act on the cgroup freezer directly (`cgroup.freeze`),
  stopping every process in the VM's `fluxvm.slice/{id}.scope` at the
  kernel level, which is a different mechanism from `pause`/`resume`
  (already CLI-native) — those go through the VMM's own control socket
  (QMP `stop`/`cont` for QEMU, `ch-remote pause`/`resume` for Cloud
  Hypervisor) and do nothing to help when that socket itself is wedged,
  exactly the case `freeze` covers. `fluxctl freeze <id>` and `fluxctl thaw
  <id>` call `VmManager::freeze`/`::thaw` directly; `fluxctl frozen <id>`
  reports the freezer's current state as `{"frozen": true|false}` without
  changing anything, matching `GET .../frozen` exactly. All three are
  bodyless GETs/POSTs against an existing `VmManager` method, so no new
  wire types were needed; `resources`/`stats`/`pressure` stay REST-only —
  `resources` takes a multi-field patch that deserves real flag design of
  its own, and the other two are read-only introspection with no CLI
  urgency yet. 7 new CLI-argument-parsing tests, including one proving the
  three new commands aren't accidentally aliased to each other or to
  `pause`/`resume`.
- **`fluxctl migrate start`/`status`/`cancel` — CLI parity for live migration.**
  `POST /v1/vms/{id}/migration/start`, `GET .../migration/status`, and
  `POST .../migration/cancel` have existed since the QEMU (and, more
  recently, Cloud Hypervisor) source-side live-migration transport landed
  (see docs/runtime-boundary.md's runtime contract v1), but triggering one
  meant a raw HTTP call with a hand-built JSON body — there was no CLI
  equivalent at all, unlike every other VM lifecycle operation. This closes
  that gap for the standalone mode the runtime-boundary doc already calls
  out: a deployment with no Fabric orchestrator driving these routes over
  HTTP still needs a way to move a VM off a node by hand.
  `fluxctl migrate start <id> --destination <tcp:host:port|unix:/path>
  [--mode pre-copy|post-copy] [--bandwidth-mbps N] [--max-downtime-ms N]
  [--multifd-channels N]` requires the VM to already be `Running` and
  refuses anything but a `tcp:`/`unix:` destination, same shared allowlist
  the REST route already validated against (`exec:` included, so this can't
  become an arbitrary shell invocation on the source host); `--mode` takes
  exactly `MigrationMode`'s own kebab-case wire spelling rather than a
  second CLI vocabulary for the same two values. `migrate status`/`migrate
  cancel <id>` stay QEMU-only — Cloud Hypervisor's `send-migration` is
  fire-and-forget with no status-polling or cancellation primitive of its
  own — and now surface that as a clear CLI error instead of only being
  discoverable by reading the REST handler's source. 5 new
  CLI-argument-parsing tests plus 2 for the `--mode` parser; verified on the
  Linux remote alongside the rest of this crate's suite.
- **`fluxctl ping`/`copy-to`/`copy-from` — CLI parity for the vsock guest
  agent's health check and file transfer.** The REST API has exposed
  `POST /v1/vms/{id}/agent/put-file` and `.../get-file` since the guest
  agent itself gained `PutFile`/`GetFile` (see the "Add vsock guest agent
  file transfer" entry further down this changelog), but the CLI only ever
  grew an `exec` command alongside them — copying a file into or out of a
  VM meant hand-rolling the HTTP call yourself, base64 and all, with no
  local equivalent of the `scp`-style ergonomics `exec` already gets.
  `fluxctl copy-to <id> <local> <remote> [--mode <bits>]` reads a local file,
  rejects anything already over the guest agent's own
  `MAX_FILE_TRANSFER_BYTES` cap before spending a base64 encode and a vsock
  round trip on content that would just be rejected guest-side anyway, and
  writes it in; `fluxctl copy-from <id> <remote> <local>` reads it back out
  and restores the guest-reported Unix permission bits on the local copy,
  not just its bytes — a copied-out private key or script keeps behaving
  the way its mode implies instead of landing at this process's umask
  default. `fluxctl ping <id>` adds the missing health check for this same
  channel: `qga ping` has covered the separate QEMU guest-agent socket for a
  while, but there was no way to ask "is the plain vsock agent even up"
  without spending a real `exec` round trip to find out — a new
  `VmManager::agent_ping` (and `POST /v1/vms/{id}/agent/ping`, gated the
  same as every other agent route) answers that with one `AgentRequest::Ping`
  instead. New CLI-argument-parsing tests for all three commands, plus unit
  tests for the size-cap check and the base64-decode-and-restore-mode path
  `copy-to`/`copy-from` are built on.
- **All-features GitHub CI** — `.github/workflows/all-features.yml` runs portable
  suites on `push` to `main` and `workflow_dispatch` (vsock CSM, Network Fabric
  preflight/enable dry-run, devops gates, Secure Containers units + use-case
  matrix, Sentinel/intelligence static). `ci.yml` adds an explicit virtio-vsock
  CSM filter; `network-fabric.yml` path-filters and runs preflight + enable
  dry-runs after installing BPF objects. `docs/DEVOPS.md` documents
  `vars.FLUXVM_*` and self-hosted lab labels. Privileged/live lanes stay opt-in.
- **In-tree FluxVM KVM virtio-vsock host→guest CSM** — `fluxvm-hypervisor`
  previously bound the Firecracker-style unix socket and advertised the MMIO
  device so the guest driver could bind, but drained TX without parsing
  packets and never accepted `CONNECT`, so guest-agent ping/exec could not
  complete on `fluxvm_engine=kvm`. The device now implements the Firecracker
  unix proxy handshake (`CONNECT <port>\n` → virtio REQUEST → guest RESPONSE
  → `OK <host_port>\n`) plus RW/credit/shutdown bridging for host-initiated
  streams. Guest→host `uds_path_<port>` muxer remains deferred. Unit tests
  cover header codec, CONNECT parsing, and CONNECT→REQUEST→OK→RW.
- **Network Fabric eBPF enablement UX** — new
  `scripts/network-fabric-preflight.sh` (bpffs, bpftool/tc, BPF object,
  systemd MEMLOCK/paths); `enable-network-fabric-ga.sh` merges from
  `configs/network-fabric-{ga,lab}.toml` (SoT), supports `--lab` soft
  profile, schema-v4 managed markers, and post-restart health hints. README /
  `config.example.toml` / production-dataplane runbook surface the one-liner.
  Global default remains `mode=legacy`.
- **`GuestImage.spec.kernel` now actually reaches the VM it boots** — the
  field has existed on `GuestImageSpec` since `GuestImage` was introduced
  (`docs/microvm.md` already documented it as an "optional ... `kernel`"),
  but nothing downstream ever read it: `images::guest_image_host_path` only
  ever surfaced the disk image, `fluxvm_client::create_body` never emitted a
  `"kernel"` key in the `POST /v1/vms` body, and `MicroVMSpec` itself has no
  `kernel` field to carry one — so a GuestImage catalogued for Firecracker's
  direct-kernel boot silently had no way to actually get its kernel to the
  VM it named. `CreateVmRequest.kernel` (`fluxvm-core`) and the scheduler's
  own Firecracker-eligibility check (`req.kernel.is_some()`) were already
  real and load-bearing on the `fluxctl serve` side — the microvm CRD layer
  was the missing link. Wired now: `guest_images::reconcile` verifies
  `spec.kernel` is present on the node (same fail-closed contract as
  `spec.sha256` above — a GuestImage naming a kernel that isn't staged is
  never marked Ready, never launches a guest with no kernel or a stale one
  reused from a same-named entry) and records the confirmed path in a new
  `status.kernelPath`. `node_agent::resolve_image` now resolves both the
  disk path and `status.kernelPath` from the same GuestImage lookup, and
  `FluxVMClient::create_vm`/`create_body` take an added `kernel: Option<&str>`
  forwarded straight onto the create request. Warm-pool templates
  (`pools::reconcile` → `ensure_pool`) are unaffected — they don't resolve
  the GuestImage catalog for their `image` field either, so pool templates
  must still name a direct disk image, matching existing behavior. 9 new
  unit tests (`guest_images::resolve_kernel`, `images::guest_image_kernel_path`,
  `fluxvm_client::resolved_kernel_is_forwarded`). Docs:
  [docs/microvm.md](docs/microvm.md#guestimage),
  [docs/tutorials/microvm/05-guestimage.md](docs/tutorials/microvm/05-guestimage.md)
  (new "catalog a direct-kernel-boot image" section). Verified with `cargo
  build`/`cargo test`/`cargo clippy --no-deps`/`cargo fmt --check` on macOS
  and the real Linux build host — no live Firecracker guest was booted
  end-to-end to confirm the forwarded `kernel` path actually produces a
  working direct-kernel boot; that's a hardware/root capability this
  environment doesn't have, so it's verified by code inspection of the
  already-existing `fluxvm-core`/scheduler kernel handling plus these unit
  tests, not a live run.
- **`GuestImage.spec.sha256` is now actually verified** — the field has
  existed on `GuestImageSpec` since `GuestImage` was introduced (`docs/microvm.md`
  already documented it as an "optional `sha256`"), but nothing in
  `guest_images::reconcile` ever read it: any file staged at `spec.source`
  flipped `status.ready=true` regardless of its contents, so a corrupted
  transfer or an operator staging the wrong file under the right path was
  silently handed to every `MicroVM` naming that catalog entry — no error,
  no signal, just a guest that boots off the wrong disk. Fail-closed now:
  when `spec.sha256` is set, the reconciler hashes the staged file and
  compares before `status.ready` flips true; a mismatch leaves
  `status.ready=false`, clears `status.path`, and reports
  `status.message: "sha256 mismatch: expected <spec>, got <actual>"` so the
  cause is visible on `kubectl get gimg -o yaml` rather than a `MicroVM`
  stuck unexplainably Pending against a Ready-but-wrong image. A GuestImage
  with `spec.sha256` unset keeps today's behavior exactly (Ready as soon as
  the file exists) — this is opt-in, not a change to any existing manifest's
  observed lifecycle. Re-hashing a multi-GB disk image on every 30s
  reconcile forever would be its own quiet cost, so the digest is only
  recomputed when the staged file's size/mtime or the requested `spec.sha256`
  itself changes since the last successful check — a new internal
  `status.verifiedSignature` field (`"{len}:{mtime}:{sha256}"`) is the cache
  key, so an unchanged file costs one `stat()` per reconcile instead of a
  full re-read. New `sha2` dependency in `fluxvm-microvm` — already vetted
  and present in the workspace via `fluxvm-image`'s own catalog signing,
  which uses the identical `expected .../got ...` mismatch message
  convention (`fluxvm-image::verify_sha256`) this mirrors for consistency.
  8 new unit tests in `fluxvm-microvm::guest_images` (`verify_staged_file`
  and its `signature`/`hash_file` helpers are plain functions against real
  temp files via `tempfile`, matching this crate's existing
  `jobs::ttl_expired`/`policy` convention of keeping reconcile decisions
  testable without a cluster): no-`sha256` short-circuit, matching digest,
  case-insensitive comparison, mismatch clears `path`, a missing file fails
  closed even without a `sha256` requirement, a fresh cache hit is trusted
  without re-hashing, and changing the requested digest invalidates a stale
  cache entry rather than trusting it. Docs:
  [docs/microvm.md](docs/microvm.md#guestimage),
  [docs/tutorials/microvm/05-guestimage.md](docs/tutorials/microvm/05-guestimage.md)
  (new "verify the staged file's digest" section). Verified with `cargo
  build`/`cargo test`/`cargo clippy --no-deps`/`cargo fmt --check` on macOS
  (`fluxvm-microvm` builds there) and on the real Linux build host — no live
  k3s cluster exercised this end to end, so the `MicroVM` reading a stale
  `status.path` from a since-invalidated GuestImage is verified by code
  inspection of `images::guest_image_host_path` (unchanged; it already
  requires `status.ready`) plus these unit tests, not a live cluster run.
- **`MicroVMJob.spec.ttlSecondsAfterFinished` now actually does something** —
  the field has existed on the CRD since `MicroVMJob` was introduced (it's
  right there in `MicroVMJobSpec`, and `examples/microvm/microvmjob.yaml`
  never set it), but nothing in `jobs::reconcile` ever read it: a finished
  Job — and every child `MicroVM` it created along the way — sat around
  forever until an operator ran `kubectl delete mvmj` by hand. CI-style
  fan-out workloads (`MicroVMJob`'s own documented use case in
  `docs/tutorials/microvm/02-job.md`) are exactly the kind that create a lot
  of these and finish quickly, so this was a slow, silent resource leak
  every run added to. Fixed the same way Kubernetes' own `Job` TTL
  controller works: the reconciler now stamps a new `status.finishedAt`
  (RFC3339) the first reconcile that observes a terminal phase
  (`Succeeded`/`Failed`) — set once and carried forward unchanged on every
  later reconcile, so restarting the controller or re-reconciling an
  already-finished Job can never push its deletion out — and once
  `now >= finishedAt + ttlSecondsAfterFinished`, deletes the `MicroVMJob`
  object outright. Deleting it is enough: its child `MicroVM`s already carry
  a `controller_owner_ref` back to the Job (set when `jobs::reconcile`
  creates them), so Kubernetes' own garbage collector cascades the delete to
  them, and each child's own finalizer-driven cleanup (shadow Pod,
  EndpointSlice, node-agent-side VMM teardown — unchanged, in
  `controller.rs`) runs exactly as it would for a `kubectl delete mvm` today.
  A Job with `ttlSecondsAfterFinished` unset keeps today's behavior exactly
  — this is opt-in per Job, not a change to any existing manifest's
  observed lifecycle. The reconcile's own requeue interval is now
  TTL-aware too (`next_requeue`): it sleeps until the TTL deadline instead
  of the previous fixed 10s poll, clamped to a 1s floor and the existing 10s
  ceiling, so a short TTL is honored promptly rather than waiting up to one
  more full poll interval after it expires. 7 new unit tests in
  `fluxvm-microvm::jobs` (`ttl_expired`/`next_requeue` are pure functions,
  matching this crate's existing `policy`/`capacity` convention, so no
  cluster is needed to exercise the TTL math: not-yet-expired, expired-at-
  and-past-the-deadline, a zero-TTL expiring immediately, the no-TTL steady
  cadence, mid-countdown sleep length, capping at the steady ceiling for a
  far-off TTL, and flooring at 1s when a reconcile lands essentially exactly
  on the deadline). Docs:
  [docs/microvm.md](docs/microvm.md#microvmjob),
  [docs/tutorials/microvm/02-job.md](docs/tutorials/microvm/02-job.md),
  `FEATURES.md`'s "MicroVM" bullet; `examples/microvm/microvmjob.yaml` now
  sets `ttlSecondsAfterFinished: 300` to show the shape. Verified with
  `cargo build`/`cargo test`/`cargo clippy --no-deps`/`cargo fmt --check`
  both on macOS and on the real Linux build host (`fluxvm-microvm` builds
  on both) — no live k3s cluster exercised this end to end, so the
  ownerReference-cascade-to-a-real-finalizer-cleanup path is verified by
  code inspection of the existing, unchanged `controller.rs` cleanup path
  plus these unit tests, not a live cluster run.
- **Image catalog signing: build-lineage/CI-provenance recording** — closes
  the second, deeper half of the gap FEATURES.md's Security Posture table
  named explicitly as still open ("Real build-lineage/CI-provenance
  recording (which pipeline/run produced this image)") after the first half
  (`signed_at`/`signed_by`/covering `distro`/`version`/`arch`) closed
  earlier. `CatalogEntry` gains three new optional fields —
  `build_pipeline`, `build_run_id`, `build_commit` — settable via three new
  `fluxvm catalog sign` flags (`--build-pipeline`/`--build-run-id`/
  `--build-commit`) and now covered by `canonical_payload`, the same
  tamper-evidence treatment `distro`/`version`/`arch` got: relabeling any of
  them in `catalog.json` after signing invalidates the signature (new test:
  `verify_rejects_a_relabeled_build_provenance_field`). Read the honesty
  caveat plainly, though — same posture as `signed_by` — this *records* a
  claim asserted by whoever ran `catalog sign`, not an independently
  verified attestation; there is still no cryptographic chain proving the
  named CI system actually produced these bytes (that would need something
  like Sigstore/in-toto, which this project's signing scheme deliberately
  avoids, same reasoning as avoiding a `cosign`/Fulcio/Rekor dependency —
  see this file's own module doc comment). Live-verified against the real
  `fluxvm` binary on the test host: signed an entry with
  `--build-pipeline github-actions/build-images.yml --build-run-id
  987654321 --build-commit <sha>`, confirmed `GET`/`catalog list` reports
  `signature_valid: true`/`signed_by: "release-ci"`, then hand-edited
  `build_run_id` in `catalog.json` and confirmed the same entry flips to
  `signature_valid: false`/`signed_by: null` — the tamper-evidence claim is
  real, not just unit-tested. 3 new catalog tests (round-trip through
  `sign_entry`, the relabel-invalidates-signature test above, and the
  existing sign/verify suite extended to cover the new fields) plus 2 new
  `fluxvm catalog sign` CLI-parsing tests.
- **Cloud Hypervisor backend: real live migration** — `POST
  /v1/vms/{uuid}/migration/start` previously bailed "live migration
  contract v1 supports qemu only" for every non-QEMU backend; Cloud
  Hypervisor now actually migrates. `migration_start` validates the
  destination through the same shared `validate_migration_transport`
  `fluxvm-qemu` already used (moved into `fluxvm-core::backend` so the two
  backends' `tcp:`/`unix:`-only contract can't drift apart), maps
  `MigrationStartRequest` onto `ch-remote send-migration`'s own
  `destination_url=...,downtime_ms=...,memory_mode=precopy|postcopy,
  connections=...` config string, and pre-checks three real Cloud
  Hypervisor constraints up front rather than relaying its raw validation
  error for them (all three verified live): it has no bandwidth-throttle
  knob at all, so `bandwidth_mbps` is rejected outright rather than
  silently ignored; `connections` (its multifd analogue) and a `unix:`
  destination are mutually exclusive; and post-copy mode requires exactly
  one connection. `RuntimeCapabilities`'s migration entry gained a new
  `status_pollable` field (`true` for QEMU, `false` for Cloud Hypervisor)
  and a Cloud Hypervisor entry, so Fabric can tell up front which contract
  it's getting. 9 new tests (5 in `fluxvm-cloud-hypervisor` against a
  scripted fake `ch-remote` logging its full argv, 2 shared-validator
  tests moved with the function, plus the pre-existing QEMU validator
  tests now exercising the shared implementation).

  The single biggest way this differs from QEMU's contract, discovered
  only by testing against real binaries rather than assumed from Cloud
  Hypervisor's own docs: `send-migration` returns as soon as the request
  is *accepted*, not once the transfer finishes. Verified live against a
  real `cloud-hypervisor`/`ch-remote` v53.0 pair by pointing `send-migration`
  at a `unix:` destination nothing was listening on — the call still
  returned success immediately, with the real "Migration failed: ... No
  such file or directory" only ever surfacing seconds later in the VMM's
  own log file. Cloud Hypervisor's API has no status-query or cancellation
  primitive at all for what happens next, so `migration_status`/
  `cancel_migration` deliberately stay qemu-only (with a Cloud
  Hypervisor-specific error explaining why, not the generic "supports qemu
  only" every other unsupported backend gets) rather than inventing a
  status this backend cannot actually report. Also verified live, over
  both `unix:` and `tcp:` destinations on that same real pair: a running
  VM was fully handed off between two separate `cloud-hypervisor`
  processes — the destination's `ch-remote info` came back with the
  migrated config and `"state":"Running"`, and the source process exited
  on its own right after, exactly as Cloud Hypervisor's docs describe. That
  source exit needed no new handling here: this project's existing
  reconcile loop already notices the pid is gone and marks the VM
  `Stopped` (releasing its tap/netns/sandbox policy on this node) the same
  as it would for any other process that exited on its own — which is
  exactly the right outcome for a VM that just left this node for another
  one.
- **Cloud Hypervisor backend: real CPU/memory hotplug** — `POST
  /v1/vms/{uuid}/hotplug/cpu`/`hotplug/memory` previously worked on QEMU
  only ("Cloud Hypervisor/Firecracker backends have no hotplug support in
  this codebase," per this file's own QEMU-hotplug entry below); Firecracker
  still doesn't, but Cloud Hypervisor now does. `build_args` reserves the
  same headroom QEMU already reserves by default (mirrored via two new
  shared `max_vcpus`/`max_memory_mib` helpers so the two backends' default
  formulas can never drift apart) — `--cpus boot=N,max=M` and `--memory
  size=NM,hotplug_size=HM` (Cloud Hypervisor's own headroom parameter is
  *additive*, unlike QEMU's absolute `-m maxmem=`, so `hotplug_size` is
  computed by subtracting `size` back out of the same absolute ceiling QEMU
  would use for an identical request). `hotplug_cpu`/`hotplug_memory` query
  `ch-remote info` for the VM's current live vCPU count/memory size, compute
  the new absolute total, and call `ch-remote resize --cpus`/`--memory` to
  it — `resize` itself takes an absolute target, not a delta, the opposite
  shape from QEMU's own `device_add`-based fill-the-next-free-slot
  mechanism. Grow-only by this crate's own choice (`resize` itself can
  shrink too, auto-offlining vCPUs in the guest) to match the QEMU backend's
  existing no-unplug contract. A memory add must be a whole multiple of
  128MiB, Cloud Hypervisor's own ACPI-hotplug requirement — checked up
  front with a clear message instead of relaying its raw
  "not a valid size" error. 8 new tests against a scripted fake `ch-remote`
  (extending the existing `snapshot_save` fixture pattern with a fake
  `info` JSON response and resize-argv logging) plus 2 build-args tests
  proving the new `max=`/`hotplug_size=` headroom math. Verified live
  end-to-end against a real `cloud-hypervisor v53.0`/`ch-remote v53.0` pair
  on a KVM-capable Linux host — not just unit tests against a fake binary:
  booted with `--cpus boot=1,max=4`/`--memory size=512M,hotplug_size=2048M`,
  resized vCPUs 1→2 and memory 512M→1G→2G→2.5G (`ch-remote info` confirming
  the new live totals each time), confirmed the documented 128MiB-alignment
  and max-headroom rejections fail with Cloud Hypervisor's own real error
  strings, and confirmed `resize --cpus`/`--memory` reject a target beyond
  `max_vcpus`/`size + hotplug_size` exactly as this crate's own pre-checks
  now anticipate before ever shelling out.
- **`fluxvm-agent central`'s fleet-wide `GET /fleet/vms` now names any node
  it couldn't account for, instead of silently omitting it** — the same
  surface-don't-hide fix the single-node `GET /fleet/nodes/{name}/vms`
  route got below, extended to the aggregate it was originally written to
  work around. Previously a node excluded up front for a stale heartbeat,
  or one whose own `GET /v1/vms` call failed partway through (connection
  error, non-2xx response, unparseable body), just disappeared from
  `"items"` with nothing but a server-side `tracing::warn!` the caller
  never saw — a fleet member being down looked identical to it simply
  having no VMs, with no way to tell the two apart from the response
  alone. The response now carries a second field, `"unreachable_nodes"`:
  an array of `{"node": "...", "reason": "..."}` naming every node that
  didn't make it into `"items"` and why (`"unhealthy (stale heartbeat)"`
  for one excluded before it was even queried; a specific connection/
  status/parse error for one that was queried and failed). It's `[]` on
  the ordinary all-healthy path, so an existing caller that only reads
  `"items"` sees no behavior change; one that wants to know whether the
  list it just got is the *whole* fleet's now has a direct answer instead
  of having to cross-reference `GET /fleet/nodes` or grep server logs. 4
  new tests in `fluxvm-agent::central`: all-healthy-and-reachable reports
  an empty `unreachable_nodes`; an unreachable node is named while the
  other node's real VMs still come through; a stale-heartbeat node is
  named without ever being contacted; a node that rejects the call with a
  non-2xx is named with its own error message folded into the reason.
  Docs:
  [docs/operations.md — Distributed node-agent](docs/operations.md#distributed-node-agent),
  `FEATURES.md`'s "`fluxvm-agent`" bullet. Same honest limit as the two
  fleet-registry features below: not re-verified against the real
  two-physically-separate-host rig `scripts/test-fleet-agent.sh`
  exercises — that script is unchanged and wasn't re-run against live
  hardware; verification here is the 4 new unit-level tests plus a real
  (if local) build/test/clippy/fmt pass, not a live-fleet run.
- **`fluxvm-agent central` can now list exactly one node's VMs** —
  `GET /fleet/nodes/{name}/vms`. The only existing way to see what's
  running on a specific node was `GET /fleet/vms`, which aggregates every
  *healthy* node's VMs into one list tagged by node — useful for a
  fleet-wide view, but the wrong tool for the actual question an operator
  has right before (or right after) cordoning a node: "what, specifically,
  is on this one node?" That question needed either grep'ing the
  fleet-wide aggregate client-side (which silently drops a node's VMs
  entirely, with only a server-side `tracing::warn!` the caller never
  sees, if that one node happens to be unreachable — exactly the node an
  operator is most likely asking about mid-maintenance) or bypassing
  `fluxvm-agent` altogether and querying that host's local `fluxctl serve`
  directly (which means already knowing, and having direct network access
  to, that host — the whole point of the fleet registry is not needing
  that). The new route proxies straight to the named node's own
  `GET /v1/vms`, tags each VM with `"node"` the same way the fleet-wide
  list does, and — unlike the fleet-wide list — turns that one node being
  unreachable or erroring into a real `502` naming the node, instead of
  quietly omitting it. Works for any registered node regardless of
  `cordoned`/`healthy` state (an operator checking on a node they just
  cordoned, or one that just went stale, still gets a real answer or a
  real error, never silence). 5 new tests in `fluxvm-agent::central`
  against a real (not mocked) minimal axum server bound to an OS-assigned
  loopback port standing in for the target node's `fluxctl serve` — the
  same shape `fluxvm-container-agent`'s own tests already use for this —
  covering the happy path (VMs returned and correctly tagged with the
  node name), an unknown node name (400, not a panic or an empty list),
  a node that's unreachable (bound-then-dropped listener; 502, not a
  silently empty result), a node whose own `GET /v1/vms` itself errors
  (its status/body is propagated, not swallowed), and a node with zero
  VMs (empty list, not an error). Docs:
  [docs/operations.md — Distributed node-agent](docs/operations.md#distributed-node-agent),
  `FEATURES.md`'s "`fluxvm-agent`" bullet. Same honest limit as the
  cordon feature below: not re-verified against the real
  two-physically-separate-host rig `scripts/test-fleet-agent.sh`
  exercises — that script is unchanged and wasn't re-run against live
  hardware; verification here is the 5 new unit-level tests plus a real
  (if local) Linux build/test/clippy/fmt pass, not a live-fleet run.
- **`fluxvm-agent central` fleet nodes can now be cordoned for planned
  maintenance** — `POST /fleet/nodes/{name}/cordon` and `.../uncordon`.
  Previously the only way to stop new VMs landing on a specific node ahead
  of a reboot/upgrade/decommission was to either stop its `fluxvm-agent
  node` heartbeat client outright and wait out `HEALTHY_WINDOW_SECS` (30s)
  for the central registry to mark it unhealthy — at which point it also
  silently drops out of the fleet-wide `GET /fleet/vms` aggregation and
  `DELETE /fleet/vms/{node}/{id}` still works but the operator has lost
  the node's own reported capacity/VM-count in the meantime — or take the
  whole node offline and lose visibility into it entirely. Neither gives
  a clean "stop scheduling new work here, but keep everything already
  running and keep reporting on it" state, which is the actual maintenance
  workflow a fleet operator needs. New `NodeInfo.cordoned: bool`
  (`#[serde(default)]`, so an existing `fleet-nodes.json` still loads as
  "never cordoned") excludes a node from `pick_best_capacity`'s
  placement candidates regardless of how much free capacity it reports,
  while `GET /fleet/nodes` keeps reporting it (now with a `"cordoned"`
  field) and the fleet-wide `GET /fleet/vms` keeps aggregating its VMs
  exactly as before — cordoning never touches health, capacity reporting,
  or any VM already there. An explicit `POST /fleet/vms {"node": "..."}`
  naming a cordoned node by name still resolves and proxies through
  unchanged — deliberately, matching the same precedent a Kubernetes Pod
  with `spec.nodeName` set already has (it bypasses the scheduler and can
  still land on a cordoned node): cordoning was only ever meant to narrow
  automatic placement's candidate set, never to become a second admission
  check bolted onto every route. A node's own heartbeat (`POST
  /fleet/register`, sent by `fluxvm-agent node` every `--interval-secs`)
  carries no notion of cordoning at all — the node agent has no idea the
  feature exists — so `register`'s handling had to change too: it now
  looks up whether the node already has a `cordoned` flag set before
  overwriting the rest of its `NodeInfo`, instead of blindly re-inserting
  a fresh record (which would have silently un-cordoned every node the
  very next heartbeat, seconds after an operator cordoned it). 9 new unit
  tests in `fluxvm-agent::central`, all against the same pure,
  HTTP-free functions the existing placement tests already use
  (`pick_best_capacity`, plus new `set_cordoned`/`apply_register`/
  `resolve_target` extracted the same way to stay testable without
  standing up a mock node backend): cordoned-node placement exclusion
  even against a node with far more free capacity, the only-registered-
  node-cordoned case, uncordon restoring eligibility, cordoning an
  unregistered name reporting not-found instead of silently no-op'ing,
  a heartbeat preserving an existing cordon while still updating every
  other field, a brand-new node's first-ever heartbeat registering
  uncordoned, and both directions of the explicit-`"node"`-bypasses-
  cordon behavior (a cordoned node targeted by name still resolves; an
  unregistered name still errors). Docs:
  [docs/operations.md — Distributed node-agent](docs/operations.md#distributed-node-agent),
  `FEATURES.md`'s "`fluxvm-agent`" bullet. Not re-verified against the
  real two-physically-separate-host rig `scripts/test-fleet-agent.sh`
  already exercises for the rest of this subsystem — that script is
  unchanged by this commit and wasn't re-run against live hardware; the 9
  new tests are unit-level only, against the same in-process registry
  logic the existing placement tests already cover the same way.
- **`fluxvm catalog` gained CLI parity with the image catalog's REST CRUD** —
  `list`/`add`/`remove`/`rename`/`clone`/`export`/`lock`/`unlock`/`clean`,
  alongside the existing `keygen`/`sign`. The underlying
  `fluxvm_image::catalog` functions (`add_entry`, `remove_entry`,
  `rename_entry`, `clone_entry`, `export_entry`, `set_read_only`,
  `clean_downloads`, `list_with_verification`) already backed all of this
  over REST (`POST/GET/DELETE /v1/images/catalog...`) — the CLI itself had
  never grown past the two offline-signing verbs, so managing a catalog
  without a running `fluxctl serve` (seeding a fresh host before the daemon
  is up, or a script that would rather shell out than depend on an HTTP
  endpoint) had no path at all. Each new subcommand is a thin wrapper
  reading `catalog.path` straight off `--config`/`FLUXVM_CONFIG`, the same
  one-shot-process model `fluxctl pool claim` already uses — works whether
  or not `fluxctl serve` happens to be running against the same
  `state_dir`. `lock`/`unlock` replace the REST route's boolean
  `{"read_only": bool}` body with two verbs, clearer on a command line.
  9 new tests (clap parsing for every new subcommand, including that
  `catalog add` rejects a missing `--source`). Docs:
  [docs/operations.md — Image catalog & signing](docs/operations.md#image-catalog--signing).
- **Warm VM pools now report computed occupancy, not just raw membership** —
  `GET /v1/pools`, `GET /v1/pools/{name}`, `fluxctl pool list`, and
  `fluxctl pool get` previously returned the bare `PoolRecord`: `size` (the
  *target* member count) and `members` (the ids of members currently ready),
  with nothing naming which was which. Telling "fully backfilled" apart
  from "still catching up after a resize or a burst of claims" meant a
  caller had to already know, unprompted, to compare `members.len()`
  against `size` itself — and there was no visibility at all into how
  heavily a pool had actually been used over its lifetime, which is the
  other half of knowing whether it's sized right. New `PoolView`
  (`fluxvm-core::model`), a `#[serde(flatten)]` wrapper around `PoolRecord`
  adding two computed fields — `ready` (`members.len()`) and `pending`
  (`size` minus `ready`, saturating so a pool briefly over target
  mid-shrink reports 0 rather than an underflowed `usize`) — plus a new
  persisted `PoolRecord.claimed_total: u64`, a lifetime counter of
  successful `claim_from_pool` calls, bumped via a new
  `PoolStore::increment_claimed` right after a claim has already fully
  succeeded (member resumed, and tenant-checked when the caller's token
  carries one) — best-effort and fail-open the same way `delete_pool`'s own
  member cleanup is, so a stats-increment failure can never turn an
  already-completed claim into an error for the caller who just received
  their VM. `#[serde(default)]` on the new field so a `pools.json` written
  before this existed still loads cleanly (as 0, the honest "unknown
  history" value). All four pool-returning routes (`create`, `list`, `get`,
  `resize`) and both CLI print sites (`pool list`/`get`, which read
  straight off the same local `VmManager` the server uses, not through
  HTTP) now go through `PoolView` — purely additive, no existing field
  renamed or removed. 9 new tests (4 `fluxvm-core` unit tests on `PoolView`
  covering the ready/pending arithmetic, the saturating-at-target-exceeded
  case, and that the flatten doesn't shadow a persisted field; 2
  `fluxvm-storage` unit tests on `increment_claimed`, including the
  pool-deleted-concurrently no-op case; 1 `fluxvm-api` router test
  asserting `ready`/`pending`/`claimed_total` on both the list and
  by-name routes). Docs: `FEATURES.md`'s "Warm VM pools" bullet.
- **Warm VM pools can now be resized after creation** —
  `POST /v1/pools/{name}/resize` (admin-only, body `{"size": N}`) and
  `fluxctl pool resize <name> --size N`. Previously `PoolSpec::size` was
  fixed for the life of a pool: an operator whose real load outgrew (or
  shrank below) a pool's original size had no way to change it short of
  `DELETE`-ing the pool outright and `POST`-ing a new one from the same
  spec, discarding every still-ready warm member in the process just to
  change one number. New `VmManager::resize_pool` and
  `PoolStore::set_size` (`fluxvm-scheduler`/`fluxvm-storage`). Growing
  only updates the stored target and fires the same background
  `spawn_backfill` `create_pool`/`claim_from_pool` already use — the
  reaper's per-tick top-up is the same backstop for a resize as it is for
  those two, so nothing new was needed there. Shrinking is handled
  synchronously instead: excess ready members are popped and deleted
  immediately, fail-open per member (a single stuck delete is logged and
  skipped, matching `delete_pool`'s own best-effort cleanup) rather than
  left for the next reaper tick — asking for a smaller pool is asking to
  give resources back, and the reaper itself only ever grows a pool
  toward its target, never shrinks it, so an under-trimmed shrink simply
  stays put rather than drifting back up. Both directions serialize
  against the same per-pool `backfill_locks` mutex `backfill_pool` itself
  already uses, so a resize can't race a concurrent reaper-triggered (or
  claim-triggered) backfill into an inconsistent membership count. Tenant
  scoping matches every other name-keyed pool route (`get`/`delete`/
  `claim`): a mismatched tenant's token gets the same 404
  `pool_visible_to` already returns for those. 10 new tests (2
  `fluxvm-storage` unit tests on `set_size`, 4 `fluxvm-scheduler` unit
  tests on `resize_pool` covering zero-size rejection, an unknown pool,
  growing, and shrinking down to and past actual membership, 4
  `fluxvm-api` router tests covering the REST route's tenant scoping,
  admin-only enforcement, and validation). Docs: `docs/api.md`'s pools
  section, `docs/operations.md`'s "Warm VM pools" section (with an
  explicit "Real limits today" noting this has not yet been exercised
  against real hardware the way the rest of that section has been —
  `scripts/test-warm-pool.sh` doesn't cover it), `FEATURES.md`.
- **REST API rate limiting** — `auth.rate_limit_rps`/`auth.rate_limit_burst`
  (opt-in, both must be set together). Closes a real gap: `fluxvm-api`
  had no request-volume limiting at all, in either the network-dataplane
  sense (`[[policy.tenants]]`/per-VM Mbps/PPS limits already exist there)
  or the control-plane sense — a single caller holding one valid token
  could issue unbounded requests with nothing to push back. New
  `fluxvm-api::rate_limit::Limiter`, a small hand-rolled per-key token
  bucket (no new dependency), keyed by the same actor identity the audit
  log already attributes a request to (token name, OIDC subject, mTLS
  cert CN, or `"anonymous-admin"` on an unauthenticated loopback
  deployment) rather than raw connection volume — two callers sharing
  one token share one bucket by design. Runs after auth (so every
  request it sees already carries that identity) and before the
  per-tenant scope guard, with its own explicit bypass for `/healthz`/
  `/readyz` (auth only skips resolving an identity for those two, it
  doesn't stop them reaching the layers below it) so a probe can never
  be starved by a caller's own throttling. A throttled request gets `429` with
  `Retry-After` set. Absent by default: no rate limiting at all,
  byte-for-byte the behavior before this existed. Docs:
  `docs/operations.md`'s "REST API rate limiting" section.
- **AppArmor local-include for `swtpm` on Debian/Ubuntu** —
  `packaging/apparmor/usr.bin.swtpm.fluxvm`. Found by actually driving a
  real `fluxctl create` call with `tpm: true` through the compiled binary
  on a real Ubuntu host (not just the argument-syntax smoke test the
  Secure Boot/vTPM change shipped with): the distro's own `swtpm` package
  ships an AppArmor profile confining it to libvirt's conventional paths,
  with nothing for FluxVM's own `<state_dir>/instances/<id>/` workspace,
  so `spawn_swtpm` fails closed with a permission error on any host
  where that profile enforces (the common case). The snippet extends the
  packaged profile via its own already-present `#include
  <local/usr.bin.swtpm>` hook — Debian/Ubuntu's supported mechanism for
  this, never edits the package-owned file itself. Not live-verified
  end-to-end in this session (installing it edits a host's live security
  policy, deliberately not done here without separate authorization) —
  see `docs/secure-boot-tpm.md`'s "Real limits" for the honest framing
  and the diagnosed-but-unverified distinction.
- **Stronger image catalog signatures** — the Ed25519 signed payload now
  covers `distro`/`version`/`arch` and a new tamper-evident `signed_at`
  timestamp, not just `name`/`source`/`sha256`/`format`. Previously
  `distro`/`version`/`arch` were present on a `CatalogEntry` but excluded
  from what was actually signed, so they could be edited in `catalog.json`
  post-signing (e.g. relabeling `arch` to mislead a platform-matching
  consumer) without invalidating the signature — a real gap, closed here.
  `read_only` stays deliberately unsigned (a mutable operational flag
  toggled via its own REST route, not provenance data). `[[catalog.trusted_signers]]`
  is now a named list (`name`/`public_key`, the same `[[auth.tokens]]`-shaped
  convention this project already uses for labeled credential lists)
  instead of a bare list of base64 keys, so `GET /v1/images/catalog`'s
  new `signed_by` field can report real signer identity — the *name* of
  whichever configured key actually verified the signature, derived
  fresh on every call from which key matched, never trusted from
  anything the entry itself claims about its own signer. **Breaking
  change**: an entry signed before this existed will fail verification
  against the wider payload; re-run `fluxvm catalog sign` for every
  entry after upgrading if `trusted_signers` is configured. Does not
  close the deeper "no real build-lineage/CI-provenance recording" gap —
  see FEATURES.md's Security Posture table for what's still genuinely
  open there. Docs: `docs/operations.md`'s "Image catalog & signing"
  section.
- **Per-tenant aggregate admission quotas** — `[[policy.tenants]]`
  (`tenant`, `max_vcpus_total`, `max_memory_mib_total`, `max_vms_total`),
  summed across every existing VM a tenant already owns plus the incoming
  request, matched against `CreateVmRequest.tenant` (already authoritative
  by the time `fluxvm-scheduler` sees it — resolved by `fluxvm-api` from
  `[[auth.tokens]]`'s own `tenant` field or an OIDC claim). Closes a real
  gap: `[policy]`'s existing fields (`max_vcpus`, `max_memory_mib`, etc.)
  only ever validate one incoming request in isolation, with no way to cap
  how much a tenant accumulates across many VMs over time. New
  `fluxvm-scheduler::validate_tenant_policy`, called from `VmManager::create`
  right after the existing per-request `validate_policy`, only when the
  request has a `tenant` set and at least one `[[policy.tenants]]` entry
  exists — a full `Store::list()` scan is skipped entirely otherwise, so
  hosts that don't use this pay nothing extra per create. The aggregate,
  fleet-wide counterpart to Kairon's own `MachineQuota` CRD (a sibling
  project). 6 new unit tests. Docs: `docs/operations.md`'s "Policy" section.
- **UEFI Secure Boot (QEMU) + emulated vTPM 2.0 (QEMU and Cloud
  Hypervisor)** — `CreateVmRequest.secure_boot`/`.tpm`, with deliberately
  different scope per field: `tpm` works on both backends, `secure_boot`
  is QEMU-only, permanently — not "not implemented yet" on Cloud
  Hypervisor. Cloud Hypervisor's own `--firmware` is a single opaque file
  with no documented separate variable store to enroll Secure Boot keys
  into and no documented enforcement mechanism (confirmed against Cloud
  Hypervisor's own `docs/uefi.md`/Windows-guest docs) — claiming support
  there would be dishonest, not just unimplemented, so it's rejected
  outright. Also fixes a real, independent pre-existing gap:
  `CreateVmRequest.firmware` already existed and Cloud Hypervisor already
  wired it correctly, but the QEMU backend never read it at all despite
  `docs/tiny-windows.md`/three `examples/*.json` setting it on QEMU-backend
  requests — those silently fell back to QEMU's default BIOS. Now wired as
  split code/vars pflash (`-drive if=pflash,...unit=0,readonly=on` +
  `...unit=1` for a per-VM writable `<workspace>/ovmf_vars.fd` copy of a
  new `Config::qemu_ovmf_vars_template`, plus `smm=on`/
  `driver=cfi.pflash01,property=secure,value=on`) — the prerequisite
  Secure Boot itself needs. `tpm: true` spawns a shared `swtpm` sidecar
  (`fluxvm_core::process::spawn_swtpm`, reused by both backends; mirrors
  the existing `virtiofsd` spawn/wait/kill-on-failure pattern, whose
  readiness-poll loop was extracted into `wait_for_socket_ready` for
  reuse) — QEMU wires `-tpmdev emulator` + `-device tpm-crb`; Cloud
  Hypervisor wires its own, simpler `--tpm socket=<path>` (confirmed
  against a real `cloud-hypervisor --help`, v53.0). TPM state persists
  under `<workspace>/tpm/` for the VM's lifetime, independent of the
  sidecar process's own per-launch lifecycle. Both fields are rejected
  outright at `create()` time on a backend that doesn't support them
  (unlike `vfio_devices`/`numa_node`, which those backends silently
  ignore) — a caller believing they got Secure Boot/measured boot when
  they silently didn't is a real, security-relevant footgun. Real unit
  coverage for both backends' `build_args` argument construction; the
  `swtpm`/OVMF-vars-copy process-spawning glue has no dedicated unit test
  of its own (the same pre-existing gap `spawn_virtiofsd_instances` itself
  already had). Docs: [`docs/secure-boot-tpm.md`](docs/secure-boot-tpm.md).
- **QGA: `guest-network-get-interfaces`** — `GET /v1/vms/{uuid}/qga/network-interfaces`
  (read-only, no `admin` role required unlike the other `qga/*` routes)
  returns the guest's own reported interfaces/IPs via the real
  `qemu-guest-agent` protocol. Unlike `guest_ip`, which only ever comes from
  parsing a dnsmasq DHCP lease file (`NetworkSpec::Tap { netns: true }`
  only — `None` for every other network mode, `User`/SLIRP included), this
  works for any network mode the guest agent can reach. Verified against a
  real running VM under `network.mode = "user"` (SLIRP), which has no lease
  file at all: the guest's own real SLIRP-assigned address (`10.0.2.15`)
  came back correctly.
- **QEMU backend: real CPU/memory hotplug** — `POST /v1/vms/{uuid}/hotplug/cpu`
  (`add_vcpus`) and `POST /v1/vms/{uuid}/hotplug/memory` (`add_memory_mib`),
  QEMU-only. CPU hotplug fills unrealized `query-hotpluggable-cpus` slots via
  `device_add` in deterministic `(socket-id, core-id, thread-id)` order;
  memory hotplug attaches a `pc-dimm` backed by a fresh `memory-backend-ram`
  object, rolling the backend object back if the `device_add` fails. Both use
  the hotplug headroom (`-smp maxcpus=`, `-m slots=/maxmem=`) every QEMU VM
  has reserved since `max_vcpus`/`max_memory_mib` were added — this wires up
  the actual `device_add`/`object-add` calls that headroom existed for but
  nothing in this repo previously issued. Verified against a real running VM
  (`query-cpus-fast`/`query-memory-devices` independently confirm the new
  vCPU thread and DIMM). Docs: [`docs/api.md`](docs/api.md).
- **Docs: next-features backlog** — ranked Sentinel / hypervisor / Fabric
  follow-ups after Set 15 + FC/CH parity ([`docs/NEXT-FEATURES.md`](docs/NEXT-FEATURES.md)).
- **Secure Containers Set 15** — directional attachment health for
  `fluxvm_pod_ingress` (`pod_ingress_required` / `pod_ingress_attached` on
  `NativeAttachmentStatus`; aggregate `attached` requires both hooks when
  ingress is pinned); read-only Sentinel Policy Observer
  (`tools/fluxvm-policy-observer`) exporting Pod-policy counters and
  hook/rule pressure on `:9091`. Docs:
  [`docs/secure-containers-set15.md`](docs/secure-containers-set15.md).
- **In-tree KVM FC/CH parity (P0–P2)** — virtio-mmio vsock/balloon/rng with
  `KVM_IRQFD`; auto `virtio_mmio.device=` cmdline; token-bucket net/blk
  rate limits; optional vhost-net open; ACPI RSDP/XSDT/FADT/MADT + PVH
  `rsdp_paddr`; jailer (`--jailer` / `FLUXVM_JAILER`); PCI ECAM (`--pci`);
  `FLUXKVM1` snapshot v2 (all vCPUs). P3 stubs for virtio-fs / migration /
  hotplug. Boot hang past `init_zbud` resolved; guests mount `vda` and reach
  `/sbin/init`. Docs: [`crates/fluxvm-hypervisor/README.md`](crates/fluxvm-hypervisor/README.md),
  [`docs/agent-sandbox-gaps.md`](docs/agent-sandbox-gaps.md),
  [`docs/kvm-density.md`](docs/kvm-density.md).
- **Secure Containers Set 5** — authenticated VSOCK stdio streaming on port
  17779 (lifecycle stays on 17778); guest pipes for non-TTY I/O; real guest
  PTY for `terminal=true` init/exec with `ResizePty`/`CloseIO`; output drain
  before TaskExit/Wait/Delete; legacy virtiofs stdio via
  `FLUXVM_CONTAINER_STREAMING_STDIO=0`; `scripts/e2e-secure-containers-tty.sh`.
  Docs: [docs/secure-containers.md](docs/secure-containers.md),
  [docs/secure-containers-set5.md](docs/secure-containers-set5.md).
- **Secure Containers Set 4** — Pod-UID-scoped write-through kubelet `volumes/` /
  `volume-subpaths/` virtiofs exports with bind-source rewrite; guest OCI
  security (read-only rootfs, masked/RO paths, device nodes, sysctls,
  libseccomp syscall-name rules fail-closed); mount rollback on create failure;
  `scripts/e2e-secure-containers-volume.sh`. Docs:
  [docs/secure-containers.md](docs/secure-containers.md),
  [docs/secure-containers-set4.md](docs/secure-containers-set4.md).
- **Secure Containers Set 3** — containerd task lifecycle events (create/start/
  exec/pause/resume/exit/delete) with async Wait watchers and exit
  de-duplication; definitive delete metadata; init/exec process separation;
  retry-safe staging cleanup; guest OCI process hardening (supplementary GIDs,
  umask, rlimits, `noNewPrivileges`, capability sets). Docs:
  [docs/secure-containers.md](docs/secure-containers.md),
  [docs/secure-containers-set3.md](docs/secure-containers-set3.md).
- **Secure Containers Set 2** — CNI L2 Pod-IP path (QEMU TAP on the prepared
  host bridge when a CRI netns is present; `FLUXVM_CONTAINER_CNI=0` disables),
  guest cgroup-v2 resource limits/stats/pids/update + sandbox resource config,
  shim `Stats`/`Update`/`Pids` wiring, VM shape from resource hints. Docs:
  [docs/secure-containers.md](docs/secure-containers.md).
- **Secure Containers (containerd runtime-v2)** — developer-preview foundation:
  `fluxvm-container-protocol` / `fluxvm-container-agent` / `fluxvm-container-client` /
  `fluxvm-containerd-shim` (`containerd-shim-fluxvm-v2`, runtime
  `io.containerd.fluxvm.v2`); virtiofs Pod share + VSOCK lifecycle on :17778;
  `deploy/containerd/`, install/test/e2e scripts, CI workflow
  `.github/workflows/secure-containers.yml`. Docs:
  [docs/secure-containers.md](docs/secure-containers.md). QEMU-only; hostPath
  hotplug and broader CNI/OCI namespace parity remain follow-up gates
  (Sets 4–5 cover Pod-UID volumes and VSOCK stdio/TTY).
- **Service Fabric full mesh datapath (Fabric-side)** — remote backends merge into
  existing Maglev `/v1/network/services` upserts (lifecycle v2: weighted drain +
  optional VIP match; no new FluxVM tunnel APIs; Geneve/VXLAN still N/A). See
  Fabric `service-lb::remote_backend`.
- **Service Fabric gen8 connect** — cgroup/connect6 + Maglev affinity parity with TC
  (`fluxvm_fct4`/`fct6`); `cgroup_connect` attaches both v4 and v6; program generation **8**
  (schema 4 unchanged).
- **Service Fabric map-tier ELFs** — `-DFLUXVM_MAP_TIER=S|M|L` objects
  (`fluxvm_service*_tier_{S,M,L}.bpf.o`); `map_tier` selects loader path + catalog limits.
- **Service Fabric SLO harness** — `scripts/test-service-fabric-slo.sh` + optional
  `SLO_VIP_P99_MS` / `SLO_PRESSURE_IDLE` / `SLO_REQUIRE_CHANNELS` / `SLO_CI_SHAPE` gates.
- **Service Fabric universal CI SLO defaults** — `SLO_CI=1` applies VIP p99 /
  pressure / EDT fairness / HA failover RTT / Mpps floors; RSS under-load PPS via
  `scripts/test-service-fabric-rss.sh` (`SLO_RSS_PPS_MIN`, soft-skip without VIP).
- **Service Fabric lab Mpps / CPU ceilings** — `SLO_LAB=1` /
  `scripts/test-service-fabric-lab.sh` raises connect Mpps floor to `0.05`, adds
  packet Mpps (`SLO_PKT_MPPS_MIN=0.10`) + fluxvm CPU ceiling (`SLO_CPU_MAX_PERCENT=85`)
  during storm; CI floor unchanged at `0.01`.
- **Remote ipcache ingest** — `POST/DELETE /v1/network/ipcache/remote` for Fabric
  ClusterMesh-like identity fan-out (local VM rows preserved).
- **Service Fabric gen7 ops tranche** — opt-in cgroup/connect4 (`fluxvm_service_connect.bpf.o`),
  map pressure controller (`POST /v1/network/services/pressure/reconcile`), XDP
  native→generic attach + ethtool offload/channels in `services/status`, perf lab
  `scripts/test-service-fabric-perf.sh`; program generation **7** (schema 4 unchanged).
- **Service Fabric v6** — identity/L7 service policy maps (`fluxvm_spol`/`sid4`/`sid6`),
  Envoy transparent-proxy redirect contract, HA mutation queue drain (`fluxvm_haq`);
  ABI stays schema **4**, program generation **6**. See `docs/service-fabric-v6-phase6.md`.
- **Windows Kryton golden path** — sibling [Kryton](https://github.com/zyvorai/kryton)
  builds sysprepped qcow2; `scripts/prepare-windows-golden.sh` installs under
  `/var/lib/fluxvm/images/`; docs [`windows-golden.md`](docs/windows-golden.md) /
  [`tiny-windows.md`](docs/tiny-windows.md); examples `build-image-kryton-golden.json`,
  Tiny11 QGA/TAP; gated smokes accept `KRYTON_WINDOWS_IMAGE`.
- **In-tree KVM memory snapshots (Phase 3c)** — paused `FLUXKVM1` mmap dump +
  GPRs/sregs; restore via control API. Lab-only (not Firecracker-compatible).
  Smoke: `scripts/test-kvm-snapshot-smoke.sh`.
- **Cilium agent CEP identity (Phase 2b)** — when `mode=cilium`, enrich
  CiliumEndpoint views from agent HTTP (`identity_source=cilium-agent`); still
  never writes Cilium private maps.
- **Concurrent density bench** — `scripts/bench-density.sh` (parallel keep-alive
  creates + p50/p95).
- **MicroVM Prometheus histograms** — create→Scheduled / schedule→Running /
  create→Running on `MICROVM_METRICS_ADDR` (default `127.0.0.1:9108`).

### Changed
- **MicroVM dual-run hardening** — shadow Pods request `10m`/`32Mi` (not guest
  vCPU/RAM); converted MicroVMs annotate
  `microvm.fluxvm.zyvor.io/driven-by=fluxvm-kube` so the node agent skips
  `POST /v1/vms`; deploy controller leaves `--convert` off (opt-in). Policy
  gates: `scripts/test-microvm-policy.py`.
- **GuestImage Ready** — node reconciler marks Ready when `spec.source` is a
  host file; MicroVM `spec.image` can resolve a same-namespace GuestImage name
  (still no CDI pull). Docs/tutorials: [docs/tutorials/microvm/05-guestimage.md](docs/tutorials/microvm/05-guestimage.md).
- **Lab performance publish** — `scripts/bench-microvm.sh` + refreshed
  [docs/benchmarks/README.md](docs/benchmarks/README.md) (2026-09-08 sandbox
  avg_create **5444** ms; MicroVM p50_running **2736** ms).
- **MicroVM production deploy path** — `deploy-remote` installs
  `fluxvm-microvm`/`fluxvm-kube`; DaemonSet `FLUXVM_TOKEN` from Secret;
  `publish-image.yml` for GHCR; CI MicroVM gates; dataplane e2e uses bearer
  auth; Job/Pool in k8s smoke; GuestImage/Pool printer columns.
- **rustls CryptoProvider** — `fluxvm-microvm` / `fluxvm-kube` install `ring`
  before kube TLS clients (rustls 0.23).

### Added
- **MicroVM** (`fluxvm-microvm`) — Kubernetes-native disposable compute without
  KubeVirt: `MicroVM` / `MicroVMJob` / `MicroVMPool` / `GuestImage` on
  `microvm.fluxvm.zyvor.io`, shadow-Pod capacity tickets, cluster controller +
  node agent against local `fluxctl serve`, optional `DisposableVm` → `MicroVM`
  conversion. Docs: [docs/microvm.md](docs/microvm.md). Manifests:
  `deploy/k8s/microvm/`. Tests: `cargo test -p fluxvm-microvm` /
  `scripts/test-microvm.sh`. (Formerly internal aether design.)
- Hubble-style **packet flow** renderer: hop path (guest → tap → tc/eBPF →
  uplink → peer), `--output color|plain|json`, `fluxctl hubble flow` detailed
  view, `/v1/network/hubble/flows/text`, and a Colorful/Normal Hubble-lite UI
  ([docs/packet-flow.md](docs/packet-flow.md)).
- DevOps pack paired with Fabric: probe contract
  (`docs/contracts/fabric-fluxvm-readyz.json`), `scripts/devops-gate.sh`,
  `scripts/upgrade-snapshot.sh` for N→N+1 state_dir snapshots, kustomize
  wrapper `deploy/k8s/gitops`, CI workflow `devops-gates.yml`, and
  [docs/DEVOPS.md](docs/DEVOPS.md).
- **Four-track production** — OIDC already shipped; mTLS header identity
  (`X-Client-Cert-*` when `[tls].client_ca` set); CiliumEndpoint views +
  Hubble-lite UI/flows; Cloud Hypervisor `qga.enabled` serial socket;
  in-tree KVM `FLUXVM_KVM_LOCK_MEM=1` (MAP_POPULATE+mlock).
- **OIDC JWT validation** — `auth.oidc_issuer` + `auth.oidc_audience` enable
  discovery/JWKS bearer validation alongside `[[auth.tokens]]` (role/tenant claims).
- **API TLS / mTLS** — optional `[tls]` cert/key; `tls.client_ca` requires client certs.
### Added
- **In-tree KVM virtio-blk (Phase-2 start)** — attach `cfg.disk` / rootfs as
  virtio-mmio block at `0xFEB00200` with sector R/W; cmdline advertises both
  MMIO slots.
- **In-tree KVM linux-loader** — bzImage/ELF load via `linux-loader`, zero-page
  `boot_params` (cmdline/initrd/e820), RSI set for 64-bit boot protocol;
  raw-dump fallback if parse fails.
- **In-tree KVM CPUID + boot smoke** — `KVM_SET_CPUID2` so Linux can run;
  `--kernel`/`--disk` use `from_boot_config`;
  `scripts/test-kvm-linux-boot-smoke.sh` checks for `Linux version` on serial.
- **In-tree KVM root mount** — Firecracker-style e820, MP table, CMOS RTC,
  PIT2, virtio IRQ pulse; lab reaches `EXT4-fs (vda)` / `VFS: Mounted root`.
- **In-tree KVM userspace** — do not stop the VMM at root mount; smoke uses
  a ttyS0 probe init and passes on `FLUXVM_USERSPACE_OK` /
  `FLUXVM_PROMPT_READY`.
- **In-tree KVM serial console** — 16550 RX queue, IIR/LSR, COM1 IRQ 4 pulse
  for interactive UART; smoke injects `/userspace-probe.sh` onto a temp rootfs.
- **In-tree KVM serial stdin** — host stdin → UART RX; `FLUXVM_SERIAL_INJECT`
  one-shot after userspace; smoke checks `FLUXVM_STDIN_OK:ping`.
- **In-tree KVM pause/resume** — park vCPU (no `KVM_RUN` while paused);
  `scripts/test-kvm-pause-smoke.sh`. Memory snapshots remain Firecracker-only.
- **Lab verify scripts** — `scripts/test-lab-four-tracks-e2e.sh`,
  `scripts/test-lab-regression.sh`, `scripts/test-lab-verify.sh` for post-deploy
  four-track + regression gates on a KVM host (also runs devops units, live
  `devops-gate`, and `upgrade-snapshot`; stdin closed for SSH-safe serial smokes).
- **DevOps gate TLS** — `scripts/devops-gate.sh` uses `curl -k` and auto-picks
  Fabric HTTPS then HTTP when `FABRIC_URL` is unset.
- **Sandbox bench image paths** — `scripts/bench-sandbox.sh` honors `IMAGE` /
  `FLUXVM_BENCH_IMAGE` with lab fallbacks (`bionic-fabric-rootfs.ext4`, etc.).
- **CH Windows boot (Phase-1)** — `hyperv: true` → `kvm_hyperv=on`;
  `examples/windows-ch.json`; CH QGA host path via serial socket
  ([ch-windows-qga.md](docs/ch-windows-qga.md)); named virtio-serial remains QEMU-only.
- **Density roadmap** — [ROADMAP-DENSITY.md](docs/ROADMAP-DENSITY.md): KVM boot +
  pause + lock-mem Done; CEP-*shaped* Hubble-lite Done; real Cilium-agent CEP
  and kvm memory snapshots stay Not started / FC-only.
- **Project production baseline** — `SECURITY.md`, `CONTRIBUTING.md`,
  `Makefile`, whole-stack [docs/PRODUCTION.md](docs/PRODUCTION.md),
  `/readyz` (HTTP 503 when not ready), VM `tenant` + `GET /v1/vms?tenant=`,
  token `tenant` (authoritative create + scoped list/get/mutate),
  `scripts/release-checklist.sh`.
- **Production dataplane** — FQDN→IPv4/IPv6 resolve at apply, FluxVM ipcache,
  `GET /v1/network/health|/ipcache`, `POST /v1/network/refresh-dns`,
  `fluxvm dataplane health|ipcache|refresh-dns`, prod TOML + runbook
  ([docs/production-dataplane.md](docs/production-dataplane.md)).
  Tests: `scripts/test-production-dataplane.py`,
  `scripts/test-production-dataplane-e2e.sh`.
- **Network policy (Fabric v4)** — CNP compiler (`toCIDR`,
  `toCIDRSet`, `toEntities`, `toFQDNs`, `toPorts` ranges/named ports, deny,
  `enableDefaultDeny`, `auditMode`), reserved identities, `fluxvm_gid`
  updates, conntrack learn/hit, `fluxvm cnp` / `fluxctl identity` /
  `fluxctl observe`, REST `/v1/network/cnp`, `/v1/network/identities`,
  `/v1/network/observe`.
  Docs: [docs/network-policy.md](docs/network-policy.md).
  Tutorials: [docs/tutorials/network-policy/](docs/tutorials/network-policy/README.md).
  Tests: `scripts/test-network-policy.py`;
  e2e via `scripts/test-security-groups-e2e.sh`,
  `scripts/test-production-dataplane-e2e.sh`.
- **Security groups** — label identities for the VM-edge
  dataplane. Named groups with `key=value` labels allocate a stable
  identity in the `0x10000+` range; VM policy `groups` / `labels` select
  membership; allow + deny CIDRs merge into the TC maps. REST
  `/v1/network/groups` and `/v1/vms/{id}/network/effective`, CLI
  `fluxvm group`. BPF `fluxvm_gid`, `fluxvm_ct`, `fluxvm_deny4/6`,
  ICMP passthrough, `icmp/0` L4 rules.
  Docs: [docs/network-groups.md](docs/network-groups.md).
  Tests: `scripts/test-security-groups.py`,
  `scripts/test-security-groups-e2e.sh`.

- **Fleet agent hardening** — bearer auth (`--token`), optional TLS (`--tls-cert`/`--tls-key`), persisted `fleet-nodes.json`, residual CPU/memory placement.
- **Kubernetes CRD** — `tap`/`macvtap` fields (`bridge`, `parent`, `netns`, …); optional `spec.node` + `fluxvm-kube --enable-placement`; DaemonSet packaging documented; CI container image build.
- **Security boundary** — fail-closed auth off-loopback, JSON audit logs (`fluxvm_audit`), `allowed_network_modes` / `allow_extra_args` policy, per-token VM/memory quotas, seccomp-bpf (Linux), AppArmor profile, UDS `0o600`, optional cosign catalog verify.
- **Network** — netns NAT via nftables, real IPAM (`ipam.json`), egress allowlist wired to dataplane, auto L7 redirect when proxy listen is set.
- **Snapshots** — QEMU QMP `savevm` + Cloud Hypervisor `ch-remote snapshot`; `POST /v1/vms/{id}/snapshot`.
- **Sandbox** — `fluxvm_engine = "kvm"` (no Firecracker child), multi-port proxy defaults, native TC/eBPF dataplane (`legacy`/`ebpf`/`cilium`, default nftables), bench script + docs.
- **eBPF / Cilium / Network Fabric v1** — TC L3+L4 allowlists, per-VM policy API (`/v1/vms/{id}/network/{policy,stats,flows}`), optional XDP node guard, flows/stats maps; modes `legacy`/`ebpf`/`cilium` (default nftables); docs: [docs/network-fabric.md](docs/network-fabric.md), [docs/ebpf-cilium.md](docs/ebpf-cilium.md).
- **Network Fabric v2** — Mbps/PPS egress limits, fail-closed live policy reconfigure, `GET /v1/vms/{id}/network/status`, native attach without known guest IP, `scripts/validate-network-fabric.sh`.
- **Network Fabric v3 GA** — IPv4/IPv6 TC+XDP policy, schema versioning + policy fingerprints, TC/XDP program-ID ownership, pre-attach map config, orphan pin reconcile, NDJSON flow exporter (`scripts/export_network_flows.py`).
- **Windows** — `unattend_path` / `sysprep` on `build-image` `windows{}`.
- **QEMU placement** — optional `numa_node`, `cpuset`, `hugepages`, `vfio_devices` on create.
- Richer Prometheus metrics (auth/egress denies, create/start latency).

### Fixed
- **TLS / mTLS serve** — install rustls `ring` CryptoProvider before binding so
  `[tls]` / `client_ca` no longer panic on rustls 0.23 feature detection.
- **CH QGA gate** — allow `qga.enabled` on `cloud-hypervisor` (serial socket),
  not only QEMU virtio-serial.
- **eBPF smoke** — `scripts/test-ebpf-smoke.sh` uses dual netns and one persistent
  `ip netns exec` session so policy/XDP checks work on hosts where same-netns
  `ping -I` fails and `/sys` remounts drop bpffs pins across separate execs.

### Changed
- Docs/README refreshed for Network Fabric **schema v4** (groups, CNP, observe,
  health/ipcache/FQDN refresh, production runbook, tutorials) while keeping
  historical v1–v3 notes; architecture, L4/IPv6/rate limits, REST status/schema,
  XDP, `LimitMEMLOCK`, dual-netns smoke/e2e, and vs-traditional comparison remain.
- Docs/tutorials for project production: `/readyz`, token/VM `tenant`,
  [docs/tutorials/production/](docs/tutorials/production/README.md),
  auth exceptions, and links from [PRODUCTION.md](docs/PRODUCTION.md).
- **Network Fabric v3 GA ship** — `configs/network-fabric-ga.toml` +
  `scripts/enable-network-fabric-ga.sh`; `required=true` fail-closes only when a
  host-visible VM edge exists (user NAT / `mode=none` soft-skip).

## 0.3.0

### Added
- **Windows offline customize** — a `windows{}` block on `build-image` (RDP/WinRM/firewall/scripts + Zyvor GuestKit agent inject), via GuestKit registry plans and `inject_windows_agent` (needs host `libhivex`/`hivex-devel` and guestkit's `registry-write` + `agent` features). Linux-only fields (`packages`, `commands`, `enable_services`, `ssh_key`, top-level `hostname`) can't be combined with it.
- **Live QGA control** — QEMU virtio-serial guest-agent CLI/REST for PowerShell and firewall rules after boot: `fluxctl qga ping|powershell|exec|firewall-open|firewall-close`, mirrored at `POST /v1/vms/{id}/qga/ping|exec|firewall/open|firewall/close`.
- Gated offline smoke test: `scripts/test-windows-customize.sh`.
- Client presentation decks (`docs/client-presentations/`).

## 0.2.0

### Added
- **VNC** for every QEMU-backed VM via a unix socket — no port allocation.
- **Interactive console/shell** — `GET /v1/vms/{id}/console` (WebSocket) and the guest agent's `OpenShell` vsock op for a real PTY.
- **File transfer** — `PutFile`/`GetFile` guest-agent vsock ops (`POST /v1/vms/{id}/agent/{put,get}-file`).
- **virtiofs shared folders** (QEMU backend).
- **True suspend-to-disk resume** (`-loadvm`) and a virtio-scsi controller.
- **Static-IP netns mode** — the guest gets a real DHCP-leased IP, with deterministic address reservation.
- **`GET /v1/vms/{id}/cpuset`**.
- **Kubernetes DaemonSet packaging** (`fluxvm-kube`).
- Catalog: read-only flag and orphaned-download cleanup.
- Cross-distro CI job, build-image tutorials, and a real-hardware boot smoke test.
- Multiple hypervisor backends: `fluxvm-hypervisor`, `fluxvm-cloud-hypervisor`, `fluxvm-firecracker` (alongside the existing QEMU backend).

### Changed
- **Image customization now goes through GuestKit** instead of virt-customize/libguestfs.
- Renamed Ephemera to FluxVM; added an agent-sandbox track.
- `KillMode=process` on the systemd unit, so a daemon restart/upgrade no longer SIGTERMs every running VM's QEMU process.

### Fixed
- CPU/memory hotplug (no reserved PCIe root port slots) and NIC hotplug (missing `bridge.conf`) — hotplug now actually attaches.
- Usermode-network hostfwd bound to `127.0.0.1` instead of `0.0.0.0`.
- Guest agent `OpenShell`: isolated into a double-forked process, never reaped its own shell child, fixed `EPERM` on `TIOCSCTTY`, added `PrivateTmp` for disk provisioning.
- Dockerfile build failure (stale Rust pin, missing `--locked`).
- `-nodefaults` was dropping the implicit VGA card — added explicit `-vga std`.
- `ephemera-image` (now the image crate) mounts guest fstab entries shallowest-first.
- systemd: grant `CAP_SYS_CHROOT` for GuestKit's image-customization chroot, `CAP_SYS_ADMIN` and a writable `/var/lock` for disk provisioning.
- systemd: `/sys/fs/cgroup/fluxvm.slice` creation failed with `Permission denied` despite running as root — the unit's capability set didn't include `CAP_DAC_OVERRIDE`, so root's usual DAC bypass against the cgroupfs's `dr-xr-xr-x` mode didn't apply. Found live: every VM start/restart since a host reboot left `VmRecord.cgroup_path` null, breaking memory limit/usage and any other cgroup-based resource control.
- systemd: `RuntimeDirectory=fluxvm`/`StateDirectory=fluxvm` replace a plain `ExecStartPre mkdir` for `/run/fluxvm` — the old approach raced ProtectSystem's namespace setup and failed with `226/NAMESPACE` on every fresh boot (`/run` is a tmpfs, wiped every reboot).
- cloud-init: `write_files` support in `CloudInitSpec`.
- Test fixtures: added `shared_folders`/`virtiofsd_pids` to the storage test fixture.
- Fixed the pacman branch of the GuestKit package install and hardened its regression test.

## 0.1.0

- Initial release.
