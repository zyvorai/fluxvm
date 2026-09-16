# Changelog

## 0.4.0 (unreleased)

### Fixed
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
  real `fluxvm create` call with `tpm: true` through the compiled binary
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
  node agent against local `fluxvm serve`, optional `DisposableVm` → `MicroVM`
  conversion. Docs: [docs/microvm.md](docs/microvm.md). Manifests:
  `deploy/k8s/microvm/`. Tests: `cargo test -p fluxvm-microvm` /
  `scripts/test-microvm.sh`. (Formerly internal aether design.)
- Hubble-style **packet flow** renderer: hop path (guest → tap → tc/eBPF →
  uplink → peer), `--output color|plain|json`, `fluxvm hubble flow` detailed
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
  updates, conntrack learn/hit, `fluxvm cnp` / `fluxvm identity` /
  `fluxvm observe`, REST `/v1/network/cnp`, `/v1/network/identities`,
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
- **Live QGA control** — QEMU virtio-serial guest-agent CLI/REST for PowerShell and firewall rules after boot: `fluxvm qga ping|powershell|exec|firewall-open|firewall-close`, mirrored at `POST /v1/vms/{id}/qga/ping|exec|firewall/open|firewall/close`.
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
