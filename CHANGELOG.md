# Changelog

## 0.4.0 (unreleased)

### Added
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
  [docs/secure-containers.md](docs/secure-containers.md). QEMU-only; PVC/TTY
  and FIFO-over-virtiofs stdio remain follow-up gates.
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
