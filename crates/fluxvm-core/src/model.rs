// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackendKind {
    Qemu,
    CloudHypervisor,
    Firecracker,
    /// In-tree FluxVM hypervisor (`fluxvm-hypervisor`) — agent-sandbox track.
    FluxVm,
    /// Resolved to a concrete backend by `fluxvm_scheduler::resolve_backend`
    /// as the very first step of `VmManager::create` — never persisted, and
    /// every other function taking a `BackendKind` (the backend dispatcher,
    /// image cloning, ...) assumes it never sees this variant.
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case", tag = "mode")]
pub enum NetworkSpec {
    None,
    User {
        #[serde(default)]
        forwards: Vec<PortForward>,
    },
    Tap {
        #[serde(default)]
        tap_name: Option<String>,
        #[serde(default)]
        bridge: Option<String>,
        #[serde(default)]
        mac: Option<String>,
        /// Give this VM its own network namespace (veth pair + NAT to the
        /// host, an internal bridge joining the veth and the tap inside the
        /// namespace) instead of putting its tap directly on the shared
        /// host bridge named by `bridge` (which is ignored when this is
        /// true). Real isolation: the VM's own routing table, iptables, and
        /// interface list are separate from the host's and from every other
        /// namespaced VM's — not just a shared L2 segment. The VMM process
        /// itself is launched inside the namespace (`ip netns exec`) so it
        /// can see the tap at all.
        #[serde(default)]
        netns: bool,
        /// Secondary guest NICs (Multus `netN`). Each entry is a host
        /// bridge the scheduler attaches as an extra TAP at create time
        /// (QEMU, Cloud Hypervisor, Firecracker) or via
        /// `POST /v1/vms/{id}/hotplug/nic` after a warm-pool claim.
        #[serde(default)]
        extra: Vec<ExtraNic>,
        /// Bridge-less attach: the tap is not enslaved to any bridge and a
        /// TC/eBPF redirect moves frames straight between `direct.outer`
        /// and the tap (see [`DirectSpec`]). Mutually exclusive with
        /// `bridge` and `netns`. Absent on every record written before this
        /// field existed, which keeps meaning "bridged tap".
        #[serde(default, skip_serializing_if = "Option::is_none")]
        direct: Option<DirectSpec>,
    },
    /// A macvtap device on `parent`, giving the VM its own MAC directly on
    /// that link with no host bridge involved. Supported by the QEMU and
    /// Cloud Hypervisor backends only (attached via a pre-opened file
    /// descriptor); Firecracker has no fd-based tap attachment in its API.
    Macvtap {
        parent: String,
        /// macvtap link mode: bridge (default) | vepa | private | passthru
        #[serde(default)]
        macvtap_mode: Option<String>,
        #[serde(default)]
        mac: Option<String>,
    },
}

/// How a bridge-less ("direct") tap is paired with its outer device.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DirectMode {
    /// `outer` is a veth (a CNI pod's `eth0`). Frames arriving on `outer` are
    /// redirected to the tap, and guest frames are `bpf_redirect_peer`d back
    /// through `outer` to its peer -- the Cilium `lxc*` delivery hop.
    #[default]
    PeerVeth,
    /// `outer` is a physical/bond uplink NIC with no bridge master. Frames
    /// are steered to the tap by destination MAC; anything else is passed to
    /// the host stack.
    L2Uplink,
}

/// Bridge-less attach of a VM tap to an outer device. The tap and `outer`
/// live in the same network namespace (`netns_path`, or the host's when
/// `None`) because `bpf_redirect` only works within one namespace.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectSpec {
    /// Interface the redirect pairs with the tap (`eth0` for a CNI pod).
    pub outer: String,
    /// Path of the network namespace holding both devices (for a CNI pod, the
    /// bind-mounted pod netns). `None` means the host namespace.
    #[serde(default)]
    pub netns_path: Option<String>,
    #[serde(default)]
    pub mode: DirectMode,
    /// IPv4 addresses the guest will use, for `l2-uplink` only. They let the datapath deliver an
    /// ARP request for one of them (from the LAN, or from another guest on the same uplink) to
    /// this guest's tap, since a bridge-less uplink has no other way to find it. Optional: without
    /// them unicast still works by MAC, but a LAN peer cannot discover the guest by ARP.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub guest_ips: Vec<String>,
}

/// Most guest IPs one VM may declare for uplink ARP steering.
pub const MAX_DIRECT_GUEST_IPS: usize = 8;

impl DirectSpec {
    /// Structural checks that need no host access, so a bad request is
    /// rejected at admission instead of half-way through `prepare`.
    pub fn validate(&self) -> Result<(), String> {
        if self.outer.is_empty() || self.outer.len() > 15 {
            return Err("direct.outer must be 1..=15 characters".into());
        }
        if self.outer.contains(['/', ' ']) {
            return Err("direct.outer is not a valid interface name".into());
        }
        if let Some(p) = &self.netns_path {
            if !p.starts_with('/') {
                return Err("direct.netns_path must be an absolute path".into());
            }
        }
        if !self.guest_ips.is_empty() {
            if self.mode != DirectMode::L2Uplink {
                return Err("direct.guest_ips only applies to mode=l2-uplink".into());
            }
            if self.guest_ips.len() > MAX_DIRECT_GUEST_IPS {
                return Err(format!(
                    "direct.guest_ips accepts at most {MAX_DIRECT_GUEST_IPS} addresses"
                ));
            }
            for ip in &self.guest_ips {
                if ip.parse::<std::net::Ipv4Addr>().is_err() {
                    return Err(format!(
                        "direct.guest_ips entry {ip:?} is not an IPv4 address (IPv6/NDP steering is not supported)"
                    ));
                }
            }
        }
        if self.mode == DirectMode::L2Uplink && self.netns_path.is_some() {
            return Err(
                "direct.mode=l2-uplink attaches to a host uplink; netns_path must be unset".into(),
            );
        }
        Ok(())
    }
}

impl NetworkSpec {
    /// Validates the bridge-less options of a `Tap` spec. Other variants and
    /// bridged taps always pass.
    pub fn validate_direct(&self) -> Result<(), String> {
        let NetworkSpec::Tap {
            direct: Some(d),
            bridge,
            netns,
            extra,
            ..
        } = self
        else {
            return Ok(());
        };
        d.validate()?;
        if bridge.is_some() {
            return Err("network.direct and network.bridge are mutually exclusive".into());
        }
        if *netns {
            return Err("network.direct and network.netns=true are mutually exclusive".into());
        }
        if !extra.is_empty() {
            return Err(
                "network.extra NICs are not supported together with network.direct yet".into(),
            );
        }
        Ok(())
    }
}

/// One extra guest NIC on a host bridge. `tap_name` is filled by
/// `fluxvm_network::prepare` (or NIC hotplug) and is what the VMM opens.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtraNic {
    pub bridge: String,
    #[serde(default)]
    pub mac: Option<String>,
    #[serde(default)]
    pub tap_name: Option<String>,
}

impl Default for NetworkSpec {
    fn default() -> Self {
        Self::User { forwards: vec![] }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortForward {
    pub host_port: u16,
    pub guest_port: u16,
    #[serde(default = "default_tcp")]
    pub protocol: String,
}
fn default_tcp() -> String {
    "tcp".into()
}

/// Where and how a VM's writable disk is actually provisioned, independent
/// of which VMM backend boots it. `Default` (the empty/unset request field)
/// keeps today's per-VMM behavior unchanged: a qcow2 copy-on-write overlay
/// for QEMU, a reflinked-or-copied raw file for Cloud Hypervisor/Firecracker.
/// See `fluxvm_image::storage` for how each variant is actually
/// provisioned and torn down.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum StorageBackend {
    #[default]
    Default,
    /// `request.image` must be the path to an existing LVM thin logical
    /// volume block device (e.g. `/dev/vg0/base-image`), itself backed by a
    /// thin pool. A new thin snapshot LV is created per VM and handed to
    /// the VMM directly as a raw block device: near-instant, real
    /// copy-on-write at the block layer, no filesystem/reflink involved.
    /// Not supported under the Firecracker jailer — its chroot/hardlink
    /// resource-placement model doesn't extend to shared block devices; use
    /// direct (non-jailed) Firecracker, QEMU, or Cloud Hypervisor instead.
    LvmThin,
    /// QEMU only. The per-VM disk is a normal qcow2 CoW overlay, exported
    /// over NBD via a `qemu-nbd` subprocess this VM owns (over a UNIX
    /// socket, not a TCP port) instead of being opened directly as a local
    /// file by QEMU — the same client/server split real remote/shared NBD
    /// storage uses, without requiring a separate storage host to exist in
    /// order to prove the mechanism end to end.
    Nbd,
    /// Ceph RBD. `request.image` is a `pool/image` reference to an existing
    /// RBD image; a snapshot on it named `fluxvm-base` must already exist
    /// and be protected (`rbd snap protect`) for the per-VM clone to work.
    /// Verified end to end against a real Rook Ceph cluster: `rbd clone`
    /// produces a genuine per-VM thin clone, and QEMU boots a real guest to
    /// a login prompt straight off the `rbd:` URI — see
    /// `fluxvm_image::storage::provision_ceph_rbd`. Does not support
    /// automatic guest-agent token injection (see that function).
    CephRbd,
}

/// Enables the in-guest vsock agent (ping/exec/shutdown, no SSH needed).
/// `port` is the AF_VSOCK port the guest listens on, not a host TCP port.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentSpec {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_agent_port")]
    pub port: u32,
    /// Shared secret the guest agent requires on every request. If left
    /// unset on a request with `enabled: true`, `VmManager::create`
    /// generates a random one and burns it into that VM's own disk before
    /// boot (see `fluxvm_image::inject_guest_agent_token`) — every
    /// agent-enabled VM ends up authenticated by default, without the
    /// caller having to think about it.
    #[serde(default)]
    pub token: Option<String>,
}
fn default_agent_port() -> u32 {
    17777
}

impl Default for AgentSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            port: default_agent_port(),
            token: None,
        }
    }
}

/// QEMU guest-agent (virtio-serial `org.qemu.guest_agent.0`) channel.
/// Used for Zyvor/GuestKit Windows agent live control (`fluxctl qga …`).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct QgaSpec {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CloudInitSpec {
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub ssh_authorized_keys: Vec<String>,
    #[serde(default)]
    pub packages: Vec<String>,
    #[serde(default)]
    pub runcmd: Vec<String>,
    /// Configure the guest's network address statically via cloud-init
    /// (network-config v2) instead of leaving it to the guest's own DHCP
    /// client. Only meaningful for `NetworkSpec::Tap { netns: true, .. }`
    /// -- that's the only mode with a known address to inject before boot
    /// (see `fluxvm_network::netns::NetnsHandle`). Ignored (no-op) for
    /// every other networking mode. The address is the same one DHCP mode
    /// would hand out anyway (both are pinned to the same reservation) --
    /// this just skips depending on the guest actually running a working
    /// DHCP client, which not every image does out of the box.
    #[serde(default)]
    pub static_network: bool,
    /// Files to write into the guest before first boot, via cloud-init's
    /// own `write_files` module -- e.g. dropping a systemd unit or app
    /// config without needing a custom image build.
    #[serde(default)]
    pub write_files: Vec<CloudInitFile>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudInitFile {
    pub path: String,
    pub content: String,
    /// Octal file mode, e.g. `"0644"`. Defaults to cloud-init's own default
    /// (`0644`) when unset.
    #[serde(default)]
    pub permissions: Option<String>,
}

/// A host directory shared into the guest via virtiofs, declared at create
/// time — there's no live "mount this now" equivalent for a real hardware
/// VM the way `machinectl bind` had for nspawn's shared-kernel containers
/// (see the systemd-removal migration plan's bind-mount notes). Requires
/// `virtiofsd` on the host `$PATH`; only supported by the QEMU backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedFolder {
    pub host_path: PathBuf,
    /// Where to mount it inside the guest. Auto-mounted via a generated
    /// cloud-init `runcmd` entry when `cloud_init` is set on the request
    /// (see `VmManager::create`); otherwise the guest must run
    /// `mount -t virtiofs <tag> <guest_path>` itself, where `<tag>` is
    /// this share's index in `shared_folders` (`"fs0"`, `"fs1"`, ...).
    pub guest_path: String,
    #[serde(default)]
    pub read_only: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateVmRequest {
    pub name: String,
    /// First-class tenant id for multi-team hosts. Optional; filterable on list.
    #[serde(default)]
    pub tenant: Option<String>,
    /// Identity of the API token that created this VM, stamped server-side
    /// in `create_vm`/`create_sandbox` (`fluxvm-api`) from the authenticated
    /// caller right after deserializing the request -- unconditionally,
    /// unlike `tenant` above (which has a legitimate client-supplied path
    /// for the untenanted-token case), so whatever a request body claims
    /// for this field is always discarded and replaced. Deliberately
    /// *not* `skip_deserializing`, even though there's no legitimate
    /// client-supplied path for it either: `fluxvm-storage::Store`
    /// round-trips every `VmRecord` (this field included) through this
    /// exact same serde codec on every single read (its flock-per-
    /// operation, read-fresh-under-lock file), so a `skip_deserializing`
    /// field would silently come back `None` on every `list()`/`get()`
    /// after being written -- which is exactly what broke
    /// `enforce_token_quotas` (it always saw zero VMs for any token) during
    /// development of this field. The request-body attack surface this
    /// would have closed is already closed by the handler's unconditional
    /// overwrite instead. Used by `enforce_token_quotas` to scope
    /// `max_vms_per_token`/`max_memory_mib_per_token` to the calling
    /// token's own VMs instead of every VM on the node from every token.
    #[serde(default)]
    pub created_by_token: Option<String>,
    pub backend: BackendKind,
    pub image: PathBuf,
    #[serde(default = "default_vcpus")]
    pub vcpus: u8,
    #[serde(default = "default_memory")]
    pub memory_mib: u64,
    /// Upper bound for CPU hotplug (`query-hotpluggable-cpus` / `device_add`
    /// slots) -- must be >= `vcpus`. `None` lets the backend pick a default
    /// headroom rather than disabling hotplug outright.
    #[serde(default)]
    pub max_vcpus: Option<u8>,
    /// Upper bound for memory hotplug (DIMM `device_add` address space) in
    /// MiB -- must be >= `memory_mib`. `None` lets the backend pick a
    /// default headroom rather than disabling hotplug outright.
    #[serde(default)]
    pub max_memory_mib: Option<u64>,
    #[serde(default)]
    pub disk_size_gib: Option<u64>,
    #[serde(default)]
    pub kernel: Option<PathBuf>,
    #[serde(default)]
    pub initrd: Option<PathBuf>,
    #[serde(default)]
    pub firmware: Option<PathBuf>,
    #[serde(default)]
    pub kernel_args: Option<String>,
    #[serde(default)]
    pub network: NetworkSpec,
    #[serde(default)]
    pub cloud_init: Option<CloudInitSpec>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
    /// Resume from an existing internal (`snapshot-save`) tag on this VM's
    /// own disk instead of a normal cold boot -- restores CPU/memory/device
    /// state via QEMU's `-loadvm`, not just disk content. A one-shot
    /// override applied to a single `start`/`start_from_snapshot` call
    /// (see `fluxvm_scheduler::VmManager::start_from_snapshot`), never
    /// persisted onto the VM's own stored `CreateVmRequest` -- a later
    /// ordinary restart must not keep trying to load a now-stale tag.
    #[serde(default)]
    pub loadvm_tag: Option<String>,
    #[serde(default)]
    pub extra_args: Vec<String>,
    #[serde(default)]
    pub agent: Option<AgentSpec>,
    /// Enable QEMU guest-agent virtio-serial channel (QEMU backend only).
    #[serde(default)]
    pub qga: Option<QgaSpec>,
    /// Cloud Hypervisor: pass `kvm_hyperv=on` on `--cpus` for Windows guests.
    /// Required for most Windows boots on CH; ignored by other backends.
    #[serde(default)]
    pub hyperv: bool,
    #[serde(default)]
    pub storage: StorageBackend,
    #[serde(default)]
    pub shared_folders: Vec<SharedFolder>,
    /// QEMU only: bind vCPU threads to host NUMA node(s).
    #[serde(default)]
    pub numa_node: Option<u8>,
    /// QEMU only: cpuset expression passed to `-numa cpu=…` / taskset-style
    /// pinning via `-object memory-backend-…` + `-numa` when combined with
    /// `hugepages`.
    #[serde(default)]
    pub cpuset: Option<String>,
    /// QEMU only: back guest RAM with host huge pages (`-mem-prealloc
    /// -mem-path /dev/hugepages/...` when set true).
    #[serde(default)]
    pub hugepages: Option<bool>,
    /// QEMU only: VFIO PCI passthrough device addresses (`host=0000:…`).
    #[serde(default)]
    pub vfio_devices: Vec<String>,
    /// Set 6S: Kubernetes Pod UID (from the CRI `io.kubernetes.cri.sandbox-uid`
    /// annotation), supplied by `containerd-shim-fluxvm-v2` for Secure
    /// Containers Pods. Mints a stable eBPF Pod identity
    /// (`fluxvm_network::pod_identity`) used for Pod-scoped network policy;
    /// `None` for every non-Secure-Containers VM, matching today's behavior.
    #[serde(default)]
    pub pod_uid: Option<String>,
    /// QEMU only, requires `firmware` (OVMF) to also be set: enable UEFI
    /// Secure Boot (`-global driver=cfi.pflash01,property=secure,value=on`
    /// plus `smm=on`) and require `Config::qemu_ovmf_vars_template` to be
    /// configured -- a real Secure Boot chain needs a vars store with
    /// Microsoft's UEFI CA keys already enrolled, which this project
    /// doesn't synthesize. See docs/secure-boot-tpm.md.
    #[serde(default)]
    pub secure_boot: Option<bool>,
    /// QEMU only: attach an emulated TPM 2.0 device (`swtpm` sidecar +
    /// `-tpmdev emulator` + `-device tpm-crb`). Independent of
    /// `secure_boot`/`firmware` -- a TPM is useful under legacy BIOS too
    /// (measured boot, disk encryption unseal), not only under UEFI.
    #[serde(default)]
    pub tpm: Option<bool>,
    /// Firecracker virtio-net bandwidth cap (Mbit/s). `None` or `0` =
    /// unlimited. Mapped to Firecracker's iface `rate_limiter.bandwidth`
    /// (threat-containment barrier at the VMM, complementary to Fabric
    /// egress Mbps). Ignored by QEMU/CH.
    #[serde(default)]
    pub net_mbit_limit: Option<u32>,
    /// Firecracker virtio-net operations (packets) per second cap.
    /// Mapped to iface `rate_limiter.ops`. Ignored by QEMU/CH.
    #[serde(default)]
    pub net_pps_limit: Option<u64>,
    /// Firecracker virtio-block bandwidth cap (Mbit/s). Mapped to drive
    /// `rate_limiter.bandwidth`. Ignored by QEMU/CH.
    #[serde(default)]
    pub blk_mbit_limit: Option<u32>,
    /// Firecracker virtio-block operations per second cap. Mapped to drive
    /// `rate_limiter.ops`. Ignored by QEMU/CH.
    #[serde(default)]
    pub blk_ops_limit: Option<u64>,
    /// Firecracker static CPU template name (e.g. `T2`, `T2A`, `C3`).
    /// Emitted into Firecracker `machine-config.cpu_template` and into
    /// FluxVm when `fluxvm_engine=firecracker`. Rejected on QEMU, Cloud
    /// Hypervisor, and FluxVm+kvm (no FC-style template ABI).
    #[serde(default)]
    pub cpu_template: Option<String>,
}
fn default_vcpus() -> u8 {
    2
}
fn default_memory() -> u64 {
    2048
}

// ZYVOR_RUNTIME_BOUNDARY_V1: node-local migration contract consumed by Zyvor Fabric.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationMode {
    #[default]
    PreCopy,
    PostCopy,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationStartRequest {
    /// QEMU migration URI. Contract v1 deliberately permits only `tcp:` and
    /// `unix:` transports; shell-backed `exec:` URIs are rejected by FluxVM.
    pub destination: String,
    #[serde(default)]
    pub mode: MigrationMode,
    #[serde(default)]
    pub bandwidth_mbps: Option<u64>,
    #[serde(default)]
    pub max_downtime_ms: Option<u64>,
    #[serde(default)]
    pub multifd_channels: Option<u8>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum MigrationPhase {
    None,
    Setup,
    Active,
    PostcopyActive,
    Completed,
    Failed,
    Cancelled,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationStatus {
    pub phase: MigrationPhase,
    /// Raw VMM status for forward compatibility with newer QEMU states.
    pub status: String,
    #[serde(default)]
    pub ram_transferred: Option<u64>,
    #[serde(default)]
    pub ram_remaining: Option<u64>,
    #[serde(default)]
    pub ram_total: Option<u64>,
    #[serde(default)]
    pub total_time_ms: Option<u64>,
    #[serde(default)]
    pub downtime_ms: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeMigrationCapability {
    pub backend: BackendKind,
    pub live: bool,
    pub pre_copy: bool,
    pub post_copy: bool,
    pub multifd: bool,
    /// Contract v1 does not copy VM disks. Fabric must place the VM on
    /// shared storage (for example Ceph RBD) or prepare storage separately.
    pub requires_shared_storage: bool,
    pub transports: Vec<String>,
    /// Whether this backend's migration-start call can be followed up with
    /// a `GET .../migration/status` poll to observe progress, and whether
    /// an in-flight migration can be cancelled at all.
    ///
    /// `true` for QEMU: QMP's `migrate` is asynchronous and `query-migrate`
    /// reports live phase/progress, so Fabric polls status and can
    /// `migrate_cancel` mid-flight.
    ///
    /// `false` for Cloud Hypervisor: verified live against a real
    /// `cloud-hypervisor`/`ch-remote` v53.0 pair that `send-migration`
    /// returns as soon as the VMM *accepts* the request, not once the
    /// transfer finishes -- the real outcome (including any failure) is
    /// only ever visible in the VMM's own process log, which this contract
    /// does not scrape. Cloud Hypervisor's API also has no cancellation
    /// primitive once a migration has been requested. Fabric must instead
    /// infer completion the same way it already detects any other node-local
    /// state change: this VM disappearing from `GET /v1/vms` on the source
    /// node once its process exits (success) versus it staying `Running`
    /// there (no attempt has succeeded yet).
    #[serde(default = "default_status_pollable")]
    pub status_pollable: bool,
}
fn default_status_pollable() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeSnapshotCapability {
    pub backend: BackendKind,
    pub memory: bool,
    pub disk: bool,
    pub portable: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeCapabilities {
    pub api_version: String,
    pub scope: String,
    pub orchestration_owner: String,
    pub migration: Vec<RuntimeMigrationCapability>,
    pub snapshot: Vec<RuntimeSnapshotCapability>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum VmStatus {
    Creating,
    Running,
    Paused,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmRecord {
    pub id: Uuid,
    pub name: String,
    pub backend: BackendKind,
    pub status: VmStatus,
    pub pid: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub workspace: PathBuf,
    pub disk: PathBuf,
    pub seed_disk: Option<PathBuf>,
    pub tap_name: Option<String>,
    pub control_socket: Option<PathBuf>,
    pub log_path: PathBuf,
    pub error: Option<String>,
    pub request: CreateVmRequest,
    /// Host-unique AF_VSOCK CID assigned when `request.agent` is enabled.
    #[serde(default)]
    pub guest_cid: Option<u32>,
    /// Firecracker-jailer only — see `backend::LaunchResult::jail_path`.
    #[serde(default)]
    pub jail_path: Option<PathBuf>,
    /// Host-visible path to the vsock proxy UDS (Cloud Hypervisor/
    /// Firecracker only) — see `backend::LaunchResult::vsock_socket`.
    #[serde(default)]
    pub vsock_socket: Option<PathBuf>,
    /// QEMU guest-agent unix socket (`org.qemu.guest_agent.0`) when
    /// `request.qga.enabled` — see `VmRecord::qga_socket`.
    #[serde(default)]
    pub qga_socket: Option<PathBuf>,
    /// cgroup v2 path (`fluxvm.slice/{id}.scope`) the launched VMM
    /// process was migrated into, once `VmManager` has done so —
    /// `None` until the first successful launch completes cgroup setup.
    #[serde(default)]
    pub cgroup_path: Option<PathBuf>,
    /// Name of this VM's private network namespace, when
    /// `NetworkSpec::Tap { netns: true, .. }` — see
    /// `fluxvm_network::netns`. `None` for every other networking mode.
    #[serde(default)]
    pub netns: Option<String>,
    /// `StorageBackend::LvmThin` only: the thin snapshot LV device path
    /// (`/dev/<vg>/eph-<id>`) created for this VM, so `VmManager::delete`
    /// can `lvremove` it regardless of what `request.storage` says by the
    /// time the VM is deleted.
    #[serde(default)]
    pub lvm_lv: Option<PathBuf>,
    /// `StorageBackend::Nbd` only: pid of the `qemu-nbd` subprocess serving
    /// this VM's disk over `<workspace>/nbd.sock`, kept alive across
    /// stop/start (like the disk file itself) and reaped only on delete.
    #[serde(default)]
    pub nbd_pid: Option<u32>,
    /// PIDs of the `virtiofsd` processes backing `request.shared_folders`,
    /// one per share (same order), kept alive alongside the VM and killed
    /// on delete/stop by `VmManager` — see `LaunchResult::virtiofsd_pids`.
    #[serde(default)]
    pub virtiofsd_pids: Vec<u32>,
    /// PID of the `swtpm` process backing `request.tpm`, when set --
    /// respawned fresh on every launch (like `virtiofsd_pids`, not kept
    /// alive across stop/start like `nbd_pid`) -- see
    /// `backend::LaunchResult::swtpm_pid`. The TPM's actual persistent
    /// state (NVRAM/keys) lives under `workspace/tpm/`, independent of
    /// this PID's lifetime.
    #[serde(default)]
    pub swtpm_pid: Option<u32>,
    /// Path to this VM's per-namespace dnsmasq lease file -- only set for
    /// `NetworkSpec::Tap { netns: true, .. }` VMs. `VmManager::get`/`list`
    /// use it to freshly resolve `guest_ip` on every read rather than
    /// trusting a value that could go stale as leases renew.
    #[serde(default)]
    pub dhcp_leasefile: Option<std::path::PathBuf>,
    /// The guest's IP address on its own private subnet, learned from
    /// `dhcp_leasefile` by MAC lookup -- only set for `NetworkSpec::Tap {
    /// netns: true, .. }` VMs (see `fluxvm_network::netns`). `None` until
    /// the guest actually completes a DHCP handshake, and for every other
    /// networking mode. Recomputed on every read (see `dhcp_leasefile`
    /// above), not authoritative between reads.
    #[serde(default)]
    pub guest_ip: Option<String>,
}

/// A named template for a warm pool: `size` VMs matching `template` are
/// kept pre-booted-and-`Paused`, ready to be handed out by
/// `VmManager::claim_from_pool` in roughly resume-time (already fast — see
/// "Pause, resume, and exec") instead of full create-time. `template.name`
/// and `template.ttl_seconds` are ignored for pool members (a paused pool
/// member must never expire on its own; the claimed VM gets a fresh name/TTL
/// at claim time — see `ClaimOverrides`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolSpec {
    pub name: String,
    pub size: usize,
    pub template: CreateVmRequest,
}

/// Persisted state of a warm pool: which VM ids are currently reserved
/// members (booted, paused, unclaimed). A member id present here always
/// corresponds to a real `Paused` `VmRecord` in the main VM store — the two
/// are kept in sync by `VmManager`, not merged into one store, since pool
/// membership and VM lifecycle are different concerns with different
/// locking needs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolRecord {
    pub name: String,
    pub size: usize,
    pub template: CreateVmRequest,
    #[serde(default)]
    pub members: Vec<Uuid>,
    /// Lifetime count of members successfully handed out by
    /// `VmManager::claim_from_pool` — incremented once per claim that
    /// actually succeeded (resumed and, if tenant-scoped, verified), not
    /// once per pop attempt. Pure observability: nothing reads this back to
    /// make a decision, it exists so an operator staring at a pool that
    /// keeps running dry (or one that's never claimed at all) has a number
    /// to size it by, instead of only ever seeing a point-in-time
    /// ready-vs-target snapshot that says nothing about actual demand over
    /// time. `#[serde(default)]` so a `pools.json` written before this
    /// field existed still loads (as 0, the honest "unknown history"
    /// value) rather than failing to parse.
    #[serde(default)]
    pub claimed_total: u64,
}

/// Read-only view of a [`PoolRecord`] returned by the pool API/CLI surfaces,
/// augmenting the persisted fields with occupancy stats a caller would
/// otherwise have to derive itself. Before this, `GET /v1/pools/{name}` (and
/// `fluxctl pool get`/`list`) returned only `size` (the *target* member
/// count) and `members` (the ids of members currently ready) — nothing
/// named which was which, so telling "fully backfilled" apart from "still
/// catching up" meant a caller had to know, unprompted, to compare
/// `members.len()` against `size` itself. `ready`/`pending` name that
/// comparison explicitly; `claimed_total` (already on `record`, just called
/// out here too since it's the other half of "is this pool sized right")
/// rides along via the flatten.
#[derive(Debug, Clone, Serialize)]
pub struct PoolView {
    #[serde(flatten)]
    pub record: PoolRecord,
    /// `record.members.len()` — members currently paused and claimable
    /// right now.
    pub ready: usize,
    /// How many more members are needed to reach `record.size`. Saturating,
    /// so a pool briefly over target (e.g. mid-shrink, before the excess is
    /// trimmed) reports 0 rather than an underflowed huge number.
    pub pending: usize,
}

impl From<PoolRecord> for PoolView {
    fn from(record: PoolRecord) -> Self {
        let ready = record.members.len();
        let pending = record.size.saturating_sub(ready);
        Self {
            record,
            ready,
            pending,
        }
    }
}

/// Applied to the VM handed back by a pool claim, replacing whatever the
/// template said for these two fields (a pool member is paused with no name
/// worth keeping and no TTL, precisely so it never expires while idle in
/// the pool).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ClaimOverrides {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub ttl_seconds: Option<u64>,
}

/// Body of `POST /v1/pools/{name}/resize` / `fluxctl pool resize` — the new
/// target `size` for an existing pool. See `VmManager::resize_pool`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolResizeRequest {
    pub size: usize,
}

/// cgroup v2 resource-control settings to apply to a running VM. Every
/// field is optional so a caller only touches what it actually wants to
/// change — see `VmManager::set_resources`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ResourcePatch {
    /// CPU quota as a percentage of one core (200 = 2 full cores).
    #[serde(default)]
    pub cpu_quota_percent: Option<u32>,
    /// Memory limit in bytes.
    #[serde(default)]
    pub memory_max_bytes: Option<u64>,
    /// I/O weight (1-10000, default 100).
    #[serde(default)]
    pub io_weight: Option<u32>,
    /// Maximum number of PIDs in the VM's cgroup.
    #[serde(default)]
    pub pids_max: Option<u64>,
    /// Pin the VM to these host CPU cores.
    #[serde(default)]
    pub cpuset_cpus: Option<Vec<u32>>,
}

/// Request body for `POST /v1/vms/{id}/hotplug/cpu` -- adds vCPUs into the
/// unrealized `query-hotpluggable-cpus` slots reserved via `max_vcpus` at
/// creation. QEMU-only; other backends reject this outright (see
/// `VmManager::hotplug_cpu`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotplugCpuRequest {
    pub add_vcpus: u8,
}

/// Response for a successful CPU hotplug -- the realized vCPU count after
/// adding, not just what this call added.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotplugCpuResult {
    pub vcpus: u8,
}

/// Request body for `POST /v1/vms/{id}/hotplug/memory` -- adds RAM as a new
/// `pc-dimm` backed by a fresh `memory-backend-ram` object, into the DIMM
/// slots reserved via `max_memory_mib` at creation. QEMU-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotplugMemoryRequest {
    pub add_memory_mib: u64,
}

/// Response for a successful memory hotplug -- the VM's new *total* live
/// memory (boot-time `memory_mib` plus every hot-added DIMM so far).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotplugMemoryResult {
    pub memory_mib: u64,
}

/// Request body for `POST /v1/vms/{id}/hotplug/nic`. QEMU only: creates a
/// TAP on `bridge` and `device_add`s `virtio-net-pci` onto the next free
/// `hotplug-pcie-*` root port. Used by Secure Containers after a warm-pool
/// claim, when the template VM was booted with `network.mode=none`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HotplugNicRequest {
    /// Host bridge for a bridged NIC. Empty when `direct` is set.
    #[serde(default)]
    pub bridge: String,
    #[serde(default)]
    pub mac: Option<String>,
    /// Bridge-less attach instead of a bridge: the daemon creates the tap (inside the outer
    /// device's netns when `netns_path` is set), wires the eBPF redirect, and hands the tap to QEMU
    /// as a descriptor. Mutually exclusive with `bridge`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct: Option<DirectSpec>,
}

impl HotplugNicRequest {
    /// Exactly one of `bridge` / `direct`, and a valid `direct`.
    pub fn validate(&self) -> Result<(), String> {
        match (&self.direct, self.bridge.is_empty()) {
            (None, true) => Err("hotplug/nic needs either `bridge` or `direct`".into()),
            (Some(_), false) => {
                Err("hotplug/nic `bridge` and `direct` are mutually exclusive".into())
            }
            (Some(d), true) => d.validate(),
            (None, false) => Ok(()),
        }
    }
}

/// Point-in-time resource usage for a VM, read from its cgroup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmMetrics {
    /// CPU usage as a percentage of one core, averaged over the process's
    /// entire lifetime (not an instantaneous rate).
    pub cpu_usage_percent: f64,
    pub memory_usage_bytes: u64,
    pub disk_read_bytes: u64,
    pub disk_write_bytes: u64,
}

/// PSI (Pressure Stall Information) for a VM's cgroup — see
/// `fluxvm_cgroup::PressureStats` for field semantics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmPressure {
    pub cpu_some: Option<fluxvm_cgroup::PressureRecord>,
    pub memory_some: Option<fluxvm_cgroup::PressureRecord>,
    pub memory_full: Option<fluxvm_cgroup::PressureRecord>,
    pub io_some: Option<fluxvm_cgroup::PressureRecord>,
    pub io_full: Option<fluxvm_cgroup::PressureRecord>,
}

#[cfg(test)]
mod pool_view_tests {
    use super::*;

    /// A `CreateVmRequest` has ~25 fields, nearly all `#[serde(default)]` --
    /// going through JSON with only the three actually-required ones set
    /// exercises the same defaulting real request bodies rely on, instead
    /// of this test needing to list every field by hand (and rot every time
    /// a field is added elsewhere).
    fn minimal_request() -> CreateVmRequest {
        serde_json::from_value(serde_json::json!({
            "name": "t",
            "backend": "qemu",
            "image": "/does/not/exist.qcow2",
        }))
        .unwrap()
    }

    fn pool(size: usize, member_count: usize, claimed_total: u64) -> PoolRecord {
        PoolRecord {
            name: "p".into(),
            size,
            template: minimal_request(),
            members: (0..member_count).map(|_| Uuid::new_v4()).collect(),
            claimed_total,
        }
    }

    #[test]
    fn ready_and_pending_reflect_members_vs_target() {
        let view = PoolView::from(pool(5, 2, 0));
        assert_eq!(view.ready, 2);
        assert_eq!(view.pending, 3);
    }

    #[test]
    fn pending_is_zero_once_fully_backfilled() {
        let view = PoolView::from(pool(3, 3, 0));
        assert_eq!(view.ready, 3);
        assert_eq!(view.pending, 0);
    }

    #[test]
    fn pending_saturates_rather_than_underflows_when_over_target() {
        // Briefly possible mid-shrink, before the excess members are
        // trimmed -- must report 0, not wrap around to a huge usize.
        let view = PoolView::from(pool(2, 5, 0));
        assert_eq!(view.ready, 5);
        assert_eq!(view.pending, 0);
    }

    #[test]
    fn claimed_total_rides_along_via_the_flatten() {
        let view = PoolView::from(pool(1, 0, 42));
        let value = serde_json::to_value(&view).unwrap();
        assert_eq!(value["claimed_total"], 42);
        assert_eq!(value["ready"], 0);
        assert_eq!(value["pending"], 1);
        // The flatten must not shadow or duplicate any persisted field.
        assert_eq!(value["size"], 1);
        assert_eq!(value["name"], "p");
    }
}

#[cfg(test)]
mod create_vm_request_tests {
    use super::*;

    #[test]
    fn created_by_token_round_trips_through_serde_like_a_stored_record_would() {
        // created_by_token is deliberately a plain #[serde(default)]
        // field, not skip_deserializing (see its own doc comment for why:
        // fluxvm-storage::Store round-trips every VmRecord through this
        // exact same codec on every read, and a skip_deserializing field
        // would silently come back None there every time). This proves
        // the round trip that quota accounting depends on actually works
        // -- the client-spoofing concern that might otherwise motivate
        // skip_deserializing is handled instead by fluxvm-api's create_vm/
        // create_sandbox unconditionally overwriting this field from the
        // authenticated caller right after deserializing (see
        // created_by_token_cannot_be_spoofed_via_the_request_body in
        // fluxvm-api for that half of the guarantee).
        let req: CreateVmRequest = serde_json::from_str(
            r#"{"name":"t","backend":"qemu","image":"/does/not/exist.qcow2","created_by_token":"tokenA"}"#,
        )
        .unwrap();
        assert_eq!(req.created_by_token.as_deref(), Some("tokenA"));

        let json = serde_json::to_string(&req).unwrap();
        let round_tripped: CreateVmRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(round_tripped.created_by_token.as_deref(), Some("tokenA"));
    }

    #[test]
    fn tap_without_extra_deserializes_empty_multus_list() {
        let spec: NetworkSpec = serde_json::from_str(
            r#"{"mode":"tap","bridge":"br0","mac":"02:00:00:00:00:01","netns":false}"#,
        )
        .unwrap();
        match spec {
            NetworkSpec::Tap {
                extra,
                bridge,
                netns,
                ..
            } => {
                assert!(extra.is_empty());
                assert_eq!(bridge.as_deref(), Some("br0"));
                assert!(!netns);
            }
            other => panic!("expected tap, got {other:?}"),
        }
    }

    #[test]
    fn tap_extra_nics_round_trip_bridge_and_mac() {
        let raw = r#"{"mode":"tap","bridge":"fvbhprimary","mac":"02:00:00:00:00:01","extra":[{"bridge":"fvbhnet1","mac":"02:11:22:33:44:55"}]}"#;
        let spec: NetworkSpec = serde_json::from_str(raw).unwrap();
        let NetworkSpec::Tap { extra, .. } = &spec else {
            panic!("expected tap");
        };
        assert_eq!(extra.len(), 1);
        assert_eq!(extra[0].bridge, "fvbhnet1");
        assert_eq!(extra[0].mac.as_deref(), Some("02:11:22:33:44:55"));
        assert!(extra[0].tap_name.is_none());
        let again: NetworkSpec =
            serde_json::from_str(&serde_json::to_string(&spec).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            serde_json::to_value(&again).unwrap()
        );
    }

    #[test]
    fn bridged_tap_record_without_direct_stays_bridged_and_reserializes_unchanged() {
        // Persisted VM requests are re-prepared on start/restore, so a record
        // written before `direct` existed must keep meaning "bridged tap" and
        // must not sprout a `direct` key when written back.
        let raw = r#"{"mode":"tap","bridge":"vmbr0","mac":"02:00:00:00:00:01","netns":false}"#;
        let spec: NetworkSpec = serde_json::from_str(raw).unwrap();
        let NetworkSpec::Tap { direct, .. } = &spec else {
            panic!("expected tap");
        };
        assert!(direct.is_none());
        assert!(serde_json::to_value(&spec).unwrap().get("direct").is_none());
        assert!(spec.validate_direct().is_ok());
    }

    #[test]
    fn direct_tap_round_trips_with_defaults() {
        let raw = r#"{"mode":"tap","mac":"02:00:00:00:00:01","direct":{"outer":"eth0","netns_path":"/run/netns/fvcni-abc123"}}"#;
        let spec: NetworkSpec = serde_json::from_str(raw).unwrap();
        let NetworkSpec::Tap { direct, bridge, .. } = &spec else {
            panic!("expected tap");
        };
        let d = direct.as_ref().expect("direct present");
        assert_eq!(d.outer, "eth0");
        assert_eq!(d.netns_path.as_deref(), Some("/run/netns/fvcni-abc123"));
        assert_eq!(d.mode, DirectMode::PeerVeth, "mode defaults to peer-veth");
        assert!(bridge.is_none());
        assert!(spec.validate_direct().is_ok());
        let again: NetworkSpec =
            serde_json::from_str(&serde_json::to_string(&spec).unwrap()).unwrap();
        assert_eq!(
            serde_json::to_value(&spec).unwrap(),
            serde_json::to_value(&again).unwrap()
        );
        let l2: NetworkSpec = serde_json::from_str(
            r#"{"mode":"tap","direct":{"outer":"enp1s0","mode":"l2-uplink"}}"#,
        )
        .unwrap();
        assert!(l2.validate_direct().is_ok());
    }

    #[test]
    fn hotplug_requests_need_exactly_one_attach_mode() {
        let ok_bridge: HotplugNicRequest =
            serde_json::from_str(r#"{"bridge":"fvbh1","mac":"02:00:00:00:00:01"}"#).unwrap();
        assert!(ok_bridge.validate().is_ok());
        assert!(
            ok_bridge.direct.is_none(),
            "old bridge requests keep meaning a bridged NIC"
        );
        let ok_direct: HotplugNicRequest = serde_json::from_str(
            r#"{"mac":"02:00:00:00:00:01","direct":{"outer":"eth0","netns_path":"/run/netns/fvcni-x"}}"#,
        )
        .unwrap();
        assert!(ok_direct.validate().is_ok());
        assert!(ok_direct.bridge.is_empty());
        let neither: HotplugNicRequest = serde_json::from_str(r#"{}"#).unwrap();
        assert!(neither.validate().unwrap_err().contains("either"));
        let both: HotplugNicRequest =
            serde_json::from_str(r#"{"bridge":"b","direct":{"outer":"eth0"}}"#).unwrap();
        assert!(both.validate().unwrap_err().contains("mutually exclusive"));
        let bad: HotplugNicRequest = serde_json::from_str(r#"{"direct":{"outer":""}}"#).unwrap();
        assert!(bad.validate().is_err(), "the direct spec is validated too");
        // a bridged request serialises without a `direct` key, so older daemons still accept it
        assert!(
            serde_json::to_value(&ok_bridge)
                .unwrap()
                .get("direct")
                .is_none()
        );
    }

    #[test]
    fn guest_ips_are_validated_and_only_for_the_uplink_mode() {
        fn check(json: &str) -> Result<(), String> {
            serde_json::from_str::<NetworkSpec>(json)
                .unwrap()
                .validate_direct()
        }
        let ok = r#"{"mode":"tap","direct":{"outer":"enp1s0","mode":"l2-uplink","guest_ips":["10.0.0.5","192.168.1.9"]}}"#;
        assert!(check(ok).is_ok());
        // round-trips, and stays out of the JSON when empty (old records are unchanged)
        let spec: NetworkSpec = serde_json::from_str(ok).unwrap();
        assert_eq!(
            serde_json::to_value(&spec).unwrap()["direct"]["guest_ips"][1],
            "192.168.1.9"
        );
        let bare: NetworkSpec =
            serde_json::from_str(r#"{"mode":"tap","direct":{"outer":"eth0"}}"#).unwrap();
        assert!(
            serde_json::to_value(&bare).unwrap()["direct"]
                .get("guest_ips")
                .is_none()
        );
        assert!(
            check(r#"{"mode":"tap","direct":{"outer":"eth0","guest_ips":["10.0.0.5"]}}"#)
                .unwrap_err()
                .contains("l2-uplink")
        );
        assert!(check(r#"{"mode":"tap","direct":{"outer":"e","mode":"l2-uplink","guest_ips":["fd00::5"]}}"#)
            .unwrap_err()
            .contains("IPv4"));
        assert!(check(r#"{"mode":"tap","direct":{"outer":"e","mode":"l2-uplink","guest_ips":["not-an-ip"]}}"#).is_err());
        let many = (1..=9)
            .map(|i| format!("\"10.0.0.{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        let too_many = format!(
            r#"{{"mode":"tap","direct":{{"outer":"e","mode":"l2-uplink","guest_ips":[{many}]}}}}"#
        );
        assert!(check(&too_many).unwrap_err().contains("at most"));
    }

    #[test]
    fn direct_validation_rejects_conflicting_or_malformed_specs() {
        fn check(json: &str) -> Result<(), String> {
            serde_json::from_str::<NetworkSpec>(json)
                .unwrap()
                .validate_direct()
        }
        let ok = r#""direct":{"outer":"eth0","netns_path":"/run/netns/x"}"#;
        assert!(check(&format!(r#"{{"mode":"tap",{ok}}}"#)).is_ok());
        let bridge = check(&format!(r#"{{"mode":"tap","bridge":"vmbr0",{ok}}}"#));
        assert!(bridge.unwrap_err().contains("mutually exclusive"));
        let netns = check(&format!(r#"{{"mode":"tap","netns":true,{ok}}}"#));
        assert!(netns.unwrap_err().contains("netns=true"));
        let extra = check(&format!(
            r#"{{"mode":"tap","extra":[{{"bridge":"b"}}],{ok}}}"#
        ));
        assert!(extra.unwrap_err().contains("extra"));
        assert!(check(r#"{"mode":"tap","direct":{"outer":""}}"#).is_err());
        assert!(check(r#"{"mode":"tap","direct":{"outer":"averyveryverylongname"}}"#).is_err());
        assert!(check(r#"{"mode":"tap","direct":{"outer":"a/b"}}"#).is_err());
        let rel = check(r#"{"mode":"tap","direct":{"outer":"eth0","netns_path":"relative/ns"}}"#);
        assert!(rel.unwrap_err().contains("absolute"));
        let l2ns = check(
            r#"{"mode":"tap","direct":{"outer":"eth0","mode":"l2-uplink","netns_path":"/run/netns/x"}}"#,
        );
        assert!(l2ns.unwrap_err().contains("l2-uplink"));
        // Non-tap variants never trip direct validation.
        assert!(check(r#"{"mode":"none"}"#).is_ok());
    }
}
