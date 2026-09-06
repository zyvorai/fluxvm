// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use crate::model::BackendKind;
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub listen: String,
    pub state_dir: PathBuf,
    pub run_dir: PathBuf,
    pub qemu_binary: String,
    pub qemu_img_binary: String,
    /// Only consulted when a `CreateVmRequest` has `shared_folders` — one
    /// instance is spawned per share, QEMU backend only.
    pub virtiofsd_binary: String,
    pub cloud_hypervisor_binary: String,
    pub ch_remote_binary: String,
    pub cloud_localds_binary: String,
    pub firecracker_binary: String,
    pub firecracker_kernel: Option<PathBuf>,
    /// Path to the in-tree `fluxvm-hypervisor` binary (agent-sandbox VMM).
    pub fluxvm_hypervisor_binary: String,
    /// Default kernel for `BackendKind::FluxVm` when the create request omits one.
    pub fluxvm_kernel: Option<PathBuf>,
    pub cloud_hypervisor_firmware: Option<PathBuf>,
    pub default_bridge: Option<String>,
    pub reaper_interval_secs: u64,
    pub policy: Policy,
    pub auth: AuthConfig,
    pub jailer: JailerConfig,
    pub catalog: CatalogConfig,
    pub storage: StorageConfig,
    /// Agent-sandbox features (AutoPause, egress, templates) — FluxVm backend.
    pub sandbox: SandboxConfig,
    /// KVM engine for `BackendKind::FluxVm`: Firecracker child (default) or
    /// in-tree pure KVM via `fluxvm-hypervisor`.
    #[serde(default)]
    pub fluxvm_engine: FluxVmEngine,
}

/// Which guest runner backs the FluxVM hypervisor control plane.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FluxVmEngine {
    #[default]
    Firecracker,
    Kvm,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:7788".into(),
            state_dir: "/var/lib/fluxvm".into(),
            run_dir: "/run/fluxvm".into(),
            qemu_binary: "qemu-system-x86_64".into(),
            qemu_img_binary: "qemu-img".into(),
            virtiofsd_binary: "virtiofsd".into(),
            cloud_hypervisor_binary: "cloud-hypervisor".into(),
            ch_remote_binary: "ch-remote".into(),
            cloud_localds_binary: "cloud-localds".into(),
            firecracker_binary: "firecracker".into(),
            firecracker_kernel: None,
            fluxvm_hypervisor_binary: "fluxvm-hypervisor".into(),
            fluxvm_kernel: None,
            cloud_hypervisor_firmware: None,
            default_bridge: Some("vmbr0".into()),
            reaper_interval_secs: 5,
            policy: Policy::default(),
            auth: AuthConfig::default(),
            jailer: JailerConfig::default(),
            catalog: CatalogConfig::default(),
            storage: StorageConfig::default(),
            sandbox: SandboxConfig::default(),
            fluxvm_engine: FluxVmEngine::default(),
        }
    }
}

/// Agent-sandbox controls used with `BackendKind::FluxVm`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Idle seconds before AutoPause suspends a sandbox (0 = disabled).
    pub autopause_idle_secs: u64,
    /// How often the AutoPause scanner runs.
    pub autopause_scan_secs: u64,
    /// Domain allowlist for L7 egress (empty = no L7 filter).
    pub egress_allow_domains: Vec<String>,
    /// Inject `Authorization` on matching Host (never exposed to the guest).
    pub credential_vault: Vec<CredentialInject>,
    /// Directory for OCI→template builds and snapshot templates.
    pub templates_dir: Option<PathBuf>,
    /// Bind address for the live L7 egress proxy (empty = disabled).
    pub egress_proxy_listen: String,
    /// Default guest port for `/sandbox/{id}/…` when no port is in the path.
    #[serde(default = "default_http_proxy_port")]
    pub http_proxy_default_port: u16,
    /// VM-edge dataplane. Legacy nftables is the default; native eBPF and
    /// Cilium-coexistence modes are explicit opt-ins.
    pub dataplane: DataplaneConfig,
}

fn default_http_proxy_port() -> u16 {
    8080
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            autopause_idle_secs: 0,
            autopause_scan_secs: 10,
            egress_allow_domains: Vec::new(),
            credential_vault: Vec::new(),
            templates_dir: None,
            egress_proxy_listen: String::new(),
            http_proxy_default_port: default_http_proxy_port(),
            dataplane: DataplaneConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "kebab-case")]
pub enum DataplaneMode {
    /// Existing nftables implementation.
    #[default]
    Legacy,
    /// FluxVM-owned TC/eBPF program pinned under `pin_root`.
    Ebpf,
    /// Verify Cilium is present, then attach FluxVM's VM-edge TC/eBPF
    /// program without modifying Cilium's private BPF maps.
    Cilium,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DataplaneConfig {
    pub mode: DataplaneMode,
    pub bpf_object: PathBuf,
    pub pin_root: PathBuf,
    /// If true, a dataplane load/attach failure fails VM creation/start.
    /// If false, FluxVM logs the failure and falls back to nftables.
    pub required: bool,
    /// Default action when no CIDR entry matches. `true` preserves the
    /// pre-eBPF allow-all behavior until an operator opts into deny-by-default.
    pub default_allow: bool,
    /// IPv4/IPv6 destination CIDRs allowed by the native eBPF LPM tries.
    /// IPv6 policy is native-only and will not silently downgrade to nftables.
    pub allow_cidrs: Vec<String>,
    /// L4 allowlist entries (`tcp/443`, `udp/53`, …).
    pub allow_ports: Vec<String>,
    /// Native eBPF fixed-window bandwidth ceiling (megabits/second).
    pub max_egress_mbps: Option<u32>,
    /// Native eBPF fixed-window packet-rate ceiling.
    pub max_egress_pps: Option<u32>,
    /// Allowed-flow ringbuf sampling: 0=off, N≈1/N packets.
    pub sample_rate: u32,
    /// Optional standalone node-ingress XDP guard (disabled with Cilium).
    pub xdp: XdpConfig,
}

impl Default for DataplaneConfig {
    fn default() -> Self {
        Self {
            mode: DataplaneMode::Legacy,
            bpf_object: "/usr/lib/fluxvm/bpf/fluxvm_tc.bpf.o".into(),
            pin_root: "/sys/fs/bpf/fluxvm".into(),
            required: false,
            default_allow: true,
            allow_cidrs: Vec::new(),
            allow_ports: Vec::new(),
            max_egress_mbps: None,
            max_egress_pps: None,
            sample_rate: 0,
            xdp: XdpConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct XdpConfig {
    pub enabled: bool,
    pub interface: Option<String>,
    pub bpf_object: PathBuf,
    pub pin_root: PathBuf,
    pub required: bool,
    /// IPv4/IPv6 source CIDRs rejected at XDP.
    pub block_cidrs: Vec<String>,
}

impl Default for XdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interface: None,
            bpf_object: "/usr/lib/fluxvm/bpf/fluxvm_xdp.bpf.o".into(),
            pin_root: "/sys/fs/bpf/fluxvm".into(),
            required: false,
            block_cidrs: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CredentialInject {
    /// Match request Host / SNI (exact or suffix with leading `.`).
    pub host: String,
    /// Header value injected by the egress proxy (e.g. `Bearer …`).
    pub authorization: String,
}

/// Settings for `StorageBackend::CephRbd` (see `model::StorageBackend`) —
/// unused by every other storage backend, which need no configuration at
/// all (LVM's volume group is read off the request's device path, NBD needs
/// nothing beyond `qemu-nbd` being installed). Ceph RBD support has not
/// been exercised against a real cluster in this project's own testing.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StorageConfig {
    /// Ceph client identity used for both `rbd` CLI calls and QEMU's `rbd:`
    /// URI (`id=`, without the `client.` prefix).
    pub ceph_user: String,
    /// Path to `ceph.conf`. `None` lets the `rbd` CLI and QEMU fall back to
    /// their own default search paths (`/etc/ceph/ceph.conf`).
    pub ceph_conf: Option<PathBuf>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            ceph_user: "admin".into(),
            ceph_conf: None,
        }
    }
}

/// Named, checksummed, optionally-signed base images — see
/// `fluxvm_image::catalog`. `path: None` (the default) disables the
/// catalog entirely: `CreateVmRequest.image` is always treated as a literal
/// path/URL, exactly like before this existed.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct CatalogConfig {
    pub path: Option<PathBuf>,
    /// Base64-encoded Ed25519 public keys. Empty (the default) means
    /// catalog entries don't need to be signed at all. Non-empty means
    /// *every* catalog entry used to create a VM must carry a valid
    /// signature from one of these keys — there is no per-entry opt-out.
    pub trusted_signers: Vec<String>,
    /// Optional cosign/Sigstore identity strings. When non-empty, resolve
    /// shells out to `cosign verify-blob` against the local image path
    /// (requires `cosign` on PATH).
    pub cosign_identities: Vec<String>,
}

/// Firecracker-only: runs the VM through Firecracker's own `jailer` binary
/// (chroot, uid/gid drop, cgroups) instead of exec'ing `firecracker`
/// directly. `enabled: false` (the default) is a full no-op — every
/// Firecracker VM launches exactly as it did before this existed. QEMU and
/// Cloud Hypervisor have no jailer equivalent and ignore this entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JailerConfig {
    pub enabled: bool,
    pub jailer_binary: String,
    /// The uid/gid `jailer` drops privileges to after chrooting — must be
    /// non-root and (for a real security boundary) not shared with any
    /// other tenant's jail. Defaults match the values commonly used in
    /// Firecracker's own getting-started docs; change them for anything
    /// beyond a single-tenant host.
    pub uid: u32,
    pub gid: u32,
    /// Base directory jailer creates `<exec-file-name>/<vm-id>/root/` under.
    /// Must be on the same filesystem as `state_dir` for the hardlink-based
    /// resource placement in `fluxvm-firecracker` to avoid falling back
    /// to a full copy of the (potentially multi-GB) rootfs.
    pub chroot_base_dir: PathBuf,
}

impl Default for JailerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            jailer_binary: "jailer".into(),
            uid: 123,
            gid: 100,
            chroot_base_dir: "/srv/jailer".into(),
        }
    }
}

/// REST API bearer-token auth, enforced by `fluxvm-api`'s auth middleware.
/// Empty `tokens` with `require` false keeps local-dev open (admin). When
/// `require` is true, or when listen is non-loopback and tokens are empty,
/// the API refuses to serve mutating routes without tokens (fail-closed).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AuthConfig {
    pub tokens: Vec<ApiToken>,
    /// When true, empty `tokens` is rejected at serve-time (and middleware
    /// returns 401). Defaults false for loopback ergonomics.
    pub require: bool,
    /// Per-token concurrent VM quota (None = unlimited). Checked at create.
    pub max_vms_per_token: Option<usize>,
    /// Per-token aggregate memory MiB quota.
    pub max_memory_mib_per_token: Option<u64>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            tokens: Vec::new(),
            require: false,
            max_vms_per_token: None,
            max_memory_mib_per_token: None,
        }
    }
}

impl AuthConfig {
    /// Fail closed when explicitly required, or when binding off-loopback
    /// with no tokens configured.
    pub fn must_authenticate(&self, listen: &str) -> bool {
        if self.require {
            return true;
        }
        if self.tokens.is_empty() && !is_loopback_listen(listen) {
            return true;
        }
        !self.tokens.is_empty()
    }
}

pub fn is_loopback_listen(listen: &str) -> bool {
    listen.starts_with("127.0.0.1:")
        || listen.starts_with("localhost:")
        || listen.starts_with("[::1]:")
        || listen == "127.0.0.1"
        || listen == "localhost"
        || listen == "::1"
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiToken {
    pub token: String,
    pub role: Role,
    #[serde(default)]
    pub name: Option<String>,
}

/// `Admin` can do anything (create/stop/pause/resume/exec/delete/build
/// images). `ReadOnly` can only list/get VMs — a valid token of either role
/// is enough to satisfy `/metrics`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Role {
    Admin,
    ReadOnly,
}

/// Constant-time comparison so a mismatched API token can't be brute-forced
/// via response-time measurement.
pub fn constant_time_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Admission limits enforced by `fluxvm_scheduler::validate_policy` before
/// a VM is created. Every field defaults to unrestricted (`None`), so an
/// operator opts in to only the limits they want by setting them in
/// `[policy]` — an empty/absent `[policy]` table behaves exactly like the
/// pre-policy MVP.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct Policy {
    pub max_vcpus: Option<u8>,
    pub max_memory_mib: Option<u64>,
    pub max_disk_gib: Option<u64>,
    /// If set, every request must specify a `ttl_seconds` at or below this
    /// value — an unbounded (`ttl_seconds: null`) VM is rejected too, since
    /// the whole point of a TTL cap is that nothing can run forever.
    pub max_ttl_seconds: Option<u64>,
    /// If set, only these backends may be used (checked against the
    /// already-resolved backend, so `"auto"` is checked as whatever it
    /// resolved to, not as `"auto"` itself).
    pub allowed_backends: Option<Vec<BackendKind>>,
    /// If set, the request's `image` must be underneath one of these
    /// directories (plain path-prefix check, not a symlink-resistant
    /// containment guarantee — sufficient to stop tenants pointing at
    /// arbitrary host paths, not a sandboxing boundary).
    pub allowed_image_dirs: Option<Vec<PathBuf>>,
    /// If set, only these network modes are admitted (`none`, `user`,
    /// `tap`, `macvtap`).
    pub allowed_network_modes: Option<Vec<String>>,
    /// When false (default), non-empty `extra_args` is rejected.
    #[serde(default)]
    pub allow_extra_args: bool,
}

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let raw = fs::read_to_string(path)
            .with_context(|| format!("reading config {}", path.display()))?;
        toml::from_str(&raw).with_context(|| format!("parsing config {}", path.display()))
    }

    pub fn ensure_dirs(&self) -> Result<()> {
        fs::create_dir_all(&self.state_dir)?;
        fs::create_dir_all(&self.run_dir)?;
        Ok(())
    }
}
