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
    /// QEMU only, optional: host-wide default for `req.firmware` when a
    /// request wants UEFI but omits the field -- mirrors
    /// `cloud_hypervisor_firmware`'s fallback role. Per-request
    /// `firmware` always wins when set.
    pub qemu_ovmf_code: Option<PathBuf>,
    /// QEMU only: a *template* OVMF_VARS.fd (read-only; never written to
    /// directly -- copied once per VM into `<workspace>/ovmf_vars.fd` on
    /// first launch, then that per-VM copy is reused/persisted across
    /// stop/start so enrolled keys and boot order survive). Required
    /// whenever a VM's effective firmware (`req.firmware` or
    /// `qemu_ovmf_code`) resolves to Some -- deliberately not
    /// synthesized (a wrong-size zero-filled file risks QEMU pflash
    /// errors or a vars store OVMF can't actually use), fails closed
    /// with a clear error instead of guessing. See
    /// docs/secure-boot-tpm.md.
    pub qemu_ovmf_vars_template: Option<PathBuf>,
    /// QEMU only, consulted when `req.tpm` is set: the `swtpm` binary,
    /// resolved via $PATH like `virtiofsd_binary`/`qemu_binary`.
    pub swtpm_binary: String,
    pub default_bridge: Option<String>,
    pub reaper_interval_secs: u64,
    pub policy: Policy,
    pub auth: AuthConfig,
    /// Optional TLS for the REST API (server cert/key; optional client CA = mTLS).
    #[serde(default)]
    pub tls: TlsConfig,
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
            qemu_ovmf_code: None,
            qemu_ovmf_vars_template: None,
            swtpm_binary: "swtpm".into(),
            default_bridge: Some("vmbr0".into()),
            reaper_interval_secs: 5,
            policy: Policy::default(),
            auth: AuthConfig::default(),
            tls: TlsConfig::default(),
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
    /// VM service load-balancing and optional north-south host/XDP hooks.
    pub service: ServiceFabricConfig,
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
            service: ServiceFabricConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServiceFabricConfig {
    /// Physical interfaces that act as north-south service edges. Empty means
    /// service VIPs are east-west/VM-edge only.
    pub north_south_interfaces: Vec<String>,
    /// Attach the optional XDP accelerator on north-south interfaces. This is
    /// rejected in dataplane.mode=cilium to avoid replacing Cilium's XDP hook.
    pub xdp_acceleration: bool,
    /// XDP service object. It reuses maps from the host TC service instance.
    pub xdp_object: PathBuf,
    /// Opt-in cgroup/connect{4,6} acceleration for node-local host sockets.
    /// Master switch attaches both v4 and v6. Fail-open: TC/XDP remains the
    /// canonical path if attach fails.
    pub cgroup_connect: bool,
    /// BPF object for cgroup/connect{4,6} (shares host TC pinmaps when attached).
    pub connect_object: PathBuf,
    /// Compiled map capacity tier (`S`/`M`/`L`). Selects tiered BPF objects
    /// (`fluxvm_service_tier_{S,M,L}.bpf.o`; default `M` uses `fluxvm_service.bpf.o`)
    /// and drives pressure-controller capacity. Changing tier forces a pin reload.
    pub map_tier: String,
    /// Soft pressure percent (conntrack) that triggers aggressive GC.
    pub pressure_soft_percent: u8,
    /// Hard pressure percent that closes the service guard and forces reload.
    pub pressure_hard_percent: u8,
    /// Enable per-service EDT pacing when services set `max_egress_mbps`.
    pub edt_enabled: bool,
    /// Interfaces where FluxVM may install/manage `fq` for EDT (never silent).
    pub edt_interfaces: Vec<String>,
    /// When true, run `tc qdisc replace … fq` on `edt_interfaces`.
    pub edt_manage_fq: bool,
    /// OTLP/HTTP JSON endpoint for FluxScope service flow export (optional).
    pub otlp_endpoint: Option<String>,
    /// Timeout for OTLP export requests in milliseconds.
    pub otlp_timeout_ms: u64,
}

impl Default for ServiceFabricConfig {
    fn default() -> Self {
        Self {
            north_south_interfaces: Vec::new(),
            xdp_acceleration: false,
            xdp_object: "/usr/lib/fluxvm/bpf/fluxvm_service_xdp.bpf.o".into(),
            cgroup_connect: false,
            connect_object: "/usr/lib/fluxvm/bpf/fluxvm_service_connect.bpf.o".into(),
            map_tier: "M".into(),
            pressure_soft_percent: 70,
            pressure_hard_percent: 90,
            edt_enabled: false,
            edt_interfaces: Vec::new(),
            edt_manage_fq: false,
            otlp_endpoint: None,
            otlp_timeout_ms: 5_000,
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
    /// `[[catalog.trusted_signers]]` — named Ed25519 public keys, the same
    /// array-of-tables-with-a-keying-field shape `[[auth.tokens]]` already
    /// uses, rather than a bare list of keys with no attached identity.
    /// Empty (the default) means catalog entries don't need to be signed
    /// at all. Non-empty means *every* catalog entry used to create a VM
    /// must carry a valid signature from one of these keys — there is no
    /// per-entry opt-out. The matched entry's `name` is what
    /// `fluxvm_image::catalog::CatalogListEntry.signed_by` reports —
    /// real signer identity, derived fresh at verify time from which key
    /// actually matched, never trusted from anything the signed payload
    /// itself claims.
    pub trusted_signers: Vec<TrustedSigner>,
    /// Optional cosign/Sigstore identity strings. When non-empty, resolve
    /// shells out to `cosign verify-blob` against the local image path
    /// (requires `cosign` on PATH).
    pub cosign_identities: Vec<String>,
}

/// One named Ed25519 public key allowed to sign catalog entries -- see
/// `CatalogConfig::trusted_signers`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustedSigner {
    /// A human-readable label for this key (e.g. "release-ci",
    /// "platform-team") -- never cryptographically verified itself (it's
    /// operator-asserted config, the same trust level `[[auth.tokens]]`'s
    /// own `name` field already has), just what gets reported back as
    /// `signed_by` once the *key* has verified a signature.
    pub name: String,
    /// Base64-encoded Ed25519 public key (32 bytes).
    pub public_key: String,
}

/// Firecracker-only: runs the VM through Firecracker's own `jailer` binary
/// (chroot, uid/gid drop, cgroups) instead of exec'ing `firecracker`
/// directly. `enabled: false` (the default) is a full no-op — every
/// Firecracker VM launches exactly as it did before this existed. QEMU and
/// Cloud Hypervisor have no jailer equivalent and ignore this entirely.
///
/// Production profiles should set `enforce = true` (or `auth.require` with a
/// non-loopback `listen`): Firecracker launches then fail closed unless
/// `enabled` is also true. See docs/capability-figures.md.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct JailerConfig {
    pub enabled: bool,
    /// When true, refuse Firecracker launches (and `fluxctl serve` if
    /// Firecracker is an allowed backend) unless `enabled` is also true.
    /// Independently, `Config::jailer_required` is true when
    /// `auth.require` and listen is non-loopback — matching Firecracker's
    /// "production via jailer only" rule without surprising loopback labs.
    #[serde(default)]
    pub enforce: bool,
    pub jailer_binary: String,
    /// The uid/gid `jailer` drops privileges to after chrooting — must be
    /// non-root and (for a real security boundary) not shared with any
    /// other tenant's jail. Defaults match the values commonly used in
    /// Firecracker's own getting-started docs; change them for anything
    /// beyond a single-tenant host.
    pub uid: u32,
    pub gid: u32,
    /// When both are set, each non-empty tenant is assigned one unused uid
    /// inside `[uid_range_start, uid_range_start + uid_range_len)` and that
    /// assignment is stored under the state directory. The configured `gid`
    /// is unchanged. Unset keeps the single host-wide `uid`/`gid`.
    #[serde(default)]
    pub uid_range_start: Option<u32>,
    #[serde(default)]
    pub uid_range_len: Option<u32>,
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
            enforce: false,
            jailer_binary: "jailer".into(),
            uid: 123,
            gid: 100,
            uid_range_start: None,
            uid_range_len: None,
            chroot_base_dir: "/srv/jailer".into(),
        }
    }
}

impl JailerConfig {
    /// Host-wide jail identity. Per-tenant ids are allocated by
    /// [`assign_tenant_uid`], which persists them so two tenants cannot
    /// hash onto the same uid.
    pub fn identity_for_tenant(&self, _tenant: Option<&str>) -> (u32, u32) {
        (self.uid, self.gid)
    }
}

/// Allocate a stable jailer uid for `tenant`. The same tenant keeps its uid.
/// The range is never aliased: a full range returns an error. `gid` stays
/// the configured group.
pub fn assign_tenant_uid(
    state_dir: &Path,
    jailer: &JailerConfig,
    tenant: Option<&str>,
) -> Result<(u32, u32)> {
    let (Some(start), Some(len)) = (jailer.uid_range_start, jailer.uid_range_len) else {
        return Ok((jailer.uid, jailer.gid));
    };
    if len == 0 {
        return Ok((jailer.uid, jailer.gid));
    }
    let Some(tenant) = tenant.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok((jailer.uid, jailer.gid));
    };
    fs::create_dir_all(state_dir).context("creating jailer uid state directory")?;
    let lock_path = state_dir.join("jailer-uids.lock");
    let path = state_dir.join("jailer-uids.json");
    let lock_file = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .context("opening jailer uid lock")?;
    // SAFETY: exclusive flock released when `lock_file` is dropped.
    use std::os::unix::io::AsRawFd;
    if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        anyhow::bail!(
            "locking jailer uid assignments: {}",
            std::io::Error::last_os_error()
        );
    }
    let mut map: std::collections::BTreeMap<String, u32> = if path.exists() {
        let raw = fs::read_to_string(&path).context("reading jailer uid assignments")?;
        if raw.trim().is_empty() {
            std::collections::BTreeMap::new()
        } else {
            serde_json::from_str(&raw).context("parsing jailer uid assignments")?
        }
    } else {
        std::collections::BTreeMap::new()
    };
    if let Some(uid) = map.get(tenant) {
        return Ok((*uid, jailer.gid));
    }
    let end = start.saturating_add(len);
    let uid = (start..end)
        .find(|candidate| !map.values().any(|used| used == candidate))
        .with_context(|| {
            format!("jailer uid range {start}..{end} is exhausted; refusing to alias tenants")
        })?;
    map.insert(tenant.to_string(), uid);
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, serde_json::to_vec_pretty(&map)?).context("writing jailer uid assignments")?;
    fs::rename(&tmp, &path).context("renaming jailer uid assignments")?;
    Ok((uid, jailer.gid))
}

/// TLS termination for `fluxctl serve`. When `cert` + `key` are set the API
/// listens with HTTPS. When `client_ca` is also set, clients must present a
/// certificate signed by that CA (mTLS). Bearer tokens / OIDC still apply.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TlsConfig {
    pub cert: Option<PathBuf>,
    pub key: Option<PathBuf>,
    /// PEM CA bundle; when set, require and verify client certificates.
    pub client_ca: Option<PathBuf>,
}

impl TlsConfig {
    pub fn enabled(&self) -> bool {
        self.cert.is_some() && self.key.is_some()
    }

    pub fn mtls_enabled(&self) -> bool {
        self.enabled() && self.client_ca.is_some()
    }
}

/// REST API bearer-token auth, enforced by `fluxvm-api`'s auth middleware.
/// Empty `tokens` with `require` false keeps local-dev open (admin). When
/// `require` is true, or when listen is non-loopback and tokens are empty,
/// the API refuses to serve mutating routes without tokens (fail-closed).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
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
    /// Optional OIDC issuer URL. When set with `oidc_audience`, FluxVM
    /// accepts IdP-issued bearer JWTs validated via discovery + JWKS
    /// (in addition to static `[[auth.tokens]]`).
    #[serde(default)]
    pub oidc_issuer: Option<String>,
    #[serde(default)]
    pub oidc_audience: Option<String>,
    /// Opt-in REST API request rate limit: average requests/second allowed
    /// per caller before `fluxvm-api` starts returning 429. Both this and
    /// `rate_limit_burst` must be set together (validated at serve-time) --
    /// `None` (the default) means no rate limiting at all, byte-for-byte
    /// the behavior before this existed. Keyed by authenticated token/OIDC
    /// actor name when the request carries one, falling back to remote IP
    /// for an anonymous caller on a loopback listener with no credentials
    /// configured -- see `fluxvm-api`'s `rate_limit_middleware`.
    #[serde(default)]
    pub rate_limit_rps: Option<f64>,
    /// Burst size (tokens) paired with `rate_limit_rps` -- a caller can
    /// spend up to this many requests instantly before the average-rate
    /// limit starts throttling them.
    #[serde(default)]
    pub rate_limit_burst: Option<u32>,
}

impl AuthConfig {
    /// OIDC JWT path is enabled when both issuer and audience are set.
    pub fn oidc_enabled(&self) -> bool {
        self.oidc_issuer.as_ref().is_some_and(|s| !s.is_empty())
            && self.oidc_audience.as_ref().is_some_and(|s| !s.is_empty())
    }

    /// Rate limiting is enabled only when both `rate_limit_rps` and
    /// `rate_limit_burst` are set to a positive value -- mirrors
    /// `oidc_enabled`'s "both fields or neither" shape. Returns the
    /// resolved `(rps, burst)` pair when enabled.
    pub fn rate_limit_enabled(&self) -> Option<(f64, u32)> {
        match (self.rate_limit_rps, self.rate_limit_burst) {
            (Some(rps), Some(burst)) if rps > 0.0 && burst > 0 => Some((rps, burst)),
            _ => None,
        }
    }

    /// Fail closed when explicitly required, or when binding off-loopback
    /// with no tokens / OIDC configured.
    pub fn must_authenticate(&self, listen: &str) -> bool {
        if self.require || self.oidc_enabled() {
            return true;
        }
        if self.tokens.is_empty() && !is_loopback_listen(listen) {
            return true;
        }
        !self.tokens.is_empty()
    }

    /// True when some credential path is configured (static tokens and/or OIDC).
    pub fn has_credentials(&self) -> bool {
        !self.tokens.is_empty() || self.oidc_enabled()
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
    /// When set, VMs created with this token inherit this tenant unless the
    /// request already specified one.
    #[serde(default)]
    pub tenant: Option<String>,
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
    /// directories. The check canonicalizes existing path components, so a
    /// symlink that escapes the directory is rejected. It runs on create
    /// only.
    pub allowed_image_dirs: Option<Vec<PathBuf>>,
    /// When true, create accepts only a catalog name whose signature
    /// verifies against `[[catalog.trusted_signers]]`. Default false, so
    /// existing literal image paths keep working.
    #[serde(default)]
    pub require_catalog_names: bool,
    /// Optional host-wide vCPU cap, summed from the quota ledger. Unset
    /// means unrestricted.
    #[serde(default)]
    pub max_vcpus_host: Option<u32>,
    /// Optional host-wide memory cap in MiB. Unset means unrestricted.
    #[serde(default)]
    pub max_memory_mib_host: Option<u64>,
    /// If set, only these network modes are admitted (`none`, `user`,
    /// `tap`, `macvtap`).
    pub allowed_network_modes: Option<Vec<String>>,
    /// When false (default), non-empty `extra_args` is rejected.
    #[serde(default)]
    pub allow_extra_args: bool,
    /// Applied at cgroup attach for every backend: set `cpu.max` to this
    /// percent of one host CPU (see `CpuMax::from_percent`). `None` =
    /// leave cpu.max unlimited (operator can still PATCH resources later).
    #[serde(default)]
    pub default_cpu_quota_percent: Option<u8>,
    /// When true, set `memory.max` to the guest's `memory_mib` in bytes at
    /// cgroup attach so host overcommit is explicit. Default false keeps
    /// today's unlimited memory.max (cgroup still tracks usage).
    #[serde(default)]
    pub memory_max_equals_guest: bool,
    /// Per-tenant aggregate caps, keyed by `CreateVmRequest.tenant` --
    /// `[[policy.tenants]]`, the same array-of-tables-with-a-keying-field
    /// shape `[[auth.tokens]]` already uses (`ApiToken.tenant`), rather
    /// than a `HashMap<String, _>`-keyed TOML table, which has no
    /// precedent elsewhere in this config. Unlike the rest of `Policy`
    /// above (all per-request-only checks against one incoming request in
    /// isolation), these are aggregate: summed across every existing VM
    /// already belonging to that tenant plus the incoming request. A
    /// tenant with no matching entry here is unrestricted by this
    /// mechanism (still subject to every global `Policy` field above,
    /// unchanged).
    #[serde(default)]
    pub tenants: Vec<TenantPolicy>,
}

/// One tenant's aggregate admission caps -- see `Policy::tenants`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantPolicy {
    /// Matched against `CreateVmRequest.tenant` (already authoritative by
    /// the time `fluxvm-scheduler` sees it -- resolved once, at request
    /// entry, from `[[auth.tokens]]`'s own `tenant` field or an OIDC
    /// claim; see `fluxvm-api`'s `auth_middleware`/`create_vm`).
    pub tenant: String,
    /// Total vCPUs across every `Running`/`Creating`/etc. VM this tenant
    /// already owns, plus the incoming request's own `vcpus` -- rejected
    /// if that sum would exceed this.
    #[serde(default)]
    pub max_vcpus_total: Option<u32>,
    /// Same shape as `max_vcpus_total`, for `memory_mib`.
    #[serde(default)]
    pub max_memory_mib_total: Option<u64>,
    /// Maximum number of VMs (any status) this tenant may own at once.
    #[serde(default)]
    pub max_vms_total: Option<usize>,
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

    /// True when Firecracker must run under jailer: explicit `[jailer]
    /// enforce`, or production-shaped `auth.require` on a non-loopback
    /// listen (Firecracker's "jailer only in production" rule).
    pub fn jailer_required(&self) -> bool {
        self.jailer.enforce || (self.auth.require && !is_loopback_listen(&self.listen))
    }
}

#[cfg(test)]
mod jailer_required_tests {
    use super::*;

    #[test]
    fn default_lab_does_not_require_jailer() {
        let cfg = Config::default();
        assert!(!cfg.jailer_required());
    }

    #[test]
    fn enforce_flag_requires_jailer() {
        let mut cfg = Config::default();
        cfg.jailer.enforce = true;
        assert!(cfg.jailer_required());
    }

    #[test]
    fn auth_require_on_non_loopback_requires_jailer() {
        let mut cfg = Config::default();
        cfg.auth.require = true;
        cfg.listen = "0.0.0.0:7788".into();
        assert!(cfg.jailer_required());
    }

    #[test]
    fn auth_require_on_loopback_does_not_require_jailer() {
        let mut cfg = Config::default();
        cfg.auth.require = true;
        cfg.listen = "127.0.0.1:7788".into();
        assert!(!cfg.jailer_required());
    }

    #[test]
    fn tenant_jailer_uids_are_stable_and_distinct() {
        let dir = std::env::temp_dir().join(format!("fluxvm-jailer-uids-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut jailer = JailerConfig::default();
        assert_eq!(
            assign_tenant_uid(&dir, &jailer, Some("acme")).unwrap(),
            (123, 100)
        );
        jailer.uid_range_start = Some(2000);
        jailer.uid_range_len = Some(2);
        let a = assign_tenant_uid(&dir, &jailer, Some("acme")).unwrap();
        let b = assign_tenant_uid(&dir, &jailer, Some("other")).unwrap();
        assert_eq!(a, assign_tenant_uid(&dir, &jailer, Some("acme")).unwrap());
        assert_ne!(a.0, b.0);
        assert_eq!(a.1, 100);
        assert_eq!(b.1, 100);
        assert!((2000..2002).contains(&a.0));
        assert!((2000..2002).contains(&b.0));
        assert!(assign_tenant_uid(&dir, &jailer, Some("third")).is_err());
        assert_eq!(assign_tenant_uid(&dir, &jailer, None).unwrap(), (123, 100));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
