// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{Parser, Subcommand};
use fluxvm_api as api;
use fluxvm_core::{
    config::Config,
    model::{ClaimOverrides, CreateVmRequest, MigrationMode, MigrationStartRequest, ResourcePatch},
};
use fluxvm_guest_protocol::AgentResponse;
use fluxvm_image::{self as image, BuildImageRequest};
use fluxvm_scheduler::VmManager;
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

#[derive(Parser)]
#[command(
    name = "fluxvm",
    version,
    about = "Zyvor FluxVM: disposable compute engine for QEMU, Cloud Hypervisor, Firecracker, and FluxVM hypervisor"
)]
struct Cli {
    #[arg(long, env = "FLUXVM_CONFIG")]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve,
    Create {
        #[arg(long)]
        spec: PathBuf,
    },
    List,
    Get {
        id: Uuid,
    },
    /// Correlate Runtime Intelligence with VM-edge policy and flow state.
    /// Works as a direct one-shot and does not require the intelligence HTTP daemon.
    Diagnose {
        id: Uuid,
    },
    /// Live VM Flight Recorder events from KVM/scheduler/block/vhost eBPF probes.
    Trace {
        id: Uuid,
        #[arg(long, default_value_t = 5)]
        seconds: u64,
        #[arg(long, default_value_t = 128)]
        limit: usize,
        /// json | jsonl
        #[arg(long, default_value = "json")]
        output: String,
    },
    /// Relaunch a Stopped VM from its existing disk (skips image
    /// clone/cloud-init reseed — see VmManager::start).
    Start {
        id: Uuid,
    },
    Stop {
        id: Uuid,
    },
    Pause {
        id: Uuid,
    },
    Resume {
        id: Uuid,
    },
    /// Freeze every process in the VM's cgroup via the cgroup v2 freezer
    /// (`cgroup.freeze`) — a kernel-level stop that works even if the VMM's
    /// own control socket is unresponsive, unlike `pause` (QMP/API-level
    /// vCPU stop, tracked as the VM's `Paused` status). REST equivalent:
    /// `POST /v1/vms/{id}/freeze`. See docs/operations.md's "Resource
    /// control (cgroup v2)" section.
    Freeze {
        id: Uuid,
    },
    /// Thaw a VM previously frozen with `freeze`. REST equivalent:
    /// `POST /v1/vms/{id}/thaw`.
    Thaw {
        id: Uuid,
    },
    /// Report whether a VM's cgroup is currently frozen. REST equivalent:
    /// `GET /v1/vms/{id}/frozen`.
    Frozen {
        id: Uuid,
    },
    /// Apply cgroup v2 resource-control settings to a running VM — CPU
    /// quota, memory limit, I/O weight, max PIDs, and/or host CPU pinning.
    /// REST equivalent: `POST /v1/vms/{id}/resources`. See
    /// docs/operations.md's "Resource control (cgroup v2)" section. Every
    /// flag is optional and, like the `ResourcePatch` body it becomes, only
    /// the fields you actually pass are touched — omitting a flag leaves
    /// that control untouched, it does not reset it. At least one flag is
    /// required; a bare `fluxvm resources <id>` with nothing to change is
    /// rejected rather than silently doing nothing.
    Resources {
        id: Uuid,
        /// CPU quota as a percentage of one core (150 = 1.5 cores).
        #[arg(long)]
        cpu_quota_percent: Option<u32>,
        /// Memory limit in bytes.
        #[arg(long)]
        memory_max_bytes: Option<u64>,
        /// I/O weight, 1-10000 (cgroup default: 100).
        #[arg(long)]
        io_weight: Option<u32>,
        /// Maximum number of PIDs allowed in the VM's cgroup.
        #[arg(long)]
        pids_max: Option<u64>,
        /// Host CPU cores to pin the VM to, in the same set syntax
        /// `cpuset.cpus` itself reads back, e.g. `0-3`, `0,2,4`, or
        /// `0-1,4-5`.
        #[arg(long)]
        cpuset_cpus: Option<String>,
    },
    /// Run a command inside the guest over vsock (requires agent.enabled in the VM spec).
    Exec {
        id: Uuid,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Health-check the vsock guest agent (requires agent.enabled) without
    /// spending a real `exec` round trip just to find out it's reachable —
    /// distinct from `qga ping`, which checks the QEMU guest-agent channel.
    Ping {
        id: Uuid,
    },
    /// Copy a local file into the guest over vsock (requires agent.enabled)
    /// — the REST `/agent/put-file` route's CLI equivalent, previously only
    /// reachable by hand-rolling the HTTP call yourself.
    CopyTo {
        id: Uuid,
        /// Path to the file on this host.
        local: PathBuf,
        /// Destination path inside the guest; parent directories are
        /// created as needed.
        remote: String,
        /// Unix permission bits to set on the guest-side file, e.g. `600`.
        /// Defaults to `644` if unset.
        #[arg(long)]
        mode: Option<u32>,
    },
    /// Copy a file out of the guest over vsock (requires agent.enabled) —
    /// the REST `/agent/get-file` route's CLI equivalent. The guest file's
    /// own Unix permission bits are restored on the copy this host writes.
    CopyFrom {
        id: Uuid,
        /// Path to the file inside the guest.
        remote: String,
        /// Path to write on this host.
        local: PathBuf,
    },
    /// Live VM migration -- source-side VMM transport only (QEMU and Cloud
    /// Hypervisor; see docs/runtime-boundary.md's runtime contract v1).
    /// Fabric owns host selection, storage, and target-arming; this is the
    /// standalone-mode escape hatch for triggering the same
    /// `/v1/vms/{id}/migration/*` REST primitives without Fabric or a raw
    /// HTTP call, the same reasoning `ping`/`copy-to`/`copy-from` closed for
    /// the vsock agent.
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
    /// QEMU guest-agent (virtio-serial) helpers — Zyvor/GuestKit Windows agent.
    Qga {
        #[command(subcommand)]
        command: QgaCommand,
    },
    Delete {
        id: Uuid,
    },
    BuildImage {
        #[arg(long)]
        spec: PathBuf,
    },
    /// Manage warm VM pools — pre-booted, paused VMs handed out on claim in
    /// roughly resume time instead of full create time.
    Pool {
        #[command(subcommand)]
        command: PoolCommand,
    },
    /// Manage the named/checksummed/optionally-signed image catalog (see
    /// config.catalog). Referencing a catalog name in a VM spec's `image`
    /// field (instead of a raw path) is handled automatically by `create` —
    /// these subcommands are only for building/signing/administering the
    /// catalog itself, and work offline against `catalog.path` with no
    /// `fluxvm serve` required.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// Security groups for the VM-edge dataplane.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// CNP documents compiled onto FluxVM security groups.
    Cnp {
        #[command(subcommand)]
        command: CnpCommand,
    },
    /// Reserved + group numeric identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Snapshot of identities, groups, CNPs, and labeled VMs.
    Observe,
    /// Production dataplane health, ipcache, and FQDN refresh.
    Dataplane {
        #[command(subcommand)]
        command: DataplaneCommand,
    },
    /// Hubble-lite flows and CiliumEndpoint views.
    Hubble {
        #[command(subcommand)]
        command: HubbleCommand,
    },
}

#[derive(Subcommand)]
enum QgaCommand {
    /// guest-ping over the VM's QGA unix socket.
    Ping { id: Uuid },
    /// Run PowerShell (-Command) inside the guest via QGA guest-exec.
    Powershell {
        id: Uuid,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Raw guest-exec (path + args).
    Exec {
        id: Uuid,
        #[arg(long)]
        path: String,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Open an inbound Windows firewall port (live PowerShell).
    FirewallOpen {
        id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "tcp")]
        protocol: String,
        #[arg(long)]
        timeout_seconds: Option<u64>,
    },
    /// Remove a Windows firewall rule by display name.
    FirewallClose {
        id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        timeout_seconds: Option<u64>,
    },
}

#[derive(Subcommand)]
enum MigrateCommand {
    /// Start a live migration to `destination` (a `tcp:host:port` or
    /// `unix:/path` URI -- `exec:` is rejected by the same shared allowlist
    /// the REST route validates against). Requires the VM to already be
    /// Running; both QEMU and Cloud Hypervisor sources are supported.
    Start {
        id: Uuid,
        #[arg(long)]
        destination: String,
        /// "pre-copy" (default) or "post-copy".
        #[arg(long, default_value = "pre-copy")]
        mode: String,
        #[arg(long)]
        bandwidth_mbps: Option<u64>,
        #[arg(long)]
        max_downtime_ms: Option<u64>,
        #[arg(long)]
        multifd_channels: Option<u8>,
    },
    /// Poll migration progress. QEMU only -- Cloud Hypervisor's
    /// send-migration is fire-and-forget and exposes no status-polling
    /// primitive (see docs/runtime-boundary.md); this errors clearly for a
    /// Cloud Hypervisor VM rather than hanging or guessing.
    Status { id: Uuid },
    /// Cancel an in-flight migration. QEMU only, same reason as `status`.
    Cancel { id: Uuid },
}

#[derive(Subcommand)]
enum CnpCommand {
    List,
    Get {
        name: String,
    },
    Apply {
        #[arg(long)]
        spec: PathBuf,
    },
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    List,
}

#[derive(Subcommand)]
enum DataplaneCommand {
    Health,
    Ipcache,
    /// Netns-sandbox `/28` IPAM pool utilization (capacity, allocated, free,
    /// and whether it's near exhaustion) — see docs/network-fabric.md.
    IpamStatus,
    RefreshDns,
    /// Show the VM-edge migration gate and schema generation.
    MigrationState {
        id: Uuid,
    },
    /// Freeze creation of new flows while preserving established conntrack.
    MigrationQuiesce {
        id: Uuid,
    },
    /// Export a migration-consistent conntrack/observability snapshot.
    MigrationExport {
        id: Uuid,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Import network state on the destination and leave it in restoring mode.
    MigrationRestore {
        id: Uuid,
        #[arg(long)]
        input: PathBuf,
    },
    /// Re-enable new flows after destination cutover, or cancel source quiesce.
    MigrationResume {
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum HubbleCommand {
    /// Packet flows (Hubble-style). Color by default; `--output plain` / `normal` for no ANSI.
    Observe {
        /// color | plain | normal | json
        #[arg(long, default_value = "color")]
        output: String,
        /// One-line summaries vs full hop path.
        #[arg(long, short = 'd')]
        detailed: bool,
        #[arg(long, default_value_t = 64)]
        limit: usize,
        /// FORWARDED | DROPPED | AUDIT | all
        #[arg(long, default_value = "all")]
        verdict: String,
        /// tcp | udp | icmp | all
        #[arg(long, default_value = "all")]
        protocol: String,
    },
    /// Alias for `observe --detailed`.
    Flow {
        #[arg(long, default_value = "color")]
        output: String,
        #[arg(long, default_value_t = 64)]
        limit: usize,
        #[arg(long, default_value = "all")]
        verdict: String,
        #[arg(long, default_value = "all")]
        protocol: String,
    },
    Endpoints,
}

#[derive(Subcommand)]
enum GroupCommand {
    List,
    Get {
        name: String,
    },
    Set {
        name: String,
        #[arg(long)]
        label: Vec<String>,
        #[arg(long)]
        allow_cidr: Vec<String>,
        #[arg(long)]
        deny_cidr: Vec<String>,
        #[arg(long)]
        allow_port: Vec<String>,
        #[arg(long)]
        default_allow: Option<bool>,
        #[arg(long)]
        allow_icmp: bool,
        #[arg(long)]
        priority: Option<u32>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        max_egress_mbps: Option<u32>,
        #[arg(long)]
        max_egress_pps: Option<u32>,
    },
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum CatalogCommand {
    /// Generate a fresh Ed25519 keypair for signing catalog entries. The
    /// private key is only ever printed here — store it yourself (this
    /// project has no opinion on how); put the public key into
    /// config.catalog.trusted_signers to require it going forward.
    Keygen,
    /// Sign a catalog entry and print it as JSON, or append it to
    /// --catalog-file if given (creating the file with an empty array
    /// first if it doesn't exist yet).
    Sign {
        /// Base64 Ed25519 private key, as printed by `catalog keygen`.
        #[arg(long)]
        key: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        sha256: String,
        #[arg(long, default_value = "qcow2")]
        format: String,
        #[arg(long)]
        distro: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        arch: Option<String>,
        /// Which CI pipeline produced these image bytes, e.g.
        /// "github-actions/build-images.yml" -- asserted by you, the
        /// signer, same posture as everything else on this command: not
        /// independently verified against the actual CI system, but
        /// tamper-evident (covered by the signature) once set.
        #[arg(long)]
        build_pipeline: Option<String>,
        /// The specific run/job id within --build-pipeline that produced
        /// this image.
        #[arg(long)]
        build_run_id: Option<String>,
        /// The source commit SHA the build was triggered from.
        #[arg(long)]
        build_commit: Option<String>,
        #[arg(long)]
        catalog_file: Option<PathBuf>,
    },
    /// List every catalog entry, each with a computed `signature_valid` /
    /// `signed_by` (see `GET /v1/images/catalog`). Reads `catalog.json`
    /// directly — works with no `fluxvm serve` running.
    List,
    /// Register a new catalog entry: fetches `source` first if it's a URL,
    /// then hashes whatever actually landed on disk (never trusts a
    /// caller-supplied sha256). The entry starts unsigned — sign it
    /// separately with `catalog sign` if `trusted_signers` is configured.
    Add {
        name: String,
        /// Local path or http(s):// URL.
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "qcow2")]
        format: String,
    },
    /// Remove a catalog entry. Refuses a `read_only` entry — `catalog
    /// unlock` it first.
    Remove { name: String },
    /// Rename a catalog entry. Clears its signature and `signed_at` — a
    /// signature covers the entry's name (see `canonical_payload`), so a
    /// renamed entry's old signature no longer vouches for it. Refuses a
    /// `read_only` entry.
    Rename { name: String, new_name: String },
    /// Clone a catalog entry under a new name. The clone is unsigned, same
    /// reasoning as `rename`.
    Clone { name: String, target_name: String },
    /// Copy a catalog entry's resolved local file to `dest` (fetching it
    /// first if `source` is a URL not yet cached).
    Export { name: String, dest: PathBuf },
    /// Mark a catalog entry read-only, protecting it from `remove`/`rename`
    /// — for a base image other entries get `clone`d from.
    Lock { name: String },
    /// Clear a catalog entry's read-only flag.
    Unlock { name: String },
    /// Remove cached downloads under `state_dir/downloads` that no current
    /// catalog entry's `source` still references by filename.
    Clean,
}

#[derive(Subcommand)]
enum PoolCommand {
    Create {
        #[arg(long)]
        spec: PathBuf,
    },
    List,
    Get {
        name: String,
    },
    /// Claim one ready VM from the pool. Replenishment is fired off as a
    /// background task so this command stays fast, which means it only
    /// reliably completes if `fluxvm serve` is already running against
    /// the same state_dir — this one-shot process exits right after
    /// printing the claimed VM, taking any still-in-flight replenishment
    /// down with it. Prefer `POST /v1/pools/{name}/claim` against a running
    /// `serve` daemon for guaranteed backfill.
    Claim {
        name: String,
        #[arg(long)]
        vm_name: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    /// Change a pool's target size without deleting and recreating it from
    /// the same spec. Growing blocks until the pool actually reaches its
    /// new size, same reasoning (and same `backfill_pool_sync` call) as
    /// `pool create` -- this is a one-shot process, so it can't rely on its
    /// own background backfill task surviving past printing the result.
    /// Shrinking happens synchronously either way: excess ready members are
    /// deleted immediately, not left for a reaper tick.
    Resize {
        name: String,
        #[arg(long)]
        size: usize,
    },
    Delete {
        name: String,
    },
}

async fn manager(cfg: Config) -> Result<Arc<VmManager>> {
    VmManager::new(cfg)
}

/// Parses `migrate start --mode`, matching `MigrationMode`'s own
/// `#[serde(rename_all = "kebab-case")]` spelling ("pre-copy"/"post-copy")
/// exactly rather than inventing a separate CLI vocabulary for the same two
/// values the wire format already uses.
fn parse_migration_mode(s: &str) -> Result<MigrationMode> {
    match s {
        "pre-copy" => Ok(MigrationMode::PreCopy),
        "post-copy" => Ok(MigrationMode::PostCopy),
        other => anyhow::bail!(
            "unknown migration mode {other:?}, expected \"pre-copy\" or \"post-copy\""
        ),
    }
}

/// Parses `--cpuset-cpus`' set syntax (`"0-3"`, `"0,2,4"`, `"0-1,4-5"`) into
/// a sorted, deduplicated list of CPU ids — the same notation
/// `fluxvm_cgroup::cpuset` reads `cpuset.cpus`/`cpuset.cpus.effective` back
/// as (see `parse_set`/`format_set` there), so a value copied straight out
/// of `fluxvm resources`'s own prior output, or read directly from
/// `cpuset.cpus`, round-trips. Deliberately its own, independent parser
/// rather than importing that one: this one additionally rejects an empty
/// spec (ambiguous here — the flag is `Option<String>`, so "clear the
/// pinning" is already expressed by simply omitting the flag, not by
/// passing an empty string) and a reversed range like `"5-2"` (silently
/// empty under plain `start..=end`, which would apply an empty cpuset
/// instead of erroring the way a typo like this should).
fn parse_cpuset_spec(s: &str) -> Result<Vec<u32>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "--cpuset-cpus was empty; omit the flag entirely to leave cpuset pinning untouched"
        );
    }
    let mut ids = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            anyhow::bail!("--cpuset-cpus {trimmed:?} has an empty entry between commas");
        }
        match part.split_once('-') {
            Some((start_str, end_str)) => {
                let start: u32 = start_str.trim().parse().with_context(|| {
                    format!("--cpuset-cpus {trimmed:?}: invalid range start {start_str:?}")
                })?;
                let end: u32 = end_str.trim().parse().with_context(|| {
                    format!("--cpuset-cpus {trimmed:?}: invalid range end {end_str:?}")
                })?;
                if start > end {
                    anyhow::bail!("--cpuset-cpus {trimmed:?}: range {start}-{end} has start > end");
                }
                ids.extend(start..=end);
            }
            None => {
                let id: u32 = part.parse().with_context(|| {
                    format!("--cpuset-cpus {trimmed:?}: invalid cpu id {part:?}")
                })?;
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// Reads a local file for `copy-to`, rejecting anything already too big for
/// the guest agent's own file-transfer cap before spending a base64 encode
/// and a vsock round trip on content the agent would just reject anyway —
/// see `fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES` and
/// `fluxvm-guest-agent`'s own `put_file`, which enforces the same limit
/// guest-side on the decoded bytes.
fn read_local_file_for_copy_to(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES {
        anyhow::bail!(
            "{} is {} bytes, exceeds the guest agent's {}-byte file-transfer limit",
            path.display(),
            bytes.len(),
            fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES,
        );
    }
    Ok(bytes)
}

/// Writes a `copy-from` response's content to `local`, restoring the same
/// Unix permission bits the guest reported the file had — so a copied-out
/// script, key, or config keeps behaving the way its mode implies instead of
/// silently landing at this process's umask default. Returns the number of
/// bytes written.
#[cfg(unix)]
fn write_copy_from_response(local: &Path, content_base64: &str, mode: u32) -> Result<usize> {
    use std::os::unix::fs::PermissionsExt;
    let bytes = B64
        .decode(content_base64)
        .context("decoding file content from guest agent")?;
    std::fs::write(local, &bytes).with_context(|| format!("writing {}", local.display()))?;
    std::fs::set_permissions(local, std::fs::Permissions::from_mode(mode & 0o777))
        .with_context(|| format!("setting permissions on {}", local.display()))?;
    Ok(bytes.len())
}

/// Non-Unix hosts have no `mode` bits of their own to restore — write the
/// content and leave permissions at whatever this platform defaults to.
#[cfg(not(unix))]
fn write_copy_from_response(local: &Path, content_base64: &str, _mode: u32) -> Result<usize> {
    let bytes = B64
        .decode(content_base64)
        .context("decoding file content from guest agent")?;
    std::fs::write(local, &bytes).with_context(|| format!("writing {}", local.display()))?;
    Ok(bytes.len())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fluxvm=info,tower_http=info".into()),
        )
        .init();
    let cli = Cli::parse();
    let cfg = Config::load(cli.config.as_deref())?;
    let m = manager(cfg.clone()).await?;

    match cli.command {
        Command::Serve => {
            if cfg.auth.must_authenticate(&cfg.listen) && !cfg.auth.has_credentials() {
                anyhow::bail!(
                    "auth is required for listen={} but no [[auth.tokens]] and OIDC is not \
                     configured — add tokens, set auth.oidc_issuer+oidc_audience, or bind \
                     127.0.0.1 / set auth.require=false for loopback-only lab use",
                    cfg.listen
                );
            }
            if !cfg.auth.has_credentials() {
                tracing::warn!(
                    listen = %cfg.listen,
                    "API auth is OFF (no [[auth.tokens]] / OIDC); every request is admin"
                );
            }
            if cfg.auth.oidc_enabled() {
                tracing::info!(
                    issuer = ?cfg.auth.oidc_issuer,
                    audience = ?cfg.auth.oidc_audience,
                    "OIDC bearer JWT validation enabled alongside static tokens"
                );
            } else if cfg.auth.oidc_issuer.is_some() {
                tracing::warn!("auth.oidc_issuer set without auth.oidc_audience — OIDC disabled");
            }
            if let Some((rps, burst)) = cfg.auth.rate_limit_enabled() {
                tracing::info!(rps, burst, "REST API rate limiting enabled");
            } else if cfg.auth.rate_limit_rps.is_some() != cfg.auth.rate_limit_burst.is_some() {
                tracing::warn!(
                    "auth.rate_limit_rps and auth.rate_limit_burst must both be set — rate limiting disabled"
                );
            }
            m.start_reaper();
            m.spawn_autopause_loop();
            if !cfg.sandbox.egress_proxy_listen.is_empty() {
                let addr: std::net::SocketAddr = cfg.sandbox.egress_proxy_listen.parse()?;
                if let Err(e) = fluxvm_network::egress::apply_egress_redirect(addr.port()) {
                    tracing::warn!(error = %e, "egress redirect nftables apply failed");
                }
                let sandbox_cfg = cfg.sandbox.clone();
                tokio::spawn(async move {
                    if let Err(e) = fluxvm_network::egress_proxy::serve(addr, sandbox_cfg).await {
                        tracing::error!(error = %e, "egress proxy exited");
                    }
                });
            }
            let app = api::router(m);
            if cfg.tls.enabled() {
                // rustls 0.23: select a process-wide CryptoProvider (ring) before
                // any ServerConfig / axum-server TLS bind.
                let _ = rustls::crypto::ring::default_provider().install_default();
                let addr: std::net::SocketAddr = cfg.listen.parse()?;
                let cert = cfg.tls.cert.clone().unwrap();
                let key = cfg.tls.key.clone().unwrap();
                let rustls_config = if let Some(ca) = cfg.tls.client_ca.clone() {
                    build_mtls_config(&cert, &key, &ca).await?
                } else {
                    axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                        .await
                        .context("loading TLS cert/key")?
                };
                tracing::info!(
                    listen = %cfg.listen,
                    mtls = cfg.tls.mtls_enabled(),
                    "API listening (TLS)"
                );
                axum_server::bind_rustls(addr, rustls_config)
                    .serve(app.into_make_service())
                    .await?;
            } else {
                let listener = TcpListener::bind(&cfg.listen).await?;
                tracing::info!(listen=%cfg.listen, "API listening");
                axum::serve(listener, app).await?;
            }
        }
        Command::Create { spec } => {
            let req: CreateVmRequest = serde_json::from_slice(&std::fs::read(spec)?)?;
            println!("{}", serde_json::to_string_pretty(&m.create(req).await?)?);
        }
        Command::List => println!("{}", serde_json::to_string_pretty(&m.list().await)?),
        Command::Get { id } => println!("{}", serde_json::to_string_pretty(&m.get(id).await?)?),
        Command::Diagnose { id } => {
            let vm = m.get(id).await?;
            let pin_root = std::env::var("FLUXVM_INTEL_PIN_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| fluxvm_intelligence::DEFAULT_PIN_ROOT.into());
            let snapshot = fluxvm_intelligence::snapshot_record(&vm, &pin_root)?;
            let effective = m.network_effective(id).await?;
            let policy: fluxvm_network::dataplane::VmNetworkPolicy = serde_json::from_value(
                effective
                    .get("effective")
                    .cloned()
                    .context("network/effective response has no effective policy")?,
            )?;
            let pod_policy = m.pod_network_policy(id).await?;
            let flows = m.network_flows(id, 256).await?;
            let reasons = fluxvm_network::ebpf::drop_reasons(&m.cfg.sandbox.dataplane, id, 256)
                .unwrap_or_default();
            let report = fluxvm_intelligence::diagnose_vm_with_reasons(
                &snapshot,
                &policy,
                pod_policy.as_ref(),
                &flows,
                &reasons,
            );
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Trace {
            id,
            seconds,
            limit,
            output,
        } => {
            m.get(id).await?;
            let pin_root = std::env::var("FLUXVM_INTEL_PIN_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| fluxvm_intelligence::DEFAULT_PIN_ROOT.into());
            let events = fluxvm_intelligence::trace_events(id, &pin_root, seconds, limit)?;
            match output.to_ascii_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&events)?),
                "jsonl" => {
                    for event in events {
                        println!("{}", serde_json::to_string(&event)?);
                    }
                }
                other => anyhow::bail!("unsupported trace output {other:?}; use json or jsonl"),
            }
        }
        Command::Start { id } => println!("{}", serde_json::to_string_pretty(&m.start(id).await?)?),
        Command::Stop { id } => println!("{}", serde_json::to_string_pretty(&m.stop(id).await?)?),
        Command::Pause { id } => println!("{}", serde_json::to_string_pretty(&m.pause(id).await?)?),
        Command::Resume { id } => {
            println!("{}", serde_json::to_string_pretty(&m.resume(id).await?)?)
        }
        Command::Freeze { id } => {
            m.freeze(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::Thaw { id } => {
            m.thaw(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::Frozen { id } => {
            let frozen = m.is_frozen(id).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"frozen": frozen}))?
            );
        }
        Command::Resources {
            id,
            cpu_quota_percent,
            memory_max_bytes,
            io_weight,
            pids_max,
            cpuset_cpus,
        } => {
            if cpu_quota_percent.is_none()
                && memory_max_bytes.is_none()
                && io_weight.is_none()
                && pids_max.is_none()
                && cpuset_cpus.is_none()
            {
                anyhow::bail!(
                    "no fields to update; pass at least one of --cpu-quota-percent, \
                     --memory-max-bytes, --io-weight, --pids-max, --cpuset-cpus"
                );
            }
            let cpuset_cpus = cpuset_cpus.map(|s| parse_cpuset_spec(&s)).transpose()?;
            m.set_resources(
                id,
                ResourcePatch {
                    cpu_quota_percent,
                    memory_max_bytes,
                    io_weight,
                    pids_max,
                    cpuset_cpus,
                },
            )
            .await?;
            println!("{{\"ok\":true}}");
        }
        Command::Exec {
            id,
            timeout_seconds,
            command,
        } => {
            let response = m.exec(id, command.join(" "), timeout_seconds).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::Ping { id } => {
            m.agent_ping(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::CopyTo {
            id,
            local,
            remote,
            mode,
        } => {
            let bytes = read_local_file_for_copy_to(&local)?;
            let response = m.put_file(id, remote, B64.encode(&bytes), mode).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::CopyFrom { id, remote, local } => match m.get_file(id, remote).await? {
            AgentResponse::FileContent {
                content_base64,
                mode,
            } => {
                let n = write_copy_from_response(&local, &content_base64, mode)?;
                println!("{{\"ok\":true,\"bytes\":{n}}}");
            }
            AgentResponse::Error { message } => anyhow::bail!("guest agent error: {message}"),
            other => anyhow::bail!("unexpected response to get-file: {other:?}"),
        },
        Command::Migrate { command } => match command {
            MigrateCommand::Start {
                id,
                destination,
                mode,
                bandwidth_mbps,
                max_downtime_ms,
                multifd_channels,
            } => {
                let request = MigrationStartRequest {
                    destination,
                    mode: parse_migration_mode(&mode)?,
                    bandwidth_mbps,
                    max_downtime_ms,
                    multifd_channels,
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.start_migration(id, &request).await?)?
                );
            }
            MigrateCommand::Status { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.migration_status(id).await?)?
                );
            }
            MigrateCommand::Cancel { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.cancel_migration(id).await?)?
                );
            }
        },
        Command::Qga { command } => match command {
            QgaCommand::Ping { id } => {
                m.qga_ping(id).await?;
                println!("{{\"ok\":true}}");
            }
            QgaCommand::Powershell {
                id,
                timeout_seconds,
                command,
            } => {
                let result = m
                    .qga_powershell(id, command.join(" "), timeout_seconds)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            QgaCommand::Exec {
                id,
                path,
                timeout_seconds,
                args,
            } => {
                let result = m.qga_exec(id, path, args, timeout_seconds).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            QgaCommand::FirewallOpen {
                id,
                name,
                port,
                protocol,
                timeout_seconds,
            } => {
                let result = m
                    .qga_firewall_open(id, name, port, protocol, timeout_seconds)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            QgaCommand::FirewallClose {
                id,
                name,
                timeout_seconds,
            } => {
                let result = m.qga_firewall_close(id, name, timeout_seconds).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
        Command::Delete { id } => m.delete(id).await?,
        Command::BuildImage { spec } => {
            let req: BuildImageRequest = serde_json::from_slice(&std::fs::read(spec)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&image::build_image(&cfg, &req).await?)?
            );
        }
        Command::Pool { command } => match command {
            PoolCommand::Create { spec } => {
                let spec: fluxvm_core::model::PoolSpec =
                    serde_json::from_slice(&std::fs::read(spec)?)?;
                let name = spec.name.clone();
                m.create_pool(spec).await?;
                // This CLI process exits right after printing — wait for a
                // real backfill here rather than relying on the background
                // task create_pool() also fires off, which would otherwise
                // get killed mid-flight along with this process (see
                // VmManager::backfill_pool_sync's doc comment).
                m.backfill_pool_sync(&name).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_core::model::PoolView::from(
                        m.get_pool(&name).await?
                    ))?
                );
            }
            PoolCommand::List => {
                let items: Vec<_> = m
                    .list_pools()
                    .await
                    .into_iter()
                    .map(fluxvm_core::model::PoolView::from)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items)?)
            }
            PoolCommand::Get { name } => println!(
                "{}",
                serde_json::to_string_pretty(&fluxvm_core::model::PoolView::from(
                    m.get_pool(&name).await?
                ))?
            ),
            PoolCommand::Claim {
                name,
                vm_name,
                ttl_seconds,
            } => {
                let overrides = ClaimOverrides {
                    name: vm_name,
                    ttl_seconds,
                };
                println!(
                    "{}",
                    // No token/tenant concept for this local CLI -- same
                    // untenanted-admin posture every other m.<mutate>()
                    // call in this file already has.
                    serde_json::to_string_pretty(
                        &m.claim_from_pool(&name, overrides, None).await?
                    )?
                );
            }
            PoolCommand::Resize { name, size } => {
                let before = m.get_pool(&name).await?.size;
                m.resize_pool(&name, size).await?;
                if size > before {
                    // Same reasoning as `pool create`'s own call: this
                    // process exits right after printing, which would
                    // otherwise take resize_pool's own background backfill
                    // down with it before the pool actually reaches its
                    // new (larger) size.
                    m.backfill_pool_sync(&name).await?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_core::model::PoolView::from(
                        m.get_pool(&name).await?
                    ))?
                );
            }
            PoolCommand::Delete { name } => m.delete_pool(&name).await?,
        },
        Command::Cnp { command } => match command {
            CnpCommand::List => {
                println!("{}", serde_json::to_string_pretty(&m.list_cnp().await?)?);
            }
            CnpCommand::Get { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.get_cnp(&name).await?)?
                );
            }
            CnpCommand::Apply { spec } => {
                let raw = std::fs::read_to_string(&spec)?;
                let policy: fluxvm_network::cnp::CiliumNetworkPolicy = serde_json::from_str(&raw)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.apply_cnp(policy).await?)?
                );
            }
            CnpCommand::Delete { name } => {
                m.delete_cnp(&name).await?;
                println!("{{\"deleted\":\"ok\"}}");
            }
        },
        Command::Hubble { command } => match command {
            HubbleCommand::Observe {
                output,
                detailed,
                limit,
                verdict,
                protocol,
            } => {
                print_hubble_observe(&m, &output, detailed, limit, &verdict, &protocol).await?;
            }
            HubbleCommand::Flow {
                output,
                limit,
                verdict,
                protocol,
            } => {
                print_hubble_observe(&m, &output, true, limit, &verdict, &protocol).await?;
            }
            HubbleCommand::Endpoints => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_endpoints().await?)?
                );
            }
        },
        Command::Observe => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.network_observe().await?)?
            );
        }
        Command::Dataplane { command } => match command {
            DataplaneCommand::Health => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_health().await?)?
                );
            }
            DataplaneCommand::Ipcache => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_ipcache().await?)?
                );
            }
            DataplaneCommand::IpamStatus => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_ipam_status().await?)?
                );
            }
            DataplaneCommand::RefreshDns => {
                let n = m.refresh_fqdn_policies().await?;
                println!("{{\"refreshed\":{n}}}");
            }
            DataplaneCommand::MigrationState { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_network::migration_state::status(
                        &m.cfg, id
                    )?)?
                );
            }
            DataplaneCommand::MigrationQuiesce { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_network::migration_state::quiesce(
                        &m.cfg, id
                    )?)?
                );
            }
            DataplaneCommand::MigrationExport { id, output } => {
                let snapshot = fluxvm_network::migration_state::export_snapshot(&m.cfg, id)?;
                let encoded = serde_json::to_vec_pretty(&snapshot)?;
                if let Some(path) = output {
                    std::fs::write(path, &encoded)?;
                } else {
                    println!("{}", String::from_utf8(encoded)?);
                }
            }
            DataplaneCommand::MigrationRestore { id, input } => {
                let snapshot: fluxvm_network::migration_state::VmNetworkStateSnapshot =
                    serde_json::from_slice(&std::fs::read(input)?)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &fluxvm_network::migration_state::restore_snapshot(&m.cfg, id, &snapshot)?
                    )?
                );
            }
            DataplaneCommand::MigrationResume { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_network::migration_state::resume(
                        &m.cfg, id
                    )?)?
                );
            }
        },
        Command::Identity { command } => match command {
            IdentityCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.list_identities().await?)?
                );
            }
        },
        Command::Group { command } => match command {
            GroupCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.list_network_groups().await?)?
                );
            }
            GroupCommand::Get { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.get_network_group(&name).await?)?
                );
            }
            GroupCommand::Set {
                name,
                label,
                allow_cidr,
                deny_cidr,
                allow_port,
                default_allow,
                allow_icmp,
                priority,
                description,
                max_egress_mbps,
                max_egress_pps,
            } => {
                let group = fluxvm_network::groups::SecurityGroup {
                    name,
                    labels: label,
                    policy: fluxvm_network::dataplane::VmNetworkPolicy {
                        default_allow: default_allow.unwrap_or(true),
                        allow_cidrs: allow_cidr,
                        deny_cidrs: deny_cidr,
                        allow_ports: allow_port,
                        allow_icmp,
                        max_egress_mbps,
                        max_egress_pps,
                        ..Default::default()
                    },
                    identity: 0,
                    priority: priority.unwrap_or(100),
                    description: description.unwrap_or_default(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.upsert_network_group(group).await?)?
                );
            }
            GroupCommand::Delete { name } => {
                m.delete_network_group(&name).await?;
                println!("{{\"deleted\":\"ok\"}}");
            }
        },
        Command::Catalog { command } => match command {
            CatalogCommand::Keygen => {
                let (private_b64, public_b64) = image::catalog::generate_keypair();
                println!(
                    "private key (keep secret, use with `catalog sign --key`):\n  {private_b64}"
                );
                println!(
                    "public key -- add as [[catalog.trusted_signers]] with a name:\n  [[catalog.trusted_signers]]\n  name = \"CHANGE_ME\"\n  public_key = \"{public_b64}\""
                );
            }
            CatalogCommand::Sign {
                key,
                name,
                source,
                sha256,
                format,
                distro,
                version,
                arch,
                build_pipeline,
                build_run_id,
                build_commit,
                catalog_file,
            } => {
                let entry = image::catalog::sign_entry(
                    &key,
                    name,
                    source,
                    sha256,
                    format,
                    distro,
                    version,
                    arch,
                    build_pipeline,
                    build_run_id,
                    build_commit,
                )?;
                match catalog_file {
                    Some(path) => {
                        let mut entries: Vec<image::catalog::CatalogEntry> = if path.exists() {
                            serde_json::from_slice(&std::fs::read(&path)?)?
                        } else {
                            Vec::new()
                        };
                        entries.retain(|e| e.name != entry.name);
                        entries.push(entry);
                        std::fs::write(&path, serde_json::to_vec_pretty(&entries)?)?;
                        println!("{}", serde_json::to_string_pretty(&entries)?);
                    }
                    None => println!("{}", serde_json::to_string_pretty(&entry)?),
                }
            }
            CatalogCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&image::catalog::list_with_verification(&cfg)?)?
                );
            }
            CatalogCommand::Add {
                name,
                source,
                format,
            } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &m.add_catalog_entry(name, source, format).await?
                    )?
                );
            }
            CatalogCommand::Remove { name } => {
                m.remove_catalog_entry(&name).await?;
                println!("{}", serde_json::json!({"removed": name}));
            }
            CatalogCommand::Rename { name, new_name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.rename_catalog_entry(&name, &new_name).await?)?
                );
            }
            CatalogCommand::Clone { name, target_name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &m.clone_catalog_entry(&name, &target_name).await?
                    )?
                );
            }
            CatalogCommand::Export { name, dest } => {
                m.export_catalog_entry(&name, &dest).await?;
                println!("{}", serde_json::json!({"exported": dest}));
            }
            CatalogCommand::Lock { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.set_catalog_read_only(&name, true).await?)?
                );
            }
            CatalogCommand::Unlock { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.set_catalog_read_only(&name, false).await?)?
                );
            }
            CatalogCommand::Clean => {
                let removed = m.clean_catalog_downloads().await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({"removed": removed}))?
                );
            }
        },
    }
    Ok(())
}

async fn build_mtls_config(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig};
    use std::fs::File;
    use std::io::BufReader;
    use std::sync::Arc;

    let mut cert_reader = BufReader::new(File::open(cert).context("open TLS cert")?);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS cert PEM")?;
    let mut key_reader = BufReader::new(File::open(key).context("open TLS key")?);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse TLS key PEM")?
        .ok_or_else(|| anyhow::anyhow!("TLS key PEM contained no private key"))?;

    let mut roots = RootCertStore::empty();
    let mut ca_reader = BufReader::new(File::open(client_ca).context("open client CA")?);
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        roots
            .add(cert.context("parse client CA cert")?)
            .context("add client CA to trust store")?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build client cert verifier")?;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, PrivateKeyDer::from(key))
        .context("build rustls ServerConfig")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}

async fn print_hubble_observe(
    m: &VmManager,
    output: &str,
    detailed: bool,
    limit: usize,
    verdict: &str,
    protocol: &str,
) -> Result<()> {
    use fluxvm_network::packetflow::{FlowOutput, filter_views, render_flows};
    let mut views = m.hubble_observe_views(limit).await?;
    views = filter_views(views, Some(verdict), Some(protocol));
    let mode = if std::env::var("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
        && output.eq_ignore_ascii_case("color")
    {
        FlowOutput::Plain
    } else {
        FlowOutput::parse(output)
    };
    print!("{}", render_flows(&views, mode, detailed));
    Ok(())
}

#[cfg(test)]
mod catalog_cli_tests {
    use super::*;

    /// Every `fluxvm catalog <verb>` subcommand this file added parses into
    /// the field values it's documented to take, and rejects a required
    /// flag/positional being left off — clap wiring bugs (a typo'd `long`
    /// name, a flag that silently became optional) would otherwise only
    /// surface the first time someone actually ran the command by hand.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn catalog_list_takes_no_arguments() {
        assert!(matches!(
            parse(&["catalog", "list"]),
            Command::Catalog {
                command: CatalogCommand::List
            }
        ));
    }

    #[test]
    fn catalog_add_parses_name_positional_and_source_format_flags() {
        let Command::Catalog {
            command:
                CatalogCommand::Add {
                    name,
                    source,
                    format,
                },
        } = parse(&[
            "catalog",
            "add",
            "ubuntu-24.04",
            "--source",
            "/var/lib/fluxvm/images/ubuntu.qcow2",
        ])
        else {
            panic!("expected CatalogCommand::Add");
        };
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(source, "/var/lib/fluxvm/images/ubuntu.qcow2");
        assert_eq!(format, "qcow2", "format must default to qcow2");
    }

    #[test]
    fn catalog_add_requires_source() {
        assert!(Cli::try_parse_from(["fluxvm", "catalog", "add", "ubuntu-24.04"]).is_err());
    }

    #[test]
    fn catalog_sign_parses_optional_build_provenance_flags() {
        let Command::Catalog {
            command:
                CatalogCommand::Sign {
                    key,
                    name,
                    source,
                    sha256,
                    format,
                    distro,
                    version,
                    arch,
                    build_pipeline,
                    build_run_id,
                    build_commit,
                    catalog_file,
                },
        } = parse(&[
            "catalog",
            "sign",
            "--key",
            "base64key",
            "--name",
            "ubuntu-24.04",
            "--source",
            "/var/lib/fluxvm/images/ubuntu.qcow2",
            "--sha256",
            "abc123",
            "--build-pipeline",
            "github-actions/build-images.yml",
            "--build-run-id",
            "42",
            "--build-commit",
            "deadbeef",
        ])
        else {
            panic!("expected CatalogCommand::Sign");
        };
        assert_eq!(key, "base64key");
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(source, "/var/lib/fluxvm/images/ubuntu.qcow2");
        assert_eq!(sha256, "abc123");
        assert_eq!(format, "qcow2", "format must default to qcow2");
        assert_eq!(distro, None);
        assert_eq!(version, None);
        assert_eq!(arch, None);
        assert_eq!(
            build_pipeline.as_deref(),
            Some("github-actions/build-images.yml")
        );
        assert_eq!(build_run_id.as_deref(), Some("42"));
        assert_eq!(build_commit.as_deref(), Some("deadbeef"));
        assert_eq!(
            catalog_file, None,
            "build provenance flags must stay optional and independent of --catalog-file"
        );
    }

    #[test]
    fn catalog_sign_leaves_build_provenance_unset_when_omitted() {
        let Command::Catalog {
            command:
                CatalogCommand::Sign {
                    build_pipeline,
                    build_run_id,
                    build_commit,
                    ..
                },
        } = parse(&[
            "catalog",
            "sign",
            "--key",
            "base64key",
            "--name",
            "n",
            "--source",
            "s",
            "--sha256",
            "h",
        ])
        else {
            panic!("expected CatalogCommand::Sign");
        };
        assert_eq!(build_pipeline, None);
        assert_eq!(build_run_id, None);
        assert_eq!(build_commit, None);
    }

    #[test]
    fn catalog_remove_parses_name() {
        let Command::Catalog {
            command: CatalogCommand::Remove { name },
        } = parse(&["catalog", "remove", "ubuntu-24.04-qa"])
        else {
            panic!("expected CatalogCommand::Remove");
        };
        assert_eq!(name, "ubuntu-24.04-qa");
    }

    #[test]
    fn catalog_rename_parses_both_positionals() {
        let Command::Catalog {
            command: CatalogCommand::Rename { name, new_name },
        } = parse(&["catalog", "rename", "old-name", "new-name"])
        else {
            panic!("expected CatalogCommand::Rename");
        };
        assert_eq!(name, "old-name");
        assert_eq!(new_name, "new-name");
    }

    #[test]
    fn catalog_clone_parses_both_positionals() {
        let Command::Catalog {
            command: CatalogCommand::Clone { name, target_name },
        } = parse(&["catalog", "clone", "ubuntu-24.04", "ubuntu-24.04-staging"])
        else {
            panic!("expected CatalogCommand::Clone");
        };
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(target_name, "ubuntu-24.04-staging");
    }

    #[test]
    fn catalog_export_parses_name_and_dest_path() {
        let Command::Catalog {
            command: CatalogCommand::Export { name, dest },
        } = parse(&[
            "catalog",
            "export",
            "ubuntu-24.04",
            "/var/lib/fluxvm/exports/ubuntu-24.04.qcow2",
        ])
        else {
            panic!("expected CatalogCommand::Export");
        };
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(
            dest,
            PathBuf::from("/var/lib/fluxvm/exports/ubuntu-24.04.qcow2")
        );
    }

    #[test]
    fn catalog_lock_and_unlock_parse_name() {
        let Command::Catalog {
            command: CatalogCommand::Lock { name },
        } = parse(&["catalog", "lock", "ubuntu-24.04"])
        else {
            panic!("expected CatalogCommand::Lock");
        };
        assert_eq!(name, "ubuntu-24.04");

        let Command::Catalog {
            command: CatalogCommand::Unlock { name },
        } = parse(&["catalog", "unlock", "ubuntu-24.04"])
        else {
            panic!("expected CatalogCommand::Unlock");
        };
        assert_eq!(name, "ubuntu-24.04");
    }

    #[test]
    fn catalog_clean_takes_no_arguments() {
        assert!(matches!(
            parse(&["catalog", "clean"]),
            Command::Catalog {
                command: CatalogCommand::Clean
            }
        ));
    }
}

#[cfg(test)]
mod agent_cli_tests {
    use super::*;

    /// `ping`/`copy-to`/`copy-from` parse into the field values documented
    /// above, `mode` stays optional on `copy-to`, and the required
    /// positionals can't be left off — the same clap-wiring-bug class the
    /// sibling `catalog_cli_tests` module guards against for `catalog`.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn ping_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Ping { id: parsed } = parse(&["ping", &id.to_string()]) else {
            panic!("expected Command::Ping");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn ping_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "ping"]).is_err());
    }

    #[test]
    fn copy_to_parses_positionals_and_defaults_mode_to_none() {
        let id = Uuid::nil();
        let Command::CopyTo {
            id: parsed_id,
            local,
            remote,
            mode,
        } = parse(&[
            "copy-to",
            &id.to_string(),
            "/tmp/local-file.txt",
            "/etc/app/config.yaml",
        ])
        else {
            panic!("expected Command::CopyTo");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(local, PathBuf::from("/tmp/local-file.txt"));
        assert_eq!(remote, "/etc/app/config.yaml");
        assert_eq!(
            mode, None,
            "mode must default to None (guest agent's own 0o644 default)"
        );
    }

    #[test]
    fn copy_to_parses_explicit_mode() {
        let id = Uuid::nil();
        let Command::CopyTo { mode, .. } = parse(&[
            "copy-to",
            &id.to_string(),
            "/tmp/key",
            "/etc/app/key",
            "--mode",
            "384", // 0o600
        ]) else {
            panic!("expected Command::CopyTo");
        };
        assert_eq!(mode, Some(384));
    }

    #[test]
    fn copy_to_requires_both_local_and_remote_paths() {
        let id = Uuid::nil().to_string();
        assert!(Cli::try_parse_from(["fluxvm", "copy-to", &id, "/tmp/local-file.txt"]).is_err());
    }

    #[test]
    fn copy_from_parses_positionals_in_remote_then_local_order() {
        let id = Uuid::nil();
        let Command::CopyFrom {
            id: parsed_id,
            remote,
            local,
        } = parse(&[
            "copy-from",
            &id.to_string(),
            "/etc/app/config.yaml",
            "/tmp/local-file.txt",
        ])
        else {
            panic!("expected Command::CopyFrom");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(remote, "/etc/app/config.yaml");
        assert_eq!(local, PathBuf::from("/tmp/local-file.txt"));
    }

    #[test]
    fn copy_from_requires_both_remote_and_local_paths() {
        let id = Uuid::nil().to_string();
        assert!(Cli::try_parse_from(["fluxvm", "copy-from", &id, "/etc/app/config.yaml"]).is_err());
    }

    /// `read_local_file_for_copy_to` is what stands between a caller and a
    /// wasted base64-encode + vsock round trip for content the guest
    /// agent's own `put_file` would reject anyway — proves the cap is
    /// actually enforced client-side, not just documented.
    #[test]
    fn read_local_file_for_copy_to_rejects_oversized_files() {
        let dir = std::env::temp_dir().join(format!(
            "fluxvm-cli-copy-to-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized.bin");
        // One byte past the limit is enough to prove the boundary check —
        // no need to actually write 64MB+1 to disk to exercise it.
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&path).unwrap();
            f.seek(SeekFrom::Start(
                fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES as u64,
            ))
            .unwrap();
            f.write_all(b"x").unwrap();
        }

        let err = read_local_file_for_copy_to(&path).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_local_file_for_copy_to_accepts_files_within_the_limit() {
        let dir = std::env::temp_dir().join(format!(
            "fluxvm-cli-copy-to-test-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("small.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let bytes = read_local_file_for_copy_to(&path).unwrap();
        assert_eq!(bytes, b"hello world");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `write_copy_from_response` round-trips base64 content back to real
    /// bytes on disk and restores the guest-reported Unix mode — the two
    /// things `get_file`'s REST/CLI callers actually rely on, not just that
    /// the base64 decodes.
    #[cfg(unix)]
    #[test]
    fn write_copy_from_response_restores_content_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "fluxvm-cli-copy-from-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("restored.txt");

        let n = write_copy_from_response(&path, &B64.encode(b"secret content"), 0o600).unwrap();
        assert_eq!(n, "secret content".len());
        assert_eq!(std::fs::read(&path).unwrap(), b"secret content");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_copy_from_response_rejects_invalid_base64() {
        let dir = std::env::temp_dir().join(format!(
            "fluxvm-cli-copy-from-test-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("never-written.txt");

        assert!(write_copy_from_response(&path, "not-valid-base64!!!", 0o644).is_err());
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod freeze_cli_tests {
    use super::*;

    /// `freeze`/`thaw`/`frozen` all take a single VM-id positional and
    /// nothing else — proves the clap wiring actually produces the three
    /// distinct variants (not, say, all three silently parsing into the
    /// same one) and that the id can't be left off, the same clap-wiring-bug
    /// class `catalog_cli_tests`/`agent_cli_tests` guard against elsewhere
    /// in this file.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn freeze_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Freeze { id: parsed } = parse(&["freeze", &id.to_string()]) else {
            panic!("expected Command::Freeze");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn freeze_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "freeze"]).is_err());
    }

    #[test]
    fn thaw_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Thaw { id: parsed } = parse(&["thaw", &id.to_string()]) else {
            panic!("expected Command::Thaw");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn thaw_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "thaw"]).is_err());
    }

    #[test]
    fn frozen_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Frozen { id: parsed } = parse(&["frozen", &id.to_string()]) else {
            panic!("expected Command::Frozen");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn frozen_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "frozen"]).is_err());
    }

    /// `freeze`/`thaw`/`frozen` are three distinct commands, not aliases of
    /// each other or of `pause`/`resume` — a copy-paste bug wiring `thaw`'s
    /// arm to call `m.freeze()` (both take just an id, so the type checker
    /// wouldn't catch it) would otherwise only surface at runtime.
    #[test]
    fn freeze_thaw_frozen_are_distinct_from_each_other_and_from_pause_resume() {
        let id = Uuid::nil().to_string();
        assert!(matches!(parse(&["freeze", &id]), Command::Freeze { .. }));
        assert!(matches!(parse(&["thaw", &id]), Command::Thaw { .. }));
        assert!(matches!(parse(&["frozen", &id]), Command::Frozen { .. }));
        assert!(matches!(parse(&["pause", &id]), Command::Pause { .. }));
        assert!(matches!(parse(&["resume", &id]), Command::Resume { .. }));
    }
}

#[cfg(test)]
mod resources_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn parses_a_single_flag() {
        let id = Uuid::nil();
        let Command::Resources {
            id: parsed_id,
            cpu_quota_percent,
            memory_max_bytes,
            io_weight,
            pids_max,
            cpuset_cpus,
        } = parse(&["resources", &id.to_string(), "--cpu-quota-percent", "150"])
        else {
            panic!("expected Command::Resources");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(cpu_quota_percent, Some(150));
        assert_eq!(memory_max_bytes, None);
        assert_eq!(io_weight, None);
        assert_eq!(pids_max, None);
        assert_eq!(cpuset_cpus, None);
    }

    #[test]
    fn parses_every_flag_together() {
        let id = Uuid::nil();
        let Command::Resources {
            id: parsed_id,
            cpu_quota_percent,
            memory_max_bytes,
            io_weight,
            pids_max,
            cpuset_cpus,
        } = parse(&[
            "resources",
            &id.to_string(),
            "--cpu-quota-percent",
            "150",
            "--memory-max-bytes",
            "536870912",
            "--io-weight",
            "250",
            "--pids-max",
            "64",
            "--cpuset-cpus",
            "0-1,4",
        ])
        else {
            panic!("expected Command::Resources");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(cpu_quota_percent, Some(150));
        assert_eq!(memory_max_bytes, Some(536_870_912));
        assert_eq!(io_weight, Some(250));
        assert_eq!(pids_max, Some(64));
        assert_eq!(cpuset_cpus.as_deref(), Some("0-1,4"));
    }

    #[test]
    fn requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "resources"]).is_err());
    }

    #[test]
    fn all_flags_are_optional_at_the_clap_layer() {
        // clap itself allows zero flags -- the "at least one field" rule is
        // enforced at runtime in main()'s match arm, not by clap, since
        // ResourcePatch's own all-Option shape gives clap no way to express
        // "at least one of these".
        let id = Uuid::nil();
        assert!(matches!(
            parse(&["resources", &id.to_string()]),
            Command::Resources { .. }
        ));
    }

    #[test]
    fn is_distinct_from_freeze_and_pause() {
        let id = Uuid::nil().to_string();
        assert!(matches!(
            parse(&["resources", &id, "--pids-max", "8"]),
            Command::Resources { .. }
        ));
        assert!(matches!(parse(&["freeze", &id]), Command::Freeze { .. }));
        assert!(matches!(parse(&["pause", &id]), Command::Pause { .. }));
    }

    // --- parse_cpuset_spec ---

    #[test]
    fn cpuset_spec_parses_a_single_range() {
        assert_eq!(parse_cpuset_spec("0-3").unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn cpuset_spec_parses_a_comma_list() {
        assert_eq!(parse_cpuset_spec("0,2,4").unwrap(), vec![0, 2, 4]);
    }

    #[test]
    fn cpuset_spec_parses_mixed_ranges_and_singletons() {
        assert_eq!(parse_cpuset_spec("0-1,4,6-7").unwrap(), vec![0, 1, 4, 6, 7]);
    }

    #[test]
    fn cpuset_spec_sorts_and_dedups() {
        assert_eq!(parse_cpuset_spec("4,0-1,1,0").unwrap(), vec![0, 1, 4]);
    }

    #[test]
    fn cpuset_spec_tolerates_surrounding_whitespace() {
        assert_eq!(parse_cpuset_spec(" 0-1, 4 ").unwrap(), vec![0, 1, 4]);
    }

    #[test]
    fn cpuset_spec_rejects_empty_string() {
        let err = parse_cpuset_spec("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn cpuset_spec_rejects_an_empty_entry_between_commas() {
        assert!(parse_cpuset_spec("0,,1").is_err());
    }

    #[test]
    fn cpuset_spec_rejects_non_numeric_input() {
        assert!(parse_cpuset_spec("abc").is_err());
    }

    #[test]
    fn cpuset_spec_rejects_a_reversed_range_instead_of_silently_returning_empty() {
        // Plain `start..=end` with start > end is a silently-empty Rust
        // range -- without this check a typo like "5-2" would apply an
        // empty cpuset instead of erroring.
        let err = parse_cpuset_spec("5-2").unwrap_err();
        assert!(err.to_string().contains("start > end"));
    }
}

#[cfg(test)]
mod migrate_cli_tests {
    use super::*;

    /// `migrate start/status/cancel` parse into the field values documented
    /// above -- the same clap-wiring-bug class `agent_cli_tests` and
    /// `catalog_cli_tests` guard against for their own subcommands.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn migrate_start_parses_destination_and_defaults_mode_to_pre_copy() {
        let id = Uuid::nil();
        let Command::Migrate {
            command:
                MigrateCommand::Start {
                    id: parsed_id,
                    destination,
                    mode,
                    bandwidth_mbps,
                    max_downtime_ms,
                    multifd_channels,
                },
        } = parse(&[
            "migrate",
            "start",
            &id.to_string(),
            "--destination",
            "tcp:10.0.0.9:49152",
        ])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Start");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(destination, "tcp:10.0.0.9:49152");
        assert_eq!(mode, "pre-copy", "mode must default to pre-copy");
        assert_eq!(bandwidth_mbps, None);
        assert_eq!(max_downtime_ms, None);
        assert_eq!(multifd_channels, None);
    }

    #[test]
    fn migrate_start_parses_all_optional_tuning_flags() {
        let id = Uuid::nil();
        let Command::Migrate {
            command:
                MigrateCommand::Start {
                    mode,
                    bandwidth_mbps,
                    max_downtime_ms,
                    multifd_channels,
                    ..
                },
        } = parse(&[
            "migrate",
            "start",
            &id.to_string(),
            "--destination",
            "unix:/run/fluxvm/migrate.sock",
            "--mode",
            "post-copy",
            "--bandwidth-mbps",
            "500",
            "--max-downtime-ms",
            "300",
            "--multifd-channels",
            "4",
        ])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Start");
        };
        assert_eq!(mode, "post-copy");
        assert_eq!(bandwidth_mbps, Some(500));
        assert_eq!(max_downtime_ms, Some(300));
        assert_eq!(multifd_channels, Some(4));
    }

    #[test]
    fn migrate_start_requires_a_destination() {
        let id = Uuid::nil().to_string();
        assert!(Cli::try_parse_from(["fluxvm", "migrate", "start", &id]).is_err());
    }

    #[test]
    fn migrate_status_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Migrate {
            command: MigrateCommand::Status { id: parsed },
        } = parse(&["migrate", "status", &id.to_string()])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Status");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn migrate_cancel_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Migrate {
            command: MigrateCommand::Cancel { id: parsed },
        } = parse(&["migrate", "cancel", &id.to_string()])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Cancel");
        };
        assert_eq!(parsed, id);
    }

    /// `parse_migration_mode` matches `MigrationMode`'s own kebab-case wire
    /// spelling exactly and rejects anything else with a clear error,
    /// rather than silently falling back to a default the caller didn't ask
    /// for.
    #[test]
    fn parse_migration_mode_accepts_the_two_wire_values() {
        assert_eq!(
            parse_migration_mode("pre-copy").unwrap(),
            MigrationMode::PreCopy
        );
        assert_eq!(
            parse_migration_mode("post-copy").unwrap(),
            MigrationMode::PostCopy
        );
    }

    #[test]
    fn parse_migration_mode_rejects_unknown_values() {
        let err = parse_migration_mode("precopy").unwrap_err();
        assert!(
            err.to_string().contains("unknown migration mode"),
            "unexpected error: {err}"
        );
    }
}
