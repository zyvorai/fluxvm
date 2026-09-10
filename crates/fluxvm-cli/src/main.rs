// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fluxvm_api as api;
use fluxvm_core::{
    config::Config,
    model::{ClaimOverrides, CreateVmRequest},
};
use fluxvm_image::{self as image, BuildImageRequest};
use fluxvm_scheduler::VmManager;
use std::{path::{Path, PathBuf}, sync::Arc};
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
    /// Run a command inside the guest over vsock (requires agent.enabled in the VM spec).
    Exec {
        id: Uuid,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
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
    /// these subcommands are only for building/signing the catalog itself.
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
enum CnpCommand {
    List,
    Get { name: String },
    Apply {
        #[arg(long)]
        spec: PathBuf,
    },
    Delete { name: String },
}

#[derive(Subcommand)]
enum IdentityCommand {
    List,
}

#[derive(Subcommand)]
enum DataplaneCommand {
    Health,
    Ipcache,
    RefreshDns,
    /// Show the VM-edge migration gate and schema generation.
    MigrationState { id: Uuid },
    /// Freeze creation of new flows while preserving established conntrack.
    MigrationQuiesce { id: Uuid },
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
    MigrationResume { id: Uuid },
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
    Get { name: String },
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
    Delete { name: String },
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
        #[arg(long)]
        catalog_file: Option<PathBuf>,
    },
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
    Delete {
        name: String,
    },
}

async fn manager(cfg: Config) -> Result<Arc<VmManager>> {
    VmManager::new(cfg)
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
                tracing::warn!(
                    "auth.oidc_issuer set without auth.oidc_audience — OIDC disabled"
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
            let reasons = fluxvm_network::ebpf::drop_reasons(
                &m.cfg.sandbox.dataplane,
                id,
                256,
            )
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
        Command::Start { id } => println!("{}", serde_json::to_string_pretty(&m.start(id).await?)?),
        Command::Stop { id } => println!("{}", serde_json::to_string_pretty(&m.stop(id).await?)?),
        Command::Pause { id } => println!("{}", serde_json::to_string_pretty(&m.pause(id).await?)?),
        Command::Resume { id } => {
            println!("{}", serde_json::to_string_pretty(&m.resume(id).await?)?)
        }
        Command::Exec {
            id,
            timeout_seconds,
            command,
        } => {
            let response = m.exec(id, command.join(" "), timeout_seconds).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
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
                    serde_json::to_string_pretty(&m.get_pool(&name).await?)?
                );
            }
            PoolCommand::List => {
                println!("{}", serde_json::to_string_pretty(&m.list_pools().await)?)
            }
            PoolCommand::Get { name } => println!(
                "{}",
                serde_json::to_string_pretty(&m.get_pool(&name).await?)?
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
                    serde_json::to_string_pretty(&m.claim_from_pool(&name, overrides).await?)?
                );
            }
            PoolCommand::Delete { name } => m.delete_pool(&name).await?,
        },
        Command::Cnp { command } => match command {
            CnpCommand::List => {
                println!("{}", serde_json::to_string_pretty(&m.list_cnp().await?)?);
            }
            CnpCommand::Get { name } => {
                println!("{}", serde_json::to_string_pretty(&m.get_cnp(&name).await?)?);
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
            DataplaneCommand::RefreshDns => {
                let n = m.refresh_fqdn_policies().await?;
                println!("{{\"refreshed\":{n}}}");
            }
            DataplaneCommand::MigrationState { id } => {
                println!("{}", serde_json::to_string_pretty(
                    &fluxvm_network::migration_state::status(&m.cfg, id)?
                )?);
            }
            DataplaneCommand::MigrationQuiesce { id } => {
                println!("{}", serde_json::to_string_pretty(
                    &fluxvm_network::migration_state::quiesce(&m.cfg, id)?
                )?);
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
                println!("{}", serde_json::to_string_pretty(
                    &fluxvm_network::migration_state::restore_snapshot(&m.cfg, id, &snapshot)?
                )?);
            }
            DataplaneCommand::MigrationResume { id } => {
                println!("{}", serde_json::to_string_pretty(
                    &fluxvm_network::migration_state::resume(&m.cfg, id)?
                )?);
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
                println!("public key (put in config.catalog.trusted_signers):\n  {public_b64}");
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
                catalog_file,
            } => {
                let entry = image::catalog::sign_entry(
                    &key, name, source, sha256, format, distro, version, arch,
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

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(Arc::new(
        config,
    )))
}

async fn print_hubble_observe(
    m: &VmManager,
    output: &str,
    detailed: bool,
    limit: usize,
    verdict: &str,
    protocol: &str,
) -> Result<()> {
    use fluxvm_network::packetflow::{filter_views, render_flows, FlowOutput};
    let mut views = m.hubble_observe_views(limit).await?;
    views = filter_views(views, Some(verdict), Some(protocol));
    let mode = if std::env::var("NO_COLOR").map(|v| !v.is_empty()).unwrap_or(false)
        && output.eq_ignore_ascii_case("color")
    {
        FlowOutput::Plain
    } else {
        FlowOutput::parse(output)
    };
    print!("{}", render_flows(&views, mode, detailed));
    Ok(())
}
