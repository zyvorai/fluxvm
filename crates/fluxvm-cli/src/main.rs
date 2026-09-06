// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use clap::{Parser, Subcommand};
use fluxvm_api as api;
use fluxvm_core::{
    config::Config,
    model::{ClaimOverrides, CreateVmRequest},
};
use fluxvm_image::{self as image, BuildImageRequest};
use fluxvm_scheduler::VmManager;
use std::{path::PathBuf, sync::Arc};
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
            if cfg.auth.must_authenticate(&cfg.listen) && cfg.auth.tokens.is_empty() {
                anyhow::bail!(
                    "auth is required for listen={} but [[auth.tokens]] is empty — \
                     add tokens or bind 127.0.0.1 / set auth.require=false for loopback-only lab use",
                    cfg.listen
                );
            }
            if cfg.auth.tokens.is_empty() {
                tracing::warn!(
                    listen = %cfg.listen,
                    "API auth is OFF (no [[auth.tokens]]); every request is admin"
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
            let listener = TcpListener::bind(&cfg.listen).await?;
            tracing::info!(listen=%cfg.listen, "API listening");
            axum::serve(listener, api::router(m)).await?;
        }
        Command::Create { spec } => {
            let req: CreateVmRequest = serde_json::from_slice(&std::fs::read(spec)?)?;
            println!("{}", serde_json::to_string_pretty(&m.create(req).await?)?);
        }
        Command::List => println!("{}", serde_json::to_string_pretty(&m.list().await)?),
        Command::Get { id } => println!("{}", serde_json::to_string_pretty(&m.get(id).await?)?),
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
