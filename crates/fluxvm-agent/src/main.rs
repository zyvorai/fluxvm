// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use std::{net::SocketAddr, path::PathBuf, time::Duration};

#[derive(Parser)]
#[command(
    name = "fluxvm-agent",
    about = "Distributed node-agent + fleet registry for multi-host Zyvor FluxVM"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the central fleet registry + create/list/delete proxy.
    Central {
        #[arg(long, env = "LISTEN", default_value = "0.0.0.0:7799")]
        listen: String,
        /// Directory for `fleet-nodes.json` persistence.
        #[arg(
            long,
            env = "FLUXVM_AGENT_STATE_DIR",
            default_value = "/var/lib/fluxvm-agent"
        )]
        state_dir: PathBuf,
        /// Shared bearer token for `/fleet/*` (omit to leave auth off — lab only).
        #[arg(long, env = "FLUXVM_AGENT_TOKEN")]
        token: Option<String>,
        /// Optional TLS certificate (PEM). Requires `--tls-key`.
        #[arg(long, env = "FLUXVM_AGENT_TLS_CERT")]
        tls_cert: Option<PathBuf>,
        /// Optional TLS private key (PEM).
        #[arg(long, env = "FLUXVM_AGENT_TLS_KEY")]
        tls_key: Option<PathBuf>,
    },
    /// Run this node's heartbeat client, reporting to a central registry.
    Node {
        /// This node's name, as it'll appear in `POST /fleet/vms {"node": "..."}`.
        #[arg(long, env = "NODE_NAME")]
        name: String,
        /// Base URL of the `fluxvm-agent central` instance.
        #[arg(long, env = "CENTRAL_URL")]
        central: String,
        /// Base URL THIS agent itself uses to reach its local `fluxvm
        /// serve` — almost always a loopback address.
        #[arg(long, env = "FLUXVM_URL", default_value = "http://127.0.0.1:7788")]
        fluxvm_url: String,
        /// Base URL the CENTRAL registry should use to reach this same
        /// `fluxvm serve` — must be this host's real, externally
        /// routable address when central runs elsewhere.
        #[arg(long, env = "ADVERTISE_URL")]
        advertise_url: Option<String>,
        #[arg(long, default_value = "10")]
        interval_secs: u64,
        /// Bearer token matching `fluxvm-agent central --token`.
        #[arg(long, env = "FLUXVM_AGENT_TOKEN")]
        token: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Command::Central {
            listen,
            state_dir,
            token,
            tls_cert,
            tls_key,
        } => {
            let app = fluxvm_agent::central::router(fluxvm_agent::central::CentralConfig {
                state_dir,
                token,
            });
            let addr: SocketAddr = listen
                .parse()
                .with_context(|| format!("parsing listen address {listen}"))?;
            match (tls_cert, tls_key) {
                (Some(cert), Some(key)) => {
                    let config = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
                        .await
                        .context("loading TLS cert/key")?;
                    tracing::info!(listen = %listen, tls = true, "fleet registry listening");
                    axum_server::bind_rustls(addr, config)
                        .serve(app.into_make_service())
                        .await
                        .context("serving TLS")?;
                }
                (None, None) => {
                    let listener = tokio::net::TcpListener::bind(addr)
                        .await
                        .with_context(|| format!("binding {listen}"))?;
                    tracing::info!(listen = %listen, tls = false, "fleet registry listening");
                    axum::serve(listener, app).await.context("serving")?;
                }
                _ => bail!("both --tls-cert and --tls-key are required together"),
            }
        }
        Command::Node {
            name,
            central,
            fluxvm_url,
            advertise_url,
            interval_secs,
            token,
        } => {
            let advertise_url = advertise_url.unwrap_or_else(|| fluxvm_url.clone());
            fluxvm_agent::node::run(fluxvm_agent::node::NodeConfig {
                name,
                central_url: central,
                fluxvm_url,
                advertise_url,
                interval: Duration::from_secs(interval_secs.max(1)),
                token,
            })
            .await;
        }
    }
    Ok(())
}
