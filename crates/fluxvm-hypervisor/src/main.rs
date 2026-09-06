// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use clap::{Parser, Subcommand};
use fluxvm_hypervisor::config::VmConfig;
use fluxvm_hypervisor::control;
use fluxvm_hypervisor::net;
use fluxvm_hypervisor::VirtualMachine;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "fluxvm-hypervisor", about = "Zyvor FluxVM microVMM")]
struct Cli {
    /// JSON-line UDS control API (long-lived VMM process).
    #[arg(long)]
    api_sock: Option<PathBuf>,

    /// Optional BootConfig JSON applied immediately after the API binds.
    #[arg(long)]
    boot_config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Commands>,

    /// Legacy demo flags (when no --api-sock).
    #[arg(long)]
    dry_run: bool,
    #[arg(long)]
    print_host_net: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Print version and exit.
    Version,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("info".parse().unwrap()),
        )
        .init();

    if let Err(e) = real_main().await {
        eprintln!("fluxvm-hypervisor: {e:#}");
        std::process::exit(1);
    }
}

async fn real_main() -> anyhow::Result<()> {
    // Prefer clap when --api-sock is present; otherwise fall back to legacy argv parser
    // so existing demo flags keep working.
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "--api-sock") {
        let cli = Cli::parse();
        if matches!(cli.command, Some(Commands::Version)) {
            println!("{}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        let sock = cli.api_sock.expect("--api-sock");
        let workspace = sock
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let initial = match cli.boot_config {
            Some(p) => {
                let raw = std::fs::read_to_string(&p)?;
                Some(serde_json::from_str(&raw)?)
            }
            None => None,
        };
        control::serve(sock, initial, workspace).await?;
        return Ok(());
    }

    // Legacy demo path (no async control plane).
    let cfg = VmConfig::from_args()?;
    if cfg.print_host_net {
        print!("{}", net::host_setup_script(&cfg));
        return Ok(());
    }
    let dry = cfg.dry_run;
    let vm = VirtualMachine::instantiate(cfg)?;
    print!("{}", vm.dump());
    if dry {
        return Ok(());
    }
    let log = vm.run()?;
    if log.contains("NETWORK IS UP") {
        eprintln!("[ok] guest reported NETWORK IS UP");
        Ok(())
    } else if log.contains("FluxVM guest boot") || log.contains("guest boot") {
        eprintln!("[warn] guest booted but network handshake incomplete:\n{log}");
        Err(anyhow::anyhow!("guest booted, network not confirmed"))
    } else {
        Err(anyhow::anyhow!("guest did not boot. serial:\n{log}"))
    }
}
