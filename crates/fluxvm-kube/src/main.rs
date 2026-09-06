// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::Parser;
use fluxvm_kube::{controller, crd::DisposableVm, fluxvm_client::FluxVMClient, placement};
use kube::CustomResourceExt;

#[derive(Parser)]
#[command(
    name = "fluxvm-kube",
    about = "DisposableVm CRD operator for Zyvor FluxVM"
)]
struct Cli {
    /// Emit the CRD JSON to stdout and exit.
    #[arg(long)]
    print_crd: bool,
    /// Run the thin cluster placer (fills empty spec.node) instead of the
    /// node-local reconciler. Run at most one elected instance with this flag.
    #[arg(long, env = "ENABLE_PLACEMENT")]
    enable_placement: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();

    if cli.print_crd {
        let crd = DisposableVm::crd();
        println!("{}", serde_json::to_string_pretty(&crd)?);
        return Ok(());
    }

    let client = kube::Client::try_default().await.context(
        "connecting to Kubernetes (reads KUBECONFIG, or in-cluster config when run as a pod)",
    )?;

    if cli.enable_placement {
        placement::run(client).await;
        return Ok(());
    }

    let node_name = std::env::var("NODE_NAME")
        .context("NODE_NAME env var is required — the node name this operator instance's spec.node filter matches against")?;
    let base_url = std::env::var("FLUXVM_URL").unwrap_or_else(|_| "http://127.0.0.1:7788".into());
    let token = std::env::var("FLUXVM_TOKEN").ok();

    let fluxvm = FluxVMClient::new(base_url, token);
    controller::run(client, fluxvm, node_name).await;
    Ok(())
}
