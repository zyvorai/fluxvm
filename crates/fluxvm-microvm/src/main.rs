// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use fluxvm_microvm::{
    capacity, controller, convert,
    crd::{GuestImage, MicroVM, MicroVMJob, MicroVMPool},
    fluxvm_client::FluxVMClient,
    jobs, node_agent, pools,
};
use kube::CustomResourceExt;

#[derive(Parser)]
#[command(name = "fluxvm-microvm", about = "FluxVM MicroVM — Kubernetes-native disposable compute (not KubeVirt)")]
struct Cli {
    #[arg(long)]
    print_crd: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    Controller {
        #[arg(long, env = "MICROVM_REQUEST_KVM")]
        request_kvm: bool,
        #[arg(long, env = "MICROVM_CONVERT")]
        convert: bool,
    },
    NodeAgent {
        #[arg(long, env = "MICROVM_KVM_SLOTS", default_value_t = 0)]
        kvm_slots: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    if cli.print_crd {
        let crds = vec![
            serde_json::to_value(MicroVM::crd())?,
            serde_json::to_value(MicroVMJob::crd())?,
            serde_json::to_value(MicroVMPool::crd())?,
            serde_json::to_value(GuestImage::crd())?,
        ];
        println!("{}", serde_json::to_string_pretty(&crds)?);
        return Ok(());
    }
    let client = kube::Client::try_default().await.context("connecting to Kubernetes")?;
    match cli.command.unwrap_or(Command::Controller { request_kvm: false, convert: false }) {
        Command::Controller { request_kvm, convert: do_convert } => {
            let c1 = client.clone();
            let c2 = client.clone();
            let cluster = tokio::spawn(async move { controller::run(c1, request_kvm).await });
            let job = tokio::spawn(async move { jobs::run(c2).await });
            if do_convert {
                let c3 = client.clone();
                tokio::spawn(async move { convert::run(c3).await });
            }
            let _ = tokio::join!(cluster, job);
        }
        Command::NodeAgent { kvm_slots } => {
            let node_name = std::env::var("NODE_NAME").context("NODE_NAME is required")?;
            let base_url = std::env::var("FLUXVM_URL").unwrap_or_else(|_| "http://127.0.0.1:7788".into());
            let token = std::env::var("FLUXVM_TOKEN").ok();
            if kvm_slots > 0 {
                if let Err(e) = capacity::advertise(&client, &node_name, kvm_slots).await {
                    tracing::warn!(error = %e, "failed to advertise fluxvm.dev/kvm");
                }
            }
            let fluxvm = FluxVMClient::new(base_url, token);
            let c1 = client.clone();
            let f1 = fluxvm.clone();
            let n1 = node_name.clone();
            let agent = tokio::spawn(async move { node_agent::run(c1, f1, n1).await });
            let pools_h = tokio::spawn(async move { pools::run(client, fluxvm, node_name).await });
            let _ = tokio::join!(agent, pools_h);
        }
    }
    Ok(())
}
