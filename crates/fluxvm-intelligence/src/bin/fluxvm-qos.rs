// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use fluxvm_intelligence::{DEFAULT_PIN_ROOT, qos, snapshot_raw};
use std::{env, path::PathBuf};
use uuid::Uuid;

fn usage() -> &'static str {
    "usage: fluxvm-qos evaluate <uuid> <pid> | fluxvm-qos apply <uuid> <pid>\n\
     evaluation is read-only; apply only changes cgroup-v2 cpu.weight/io.weight\n\
     env: FLUXVM_INTEL_PIN_ROOT"
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).context(usage())?;
    if command != "evaluate" && command != "apply" { bail!(usage()); }
    let id: Uuid = args.get(2).context(usage())?.parse()?;
    let pid: u32 = args.get(3).context(usage())?.parse()?;
    let pin_root = env::var("FLUXVM_INTEL_PIN_ROOT").map(PathBuf::from).unwrap_or_else(|_| DEFAULT_PIN_ROOT.into());
    let mut snapshot = snapshot_raw(id, pid, &pin_root)?;
    let api = env::var("FLUXVM_API_URL").unwrap_or_else(|_| "http://127.0.0.1:7788".into()).trim_end_matches('/').to_string();
    let client = reqwest::Client::new();
    let mut request = client.get(format!("{api}/v1/vms/{id}/network/stats"));
    if let Ok(token) = env::var("FLUXVM_API_TOKEN") { if !token.is_empty() { request = request.bearer_auth(token); } }
    if let Ok(response) = request.send().await {
        if response.status().is_success() {
            if let Ok(stats) = response.json::<fluxvm_intelligence::NetworkVmStats>().await { snapshot.network = Some(stats); }
        }
    }
    let cgroup = qos::cgroup_for_pid(pid)?;
    let assessment = qos::assess(&snapshot, &cgroup)?;
    if command == "evaluate" {
        println!("{}", serde_json::to_string_pretty(&assessment)?);
    } else {
        let applied = qos::apply(&cgroup, &assessment)?;
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"assessment":assessment,"applied":applied}))?);
    }
    Ok(())
}
