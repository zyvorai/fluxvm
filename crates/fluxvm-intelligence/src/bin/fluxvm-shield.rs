// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result, bail};
use fluxvm_intelligence::shield::{
    self, DEFAULT_SHIELD_PIN_ROOT, DEFAULT_SHIELD_STATE_ROOT, ShieldPolicy,
};
use std::{env, fs, path::PathBuf};
use uuid::Uuid;
fn usage() -> &'static str {
    "fluxvm-shield commands:\n  apply <uuid> <iface> --policy FILE\n  status <uuid>\n  metrics <uuid>\n  events <uuid> [seconds] [limit]\n  remove <uuid>\nenv: FLUXVM_SHIELD_PIN_ROOT FLUXVM_SHIELD_STATE_ROOT FLUXVM_XDP_SHIELD_LOADER FLUXVM_XDP_SHIELD_OBJECT"
}
fn main() -> Result<()> {
    let a: Vec<String> = env::args().collect();
    let pin = env::var("FLUXVM_SHIELD_PIN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| DEFAULT_SHIELD_PIN_ROOT.into());
    let state = env::var("FLUXVM_SHIELD_STATE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| DEFAULT_SHIELD_STATE_ROOT.into());
    match a.get(1).map(String::as_str) {
        Some("apply") => {
            let id: Uuid = a.get(2).context(usage())?.parse()?;
            let iface = a.get(3).context(usage())?;
            if a.get(4).map(String::as_str) != Some("--policy") {
                bail!(usage())
            }
            let file = a.get(5).context("--policy requires FILE")?;
            let p: ShieldPolicy = serde_json::from_slice(&fs::read(file)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&shield::apply_policy(id, iface, p, &pin, &state)?)?
            );
            Ok(())
        }
        Some("status") => {
            let id: Uuid = a.get(2).context(usage())?.parse()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&shield::snapshot(id, &pin, &state)?)?
            );
            Ok(())
        }
        Some("metrics") => {
            let id: Uuid = a.get(2).context(usage())?.parse()?;
            print!(
                "{}",
                shield::prometheus(&shield::snapshot(id, &pin, &state)?)
            );
            Ok(())
        }
        Some("events") => {
            let id: Uuid = a.get(2).context(usage())?.parse()?;
            let sec = a.get(3).and_then(|v| v.parse().ok()).unwrap_or(5);
            let lim = a.get(4).and_then(|v| v.parse().ok()).unwrap_or(128);
            shield::stream_events(id, &pin, sec, lim)
        }
        Some("remove") => {
            let id: Uuid = a.get(2).context(usage())?.parse()?;
            shield::remove_policy(id, &pin, &state)?;
            println!("{{\"removed\":true,\"vm_id\":\"{id}\"}}");
            Ok(())
        }
        _ => bail!(usage()),
    }
}
