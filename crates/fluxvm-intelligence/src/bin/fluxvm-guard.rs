// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result, bail};
use fluxvm_intelligence::guard::{
    self, DEFAULT_GUARD_PIN_ROOT, DEFAULT_GUARD_STATE_ROOT, GuardMode,
};
use std::{env, path::PathBuf};
use uuid::Uuid;

fn usage() -> &'static str {
    "fluxvm-guard commands:\n\
     apply <uuid> <pid> [--mode audit|enforce] [--allow-exec] [--allow-wx]\n\
           [--no-device-allowlist] [--restrict-writes]\n\
           [--allow-device PATH]... [--allow-file PATH]...\n\
     status <uuid>\n\
     remove <uuid>\n\
     events <uuid> [seconds] [limit]\n\
     env: FLUXVM_GUARD_PIN_ROOT, FLUXVM_GUARD_STATE_ROOT"
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let pin_root = env::var("FLUXVM_GUARD_PIN_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| DEFAULT_GUARD_PIN_ROOT.into());
    let state_root = env::var("FLUXVM_GUARD_STATE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| DEFAULT_GUARD_STATE_ROOT.into());
    match args.get(1).map(String::as_str) {
        Some("apply") => apply(&args, &pin_root, &state_root),
        Some("status") => {
            let id: Uuid = args.get(2).context(usage())?.parse()?;
            println!(
                "{}",
                serde_json::to_string_pretty(&guard::status(id, &pin_root, &state_root)?)?
            );
            Ok(())
        }
        Some("remove") => {
            let id: Uuid = args.get(2).context(usage())?.parse()?;
            guard::remove_policy(id, &pin_root, &state_root)?;
            println!("{{\"removed\":true,\"vm_id\":\"{id}\"}}");
            Ok(())
        }
        Some("events") => {
            let id: Uuid = args.get(2).context(usage())?.parse()?;
            let seconds = args.get(3).and_then(|v| v.parse().ok()).unwrap_or(5);
            let limit = args.get(4).and_then(|v| v.parse().ok()).unwrap_or(128);
            guard::stream_events(id, &pin_root, seconds, limit)
        }
        _ => bail!(usage()),
    }
}

fn apply(args: &[String], pin_root: &std::path::Path, state_root: &std::path::Path) -> Result<()> {
    let id: Uuid = args.get(2).context(usage())?.parse()?;
    let pid: u32 = args.get(3).context(usage())?.parse()?;
    let mut mode = GuardMode::Audit;
    let mut deny_exec = true;
    let mut deny_wx = true;
    let mut restrict_devices = true;
    let mut restrict_writes = false;
    let mut allow_devices = Vec::new();
    let mut allow_files = Vec::new();
    let mut i = 4;
    while i < args.len() {
        match args[i].as_str() {
            "--mode" => {
                i += 1;
                mode = GuardMode::parse(args.get(i).context("--mode requires audit|enforce")?)?;
            }
            "--allow-exec" => deny_exec = false,
            "--allow-wx" => deny_wx = false,
            "--no-device-allowlist" => restrict_devices = false,
            "--restrict-writes" => restrict_writes = true,
            "--allow-device" => {
                i += 1;
                allow_devices.push(PathBuf::from(
                    args.get(i).context("--allow-device requires PATH")?,
                ));
            }
            "--allow-file" => {
                i += 1;
                allow_files.push(PathBuf::from(
                    args.get(i).context("--allow-file requires PATH")?,
                ));
            }
            other => bail!("unknown option {other:?}\n{}", usage()),
        }
        i += 1;
    }
    let state = guard::apply_policy(
        id,
        pid,
        mode,
        deny_exec,
        deny_wx,
        restrict_devices,
        restrict_writes,
        &allow_devices,
        &allow_files,
        pin_root,
        state_root,
    )?;
    println!("{}", serde_json::to_string_pretty(&state)?);
    Ok(())
}
