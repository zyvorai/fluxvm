// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxvm-vz-switch --socket PATH [--idle-exit-secs N]`: serves one private network of `vz` guests (see the library).

use std::path::PathBuf;
use std::time::Duration;

fn main() {
    let mut socket: Option<PathBuf> = None;
    let mut idle = Duration::from_secs(30);
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--socket" => socket = args.next().map(PathBuf::from),
            "--idle-exit-secs" => {
                idle = Duration::from_secs(args.next().and_then(|v| v.parse().ok()).unwrap_or(30));
            }
            _ => {
                eprintln!("usage: fluxvm-vz-switch --socket PATH [--idle-exit-secs N]");
                std::process::exit(2);
            }
        }
    }
    let Some(socket) = socket else {
        eprintln!("usage: fluxvm-vz-switch --socket PATH [--idle-exit-secs N]");
        std::process::exit(2);
    };
    if let Err(e) = fluxvm_vz_switch::serve(&socket, idle) {
        eprintln!("fluxvm-vz-switch: {e:#}");
        std::process::exit(1);
    }
}
