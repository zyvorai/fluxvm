// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Stand-alone egress proxy for `scripts/test-egress-guest.sh`. It never touches
//! the host's default network namespace: the proxy binds where it is started
//! (run it under `ip netns exec`), and the redirect helpers only operate on a
//! named namespace.
//!
//!   egress_proxy_ns serve <sandbox.json> <listen-addr>
//!   egress_proxy_ns init-ca <sandbox.json>
//!   egress_proxy_ns redirect-apply <netns> <iface> <port,port> <proxy-port>
//!   egress_proxy_ns redirect-remove <netns>
//!   egress_proxy_ns snippet <netns> <iface> <port,port> <proxy-port>

use anyhow::{Context, Result, bail};
use fluxvm_core::config::SandboxConfig;
use fluxvm_network::{egress_proxy, tls_intercept::InterceptCa, transparent_redirect};
use std::path::Path;

fn load(path: &str) -> Result<SandboxConfig> {
    serde_json::from_str(&std::fs::read_to_string(path).with_context(|| path.to_string())?)
        .context("parsing the sandbox config JSON")
}

fn spec<'a>(
    args: &'a [String],
    ports: &'a [u16],
) -> Result<transparent_redirect::RedirectSpec<'a>> {
    Ok(transparent_redirect::RedirectSpec {
        netns: &args[2],
        iface: &args[3],
        ports,
        proxy_port: args[5].parse().context("proxy port")?,
    })
}

#[tokio::main]
async fn main() -> Result<()> {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") if args.len() == 4 => {
            egress_proxy::serve(args[3].parse()?, load(&args[2])?).await
        }
        Some("init-ca") if args.len() == 3 => {
            let cfg = load(&args[2])?;
            InterceptCa::load_or_create(
                Path::new(&cfg.egress_ca_cert),
                Path::new(&cfg.egress_ca_key),
            )?;
            println!("{}", cfg.egress_ca_cert);
            Ok(())
        }
        Some(cmd @ ("redirect-apply" | "snippet")) if args.len() == 6 => {
            let ports: Vec<u16> = args[4]
                .split(',')
                .map(|p| p.parse::<u16>())
                .collect::<Result<_, _>>()
                .context("ports")?;
            let s = spec(&args, &ports)?;
            if cmd == "snippet" {
                print!("{}", transparent_redirect::snippet(&s)?);
            } else {
                transparent_redirect::apply(&s)?;
            }
            Ok(())
        }
        Some("redirect-remove") if args.len() == 3 => transparent_redirect::remove(&args[2]),
        _ => bail!("usage: see the file header"),
    }
}
