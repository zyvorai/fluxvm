// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Host-to-guest limits for the Kairon VM edge. The eBPF program only sees
//! guest egress, so ingress bandwidth is a root `tbf` qdisc and ingress packet
//! rate a `matchall` policer on the egress hook of the VM's host-side device.

use anyhow::{Context, Result, bail};
use serde_json::Value;

use crate::edge_contract::EdgeQos;

/// Runs before the Pod-ingress program (pref 49153); `pipe` hands conforming
/// packets on to it.
const POLICE_PREF: &str = "49150";
const POLICE_HANDLE: &str = "0x10";

pub fn apply(iface: &str, qos: &EdgeQos) -> Result<()> {
    if qos.ingress_mbps > 0 {
        let bytes_per_sec = u64::from(qos.ingress_mbps) * 1_000_000 / 8;
        let burst = (bytes_per_sec / 50).max(64 * 1024);
        tc(&[
            "qdisc",
            "replace",
            "dev",
            iface,
            "root",
            "tbf",
            "rate",
            &format!("{}mbit", qos.ingress_mbps),
            "burst",
            &burst.to_string(),
            "latency",
            "50ms",
        ])
        .context("installing the edge ingress bandwidth limit")?;
    } else {
        clear_tbf(iface);
    }
    if qos.ingress_pps > 0 {
        ensure_clsact(iface)?;
        let pps = qos.ingress_pps.to_string();
        tc(&[
            "filter",
            "replace",
            "dev",
            iface,
            "egress",
            "pref",
            POLICE_PREF,
            "handle",
            POLICE_HANDLE,
            "matchall",
            "action",
            "police",
            "pkts_rate",
            &pps,
            "pkts_burst",
            &pps,
            "conform-exceed",
            "drop/pipe",
        ])
        .context("installing the edge ingress packet-rate limit")?;
    } else {
        clear_police(iface);
    }
    Ok(())
}

pub fn clear(iface: &str) {
    clear_tbf(iface);
    clear_police(iface);
}

/// Packets the ingress limits dropped since they were installed.
pub fn drops(iface: &str) -> u64 {
    let qdisc = tc_json(&["-s", "-j", "qdisc", "show", "dev", iface])
        .map(|v| sum_drops(&v, "tbf"))
        .unwrap_or(0);
    let police = tc_json(&["-s", "-j", "filter", "show", "dev", iface, "egress"])
        .map(|v| sum_drops(&v, "police"))
        .unwrap_or(0);
    qdisc + police
}

fn clear_tbf(iface: &str) {
    let installed = tc_json(&["-j", "qdisc", "show", "dev", iface, "root"])
        .map(|v| has_kind(&v, "tbf"))
        .unwrap_or(false);
    if installed {
        let _ = tc(&["qdisc", "del", "dev", iface, "root"]);
    }
}

fn clear_police(iface: &str) {
    let _ = tc(&[
        "filter",
        "del",
        "dev",
        iface,
        "egress",
        "pref",
        POLICE_PREF,
        "handle",
        POLICE_HANDLE,
        "matchall",
    ]);
}

fn ensure_clsact(iface: &str) -> Result<()> {
    let present = tc_json(&["-j", "qdisc", "show", "dev", iface])
        .map(|v| has_kind(&v, "clsact"))
        .unwrap_or(false);
    if present {
        return Ok(());
    }
    tc(&["qdisc", "add", "dev", iface, "clsact"])
}

fn has_kind(v: &Value, kind: &str) -> bool {
    match v {
        Value::Array(items) => items.iter().any(|i| has_kind(i, kind)),
        Value::Object(map) => {
            map.get("kind").and_then(Value::as_str) == Some(kind)
                || map.values().any(|i| has_kind(i, kind))
        }
        _ => false,
    }
}

/// Sums `drops` from every object whose `kind` matches, including the
/// `stats` block `tc -s` nests inside actions.
fn sum_drops(v: &Value, kind: &str) -> u64 {
    match v {
        Value::Array(items) => items.iter().map(|i| sum_drops(i, kind)).sum(),
        Value::Object(map) => {
            if map.get("kind").and_then(Value::as_str) == Some(kind) {
                let own = map
                    .get("drops")
                    .or_else(|| map.get("stats").and_then(|s| s.get("drops")))
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                return own;
            }
            map.values().map(|i| sum_drops(i, kind)).sum()
        }
        _ => 0,
    }
}

fn tc(args: &[&str]) -> Result<()> {
    let out = crate::netns_scope::command("tc")
        .args(args)
        .output()
        .context("running tc")?;
    if !out.status.success() {
        bail!(
            "tc {} failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn tc_json(args: &[&str]) -> Result<Value> {
    let out = crate::netns_scope::command("tc")
        .args(args)
        .output()
        .context("running tc")?;
    if !out.status.success() {
        bail!("tc {} failed", args.join(" "));
    }
    serde_json::from_slice(&out.stdout).context("parsing tc JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sums_tbf_and_police_drops() {
        let qdisc = json!([{"kind":"tbf","handle":"8001:","drops":7},{"kind":"clsact","drops":99}]);
        assert_eq!(sum_drops(&qdisc, "tbf"), 7);
        let filters = json!([{"kind":"matchall","options":{"actions":[
            {"kind":"police","stats":{"drops":5,"packets":40}}]}}]);
        assert_eq!(sum_drops(&filters, "police"), 5);
        assert!(has_kind(&filters, "police"));
    }
}
