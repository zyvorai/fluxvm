// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! `fluxctl up|down|ps --fleet URL`: run a stack on one node of a `fluxvm-agent central` fleet. The whole stack goes
//! to one node, because its services reach each other through that Mac's NAT gateway. A stack that already has VMs on
//! a node stays there (also when that node has since been drained); otherwise the node is the `--node`/`placement.node`
//! pin, or the healthy, undrained node with the requested labels and the most free capacity.

use crate::fleet_client;
use crate::stack::{self, L_STACK, StackFile};
use anyhow::{Result, bail};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Node {
    pub name: String,
    pub url: String,
    pub healthy: bool,
    pub cordoned: bool,
    pub labels: BTreeMap<String, String>,
    pub vcpus_total: u64,
    pub memory_mib_total: u64,
    pub free_vcpus: u64,
    pub free_memory_mib: u64,
    pub vm_count: u64,
}

/// `GET /fleet/nodes`'s `items`.
pub fn parse_nodes(v: &Value) -> Vec<Node> {
    let n = |x: &Value, k: &str| x[k].as_u64().unwrap_or(0);
    v["items"]
        .as_array()
        .map(Vec::as_slice)
        .unwrap_or_default()
        .iter()
        .filter_map(|x| {
            Some(Node {
                name: x["name"].as_str()?.to_owned(),
                url: x["fluxvm_url"].as_str()?.to_owned(),
                healthy: x["healthy"].as_bool().unwrap_or(false),
                cordoned: x["cordoned"].as_bool().unwrap_or(false),
                labels: x["labels"]
                    .as_object()
                    .map(|m| {
                        m.iter()
                            .filter_map(|(k, v)| Some((k.clone(), v.as_str()?.to_owned())))
                            .collect()
                    })
                    .unwrap_or_default(),
                vcpus_total: n(x, "vcpus_total"),
                memory_mib_total: n(x, "memory_mib_total"),
                free_vcpus: n(x, "free_vcpus"),
                free_memory_mib: n(x, "free_memory_mib"),
                vm_count: n(x, "vm_count"),
            })
        })
        .collect()
}

/// vCPUs and MiB the services of `levels` ask for, with the daemon's defaults for what they leave out.
pub fn needs(f: &StackFile, levels: &[Vec<String>]) -> (u64, u64) {
    levels.iter().flatten().fold((0, 0), |(c, m), name| {
        let svc = &f.service[name];
        let (dc, dm) = if svc.container.is_some() {
            (
                u64::from(fluxvm_scheduler::oci_sandbox::OCI_DEFAULT_VCPUS),
                fluxvm_scheduler::oci_sandbox::OCI_DEFAULT_MEMORY_MIB,
            )
        } else {
            (2, 2048)
        };
        (
            c + svc.cpus.or(f.defaults.cpus).map_or(dc, u64::from),
            m + svc.memory_mib.or(f.defaults.memory_mib).unwrap_or(dm),
        )
    })
}

/// Where the stack goes. `holding`: nodes that already run some of its VMs; `unknown`: nodes whose VMs could not be
/// listed (they might hold some too).
pub fn choose<'a>(
    nodes: &'a [Node],
    holding: &BTreeSet<String>,
    unknown: &BTreeSet<String>,
    pin: Option<&str>,
    labels: &BTreeMap<String, String>,
    (cpus, mem): (u64, u64),
) -> Result<&'a Node> {
    let by_name = |name: &str| nodes.iter().find(|n| n.name == name);
    if holding.len() > 1 {
        bail!(
            "the stack has VMs on several nodes ({}); `down` it before placing it again",
            holding.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    if let Some(at) = holding.first() {
        if let Some(p) = pin
            && p != at
        {
            bail!("the stack already runs on node {at}, not {p}; `down` it to move it");
        }
        let node = by_name(at).expect("holding nodes come from the node list");
        if !node.healthy {
            bail!("the stack runs on node {at}, which is not healthy");
        }
        return Ok(node);
    }
    if let Some(p) = pin {
        let node = by_name(p).ok_or_else(|| anyhow::anyhow!("no fleet node named {p}"))?;
        if !node.healthy {
            bail!("node {p} is not healthy");
        }
        return Ok(node);
    }
    if !unknown.is_empty() {
        bail!(
            "cannot list the VMs on {}, which may already run this stack; pick a node with --node",
            unknown.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    let frac = |free: u64, total: u64| (free * 10_000).checked_div(total).unwrap_or(0);
    nodes
        .iter()
        .filter(|n| n.healthy && !n.cordoned)
        .filter(|n| labels.iter().all(|(k, v)| n.labels.get(k) == Some(v)))
        .filter(|n| n.vcpus_total >= cpus && n.memory_mib_total >= mem)
        // Free capacity is estimated from VM counts, so a node that looks full but could hold the stack is a last resort,
        // not excluded.
        .max_by_key(|n| {
            (
                n.free_vcpus >= cpus && n.free_memory_mib >= mem,
                frac(n.free_vcpus, n.vcpus_total).min(frac(n.free_memory_mib, n.memory_mib_total)),
                std::cmp::Reverse(n.vm_count),
                std::cmp::Reverse(n.name.clone()),
            )
        })
        .ok_or_else(|| {
            let want = labels
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",");
            anyhow::anyhow!(
                "no healthy, undrained node{} can hold {cpus} vCPUs and {mem} MiB",
                if want.is_empty() {
                    String::new()
                } else {
                    format!(" with {want}")
                }
            )
        })
}

/// The registry's nodes, and which of them hold VMs of `stack` (and which could not be asked).
pub async fn locate(
    central: &str,
    token: Option<&str>,
    stack: &str,
) -> Result<(Vec<Node>, BTreeSet<String>, BTreeSet<String>)> {
    let nodes = parse_nodes(&fleet_client::list_nodes(central, token).await?);
    let (mut holding, mut unknown) = (BTreeSet::new(), BTreeSet::new());
    for n in &nodes {
        match fleet_client::node_vms(central, token, &n.name).await {
            Ok(v) => {
                let has = v["items"]
                    .as_array()
                    .is_some_and(|vms| vms.iter().any(|vm| vm["labels"][L_STACK] == stack));
                if has {
                    holding.insert(n.name.clone());
                }
            }
            Err(e) => {
                tracing::warn!(node = %n.name, "listing VMs: {e:#}");
                unknown.insert(n.name.clone());
            }
        }
    }
    Ok((nodes, holding, unknown))
}

/// `up --fleet`: the node to run `f` on.
pub async fn place(
    central: &str,
    token: Option<&str>,
    f: &StackFile,
    only: Option<&[String]>,
    node: Option<&str>,
    selector: &[(String, String)],
) -> Result<Node> {
    let mut labels = f.placement.labels.clone();
    labels.extend(selector.iter().cloned());
    let pin = node.or(f.placement.node.as_deref());
    let need = needs(f, &stack::levels(f, only)?);
    let (nodes, holding, unknown) = locate(central, token, &f.name).await?;
    choose(&nodes, &holding, &unknown, pin, &labels, need).cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn node(name: &str, free: u64, vms: u64) -> Value {
        json!({"name": name, "fluxvm_url": format!("http://{name}:7788"), "healthy": true, "cordoned": false,
               "labels": {}, "vcpus_total": 8, "memory_mib_total": 16384, "free_vcpus": free,
               "free_memory_mib": free * 2048, "vm_count": vms})
    }

    fn fleet(items: Vec<Value>) -> Vec<Node> {
        parse_nodes(&json!({ "items": items }))
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn a_new_stack_goes_to_the_freest_undrained_node_with_the_labels() {
        let mut drained = node("c", 8, 0);
        drained["cordoned"] = json!(true);
        let mut gpu = node("b", 2, 3);
        gpu["labels"] = json!({"gpu": "m3"});
        let nodes = fleet(vec![node("a", 4, 2), gpu, drained]);
        let none = BTreeMap::new();
        let pick = |labels: &BTreeMap<String, String>, need| {
            choose(&nodes, &set(&[]), &set(&[]), None, labels, need).map(|n| n.name.clone())
        };
        assert_eq!(pick(&none, (2, 2048)).unwrap(), "a");
        let gpu = BTreeMap::from([("gpu".to_string(), "m3".to_string())]);
        assert_eq!(pick(&gpu, (2, 2048)).unwrap(), "b");
        // Looks full by estimate but is big enough: still a candidate.
        assert_eq!(pick(&gpu, (6, 2048)).unwrap(), "b");
        assert!(
            pick(&gpu, (9, 2048))
                .unwrap_err()
                .to_string()
                .contains("gpu=m3")
        );
    }

    #[test]
    fn a_running_stack_stays_where_it_is() {
        let mut drained = node("c", 8, 1);
        drained["cordoned"] = json!(true);
        let nodes = fleet(vec![node("a", 8, 0), drained]);
        let none = BTreeMap::new();
        let at = choose(&nodes, &set(&["c"]), &set(&[]), None, &none, (1, 512)).unwrap();
        assert_eq!(at.name, "c");
        let err = choose(&nodes, &set(&["c"]), &set(&[]), Some("a"), &none, (1, 512)).unwrap_err();
        assert!(err.to_string().contains("already runs on node c"));
        assert!(choose(&nodes, &set(&["a", "c"]), &set(&[]), None, &none, (1, 512)).is_err());
        // A node that could not be asked might hold it: no automatic placement, but a pin is fine.
        assert!(choose(&nodes, &set(&[]), &set(&["c"]), None, &none, (1, 512)).is_err());
        let pinned = choose(&nodes, &set(&[]), &set(&["c"]), Some("c"), &none, (1, 512)).unwrap();
        assert_eq!(pinned.name, "c");
    }

    #[test]
    fn needs_add_up_the_services_with_the_daemon_defaults() {
        let f = stack::parse(
            r#"
            name = "s"
            [placement]
            labels = { zone = "lab" }
            [service.db]
            container = "postgres:17"
            [service.web]
            cpus = 4
            depends_on = ["db"]
            "#,
        )
        .unwrap();
        assert_eq!(f.placement.labels["zone"], "lab");
        assert_eq!(
            needs(&f, &stack::levels(&f, None).unwrap()),
            (5, 2048 + 512)
        );
    }
}
