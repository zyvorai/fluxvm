//! `fluxctl mcp serve`: a Model Context Protocol server over stdio
//! (newline-delimited JSON-RPC 2.0, tools capability only) that drives a
//! FluxVM daemon through its REST API.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::{Method, StatusCode};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use uuid::Uuid;

use crate::remote::{Remote, encode_query};

pub const LATEST_PROTOCOL_VERSION: &str = "2025-06-18";
const SUPPORTED_VERSIONS: &[&str] = &["2024-11-05", "2025-03-26", LATEST_PROTOCOL_VERSION];
/// Cap on one tool result, so a call cannot flood the model's context.
pub const MAX_OUTPUT: usize = 64 * 1024;
const CALL_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_LOG_LINES: u64 = 500;

type ToolFuture = Pin<Box<dyn Future<Output = Result<String>> + Send>>;
type ToolFn = Arc<dyn Fn(Value) -> ToolFuture + Send + Sync>;

/// One callable tool. Write tools change state and are only listed and
/// callable when the server allows writes.
#[derive(Clone)]
pub struct Tool {
    pub name: &'static str,
    pub description: &'static str,
    pub schema: Value,
    pub write: bool,
    pub call: ToolFn,
}

pub struct Server {
    name: String,
    version: String,
    allow_write: bool,
    tools: BTreeMap<&'static str, Tool>,
}

impl Server {
    pub fn new(name: &str, version: &str, allow_write: bool) -> Self {
        Self {
            name: name.into(),
            version: version.into(),
            allow_write,
            tools: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, tools: impl IntoIterator<Item = Tool>) {
        for t in tools {
            self.tools.insert(t.name, t);
        }
    }

    /// Read requests from `r` and write one response line each to `w`
    /// until `r` ends. Requests run concurrently.
    pub async fn serve<R, W>(self, r: R, w: W) -> Result<()>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let me = Arc::new(self);
        let w = Arc::new(Mutex::new(w));
        let mut lines = BufReader::new(r).lines();
        let mut tasks = tokio::task::JoinSet::new();
        while let Some(line) = lines.next_line().await? {
            if line.trim().is_empty() {
                continue;
            }
            let req: Value = match serde_json::from_str(&line) {
                Ok(v) => v,
                Err(e) => {
                    write_line(
                        &w,
                        error_response(Value::Null, -32700, &format!("parse error: {e}")),
                    )
                    .await?;
                    continue;
                }
            };
            let id = req.get("id").cloned();
            let method = req.get("method").and_then(Value::as_str).unwrap_or("");
            if method.is_empty() {
                if let Some(id) = id {
                    write_line(&w, error_response(id, -32600, "missing method")).await?;
                }
                continue;
            }
            let Some(id) = id else {
                continue; // notification; nothing to answer
            };
            let method = method.to_string();
            let params = req.get("params").cloned().unwrap_or(Value::Null);
            let me = me.clone();
            let w = w.clone();
            tasks.spawn(async move {
                let resp = match me.handle(&method, params).await {
                    Ok(result) => json!({"jsonrpc": "2.0", "id": id, "result": result}),
                    Err((code, msg)) => error_response(id, code, &msg),
                };
                let _ = write_line(&w, resp).await;
            });
        }
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    async fn handle(&self, method: &str, params: Value) -> Result<Value, (i64, String)> {
        match method {
            "initialize" => {
                let asked = params
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let version = if SUPPORTED_VERSIONS.contains(&asked) {
                    asked
                } else {
                    LATEST_PROTOCOL_VERSION
                };
                Ok(json!({
                    "protocolVersion": version,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": self.name, "version": self.version},
                }))
            }
            "ping" => Ok(json!({})),
            "tools/list" => Ok(json!({"tools": self.listed()})),
            "tools/call" => {
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                if name.is_empty() {
                    return Err((-32602, "tools/call needs a name".into()));
                }
                let Some(tool) = self.tools.get(name) else {
                    return Err((-32602, format!("unknown tool {name}")));
                };
                if tool.write && !self.allow_write {
                    return Ok(tool_result(
                        &format!(
                            "{name} changes state; start the server with --allow-write to use it"
                        ),
                        true,
                    ));
                }
                let args = match params.get("arguments") {
                    None | Some(Value::Null) => json!({}),
                    Some(v) => v.clone(),
                };
                if let Err(e) = check_args(&tool.schema, &args) {
                    return Ok(tool_result(&e.to_string(), true));
                }
                match (tool.call)(args).await {
                    Ok(text) => Ok(tool_result(&text, false)),
                    Err(e) => Ok(tool_result(&format!("{e:#}"), true)),
                }
            }
            _ => Err((-32601, format!("method not found: {method}"))),
        }
    }

    fn listed(&self) -> Vec<Value> {
        self.tools
            .values()
            .filter(|t| self.allow_write || !t.write)
            .map(|t| {
                let mut entry = json!({
                    "name": t.name,
                    "description": t.description,
                    "inputSchema": t.schema,
                });
                if !t.write {
                    entry["annotations"] = json!({"readOnlyHint": true});
                }
                entry
            })
            .collect()
    }
}

async fn write_line<W: AsyncWrite + Unpin>(w: &Mutex<W>, v: Value) -> Result<()> {
    let mut line = serde_json::to_vec(&v)?;
    line.push(b'\n');
    let mut w = w.lock().await;
    w.write_all(&line).await?;
    w.flush().await?;
    Ok(())
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

fn tool_result(text: &str, is_error: bool) -> Value {
    let text = if text.len() > MAX_OUTPUT {
        let mut cut = MAX_OUTPUT;
        while !text.is_char_boundary(cut) {
            cut -= 1;
        }
        format!(
            "{}\n[truncated: output exceeded {MAX_OUTPUT} bytes; narrow the request, e.g. with limit]",
            &text[..cut]
        )
    } else {
        text.to_string()
    };
    json!({"content": [{"type": "text", "text": text}], "isError": is_error})
}

/// Rejects unknown and missing required arguments, so a model's typo is
/// reported instead of silently ignored.
fn check_args(schema: &Value, args: &Value) -> Result<()> {
    let Some(obj) = args.as_object() else {
        bail!("invalid arguments: expected an object");
    };
    let props = schema.get("properties").and_then(Value::as_object);
    for key in obj.keys() {
        if !props.is_some_and(|p| p.contains_key(key)) {
            bail!("invalid arguments: unknown field {key:?}");
        }
    }
    for req in schema
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
    {
        if !obj.contains_key(req) {
            bail!("invalid arguments: missing {req:?}");
        }
    }
    Ok(())
}

fn object(props: Value, required: &[&str]) -> Value {
    let mut s = json!({"type": "object", "properties": props, "additionalProperties": false});
    if !required.is_empty() {
        s["required"] = json!(required);
    }
    s
}

fn pretty(v: &Value) -> Result<String> {
    Ok(serde_json::to_string_pretty(v)?)
}

fn str_arg<'a>(args: &'a Value, key: &str) -> Option<&'a str> {
    args.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
}

fn int_arg(args: &Value, key: &str) -> Result<Option<u64>> {
    match args.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .map(Some)
            .ok_or_else(|| anyhow!("{key} must be a non-negative integer")),
    }
}

/// Resolve a VM name or UUID (or unique UUID prefix) to its id.
async fn resolve(remote: &Remote, vm: &str) -> Result<Uuid> {
    if let Ok(id) = vm.parse::<Uuid>() {
        return Ok(id);
    }
    let index = remote.vm_index().await;
    let mut hits: Vec<Uuid> = index
        .iter()
        .filter(|(_, name)| name == vm)
        .map(|(id, _)| *id)
        .collect();
    if hits.is_empty() {
        hits = index
            .iter()
            .filter(|(id, _)| id.to_string().starts_with(vm))
            .map(|(id, _)| *id)
            .collect();
    }
    match hits.as_slice() {
        [id] => Ok(*id),
        [] => bail!("no VM named or prefixed {vm:?}"),
        _ => bail!("{vm:?} matches {} VMs; use the full UUID", hits.len()),
    }
}

fn summarize(vm: &Value) -> Value {
    let mut out = Map::new();
    for key in [
        "id",
        "name",
        "status",
        "backend",
        "guest_ip",
        "tap_name",
        "created_at",
        "error",
    ] {
        if let Some(v) = vm.get(key).filter(|v| !v.is_null()) {
            out.insert(key.into(), v.clone());
        }
    }
    if let Some(req) = vm.get("request") {
        for key in ["vcpus", "memory_mib", "labels"] {
            if let Some(v) = req.get(key).filter(|v| !v.is_null()) {
                out.insert(key.into(), v.clone());
            }
        }
    }
    Value::Object(out)
}

const NETWORK_KINDS: &[&str] = &[
    "status",
    "effective",
    "stats",
    "flows",
    "drops",
    "drop-reasons",
    "learned-ip",
    "conntrack",
    "capture",
];
const POWER_OPS: &[&str] = &["start", "stop", "pause", "resume", "restart"];

fn tool<F, Fut>(
    name: &'static str,
    description: &'static str,
    schema: Value,
    write: bool,
    remote: &Arc<Remote>,
    f: F,
) -> Tool
where
    F: Fn(Arc<Remote>, Value) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<String>> + Send + 'static,
{
    let remote = remote.clone();
    let f = Arc::new(f);
    Tool {
        name,
        description,
        schema,
        write,
        call: Arc::new(move |args| {
            let remote = remote.clone();
            let f = f.clone();
            Box::pin(async move { f(remote, args).await })
        }),
    }
}

async fn timed<T>(d: Duration, fut: impl Future<Output = Result<T>>) -> Result<T> {
    tokio::time::timeout(d, fut)
        .await
        .map_err(|_| anyhow!("timed out after {}s", d.as_secs()))?
}

pub fn tools(remote: Arc<Remote>) -> Vec<Tool> {
    let vm_prop = json!({"type": "string", "description": "VM name, UUID or unique UUID prefix"});
    vec![
        tool(
            "list_vms",
            "List FluxVM VMs with status, backend, guest IP, size and labels. selector filters by labels, e.g. \"env=dev,team!=x\".",
            object(
                json!({"selector": {"type": "string", "description": "label selector"}}),
                &[],
            ),
            false,
            &remote,
            |r, args| async move {
                timed(CALL_TIMEOUT, async {
                    let vms = r.list_vms(str_arg(&args, "selector")).await?;
                    let items: Vec<Value> = vms.iter().map(summarize).collect();
                    pretty(&json!({"vms": items}))
                })
                .await
            },
        ),
        tool(
            "get_vm",
            "Get one VM's full FluxVM record: request spec, status, error, network (tap, netns, guest IP) and paths.",
            object(json!({"vm": vm_prop}), &["vm"]),
            false,
            &remote,
            |r, args| async move {
                timed(CALL_TIMEOUT, async {
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    pretty(&r.call(Method::GET, &format!("/v1/vms/{id}"), None).await?)
                })
                .await
            },
        ),
        tool(
            "host_status",
            "FluxVM host readiness: KVM, state dir, dataplane mode and BPF/Cilium health, secure containers, plus the VM count by status.",
            object(json!({}), &[]),
            false,
            &remote,
            |r, _args| async move {
                timed(CALL_TIMEOUT, async {
                    let (_, body) = r.get_raw("/readyz").await?;
                    let ready: Value = serde_json::from_slice(&body)
                        .unwrap_or_else(|_| json!(String::from_utf8_lossy(&body)));
                    let mut counts = BTreeMap::<String, u64>::new();
                    for vm in r.list_vms(None).await? {
                        let s = vm
                            .get("status")
                            .and_then(Value::as_str)
                            .unwrap_or("unknown");
                        *counts.entry(s.to_string()).or_default() += 1;
                    }
                    pretty(&json!({"readyz": ready, "vms_by_status": counts}))
                })
                .await
            },
        ),
        tool(
            "vm_network",
            "Live VM-edge network data for a VM: status (dataplane attach), effective (policy), stats, flows, drops (attributed), drop-reasons, learned-ip, conntrack (live table) or capture (packet capture sessions).",
            object(
                json!({
                    "vm": vm_prop,
                    "kind": {"type": "string", "enum": NETWORK_KINDS, "description": "which view"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 1000, "description": "max entries for flows and drops"},
                }),
                &["vm", "kind"],
            ),
            false,
            &remote,
            |r, args| async move {
                timed(CALL_TIMEOUT, async {
                    let kind = str_arg(&args, "kind").unwrap_or_default();
                    if !NETWORK_KINDS.contains(&kind) {
                        bail!("kind must be one of {}", NETWORK_KINDS.join(", "));
                    }
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let mut path = format!("/v1/vms/{id}/network/{kind}");
                    if let Some(limit) = int_arg(&args, "limit")? {
                        path.push_str(&format!("?limit={limit}"));
                    }
                    pretty(&r.call(Method::GET, &path, None).await?)
                })
                .await
            },
        ),
        tool(
            "vm_logs",
            "The last lines of a VM's serial console log (boot messages, kernel panics, QEMU errors).",
            object(
                json!({
                    "vm": vm_prop,
                    "lines": {"type": "integer", "minimum": 1, "maximum": MAX_LOG_LINES, "description": "lines from the end, default 100"},
                }),
                &["vm"],
            ),
            false,
            &remote,
            |r, args| async move {
                timed(CALL_TIMEOUT, async {
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let lines = int_arg(&args, "lines")?
                        .unwrap_or(100)
                        .clamp(1, MAX_LOG_LINES);
                    let (status, body) = r
                        .get_raw(&format!("/v1/vms/{id}/logs?lines={lines}"))
                        .await?;
                    if !status.is_success() {
                        bail!("logs: {status}: {}", String::from_utf8_lossy(&body));
                    }
                    Ok(String::from_utf8_lossy(&body).into_owned())
                })
                .await
            },
        ),
        tool(
            "vm_power",
            "Change a VM's power state: start (a stopped VM), stop, pause, resume or restart. For Kairon-managed VMs prefer Kairon's set_power_state, or Kairon will reconcile it back.",
            object(
                json!({
                    "vm": vm_prop,
                    "op": {"type": "string", "enum": POWER_OPS},
                }),
                &["vm", "op"],
            ),
            true,
            &remote,
            |r, args| async move {
                timed(Duration::from_secs(120), async {
                    let op = str_arg(&args, "op").unwrap_or_default();
                    if !POWER_OPS.contains(&op) {
                        bail!("op must be one of {}", POWER_OPS.join(", "));
                    }
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let v = r.vm_op(id, op).await?;
                    pretty(&summarize(&v)).or_else(|_| pretty(&v))
                })
                .await
            },
        ),
        tool(
            "vm_capture",
            "Run a bounded tcpdump capture (1-30 s) on a VM's dataplane interface. With output, waits and writes the pcap to that local path; otherwise returns the token (check with vm_network kind=capture).",
            object(
                json!({
                    "vm": vm_prop,
                    "seconds": {"type": "integer", "minimum": 1, "maximum": 30, "description": "capture length, default 10"},
                    "filter": {"type": "string", "description": "optional tcpdump filter, e.g. \"udp port 53\""},
                    "output": {"type": "string", "description": "optional local file path for the pcap"},
                }),
                &["vm"],
            ),
            true,
            &remote,
            |r, args| async move {
                let seconds = int_arg(&args, "seconds")?.unwrap_or(10);
                if !(1..=30).contains(&seconds) {
                    bail!("seconds must be 1-30");
                }
                timed(Duration::from_secs(seconds + 45), capture(r, args, seconds)).await
            },
        ),
        tool(
            "vm_fork",
            "Fork a running flux-vm VM into count (1-32) running copies that share its memory snapshot; each child gets a copy-on-write disk. Returns the children.",
            object(
                json!({
                    "vm": vm_prop,
                    "count": {"type": "integer", "minimum": 1, "maximum": 32, "description": "children to create, default 1"},
                    "name_prefix": {"type": "string", "description": "child names are <prefix>-<n>; default <vm>-fork"},
                }),
                &["vm"],
            ),
            true,
            &remote,
            |r, args| async move {
                timed(Duration::from_secs(300), async {
                    let count = int_arg(&args, "count")?.unwrap_or(1);
                    if !(1..=32).contains(&count) {
                        bail!("count must be 1-32");
                    }
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let mut body = json!({"count": count});
                    if let Some(p) = str_arg(&args, "name_prefix") {
                        body["namePrefix"] = json!(p);
                    }
                    let v = r
                        .call(Method::POST, &format!("/v1/vms/{id}/fork"), Some(body))
                        .await?;
                    let items: Vec<Value> = v["items"]
                        .as_array()
                        .map(|a| a.iter().map(summarize).collect())
                        .unwrap_or_default();
                    pretty(&json!({"children": items, "elapsed_ms": v["elapsed_ms"]}))
                })
                .await
            },
        ),
        tool(
            "image_import",
            "Import a VM disk from a host path (OVA, OVF, VMDK, VHD(X), qcow2) as raw disks, repairing the boot disk for virtio (VMware tools off, virtio initramfs, /dev/sdX to /dev/vdX, DHCP fallback). Returns the disk paths, OVF hardware, repair report and a suggested create request.",
            object(
                json!({
                    "source": {"type": "string", "description": "host path on the FluxVM server"},
                    "name": {"type": "string", "description": "import name, [A-Za-z0-9_-]"},
                    "repair": {"type": "boolean", "description": "offline guest repair, default true"},
                    "remove_vmware_tools": {"type": "boolean", "description": "uninstall VMware tools packages, default false"},
                }),
                &["source", "name"],
            ),
            true,
            &remote,
            |r, args| async move {
                timed(Duration::from_secs(1800), async {
                    let body = json!({
                        "source": str_arg(&args, "source").unwrap_or_default(),
                        "name": str_arg(&args, "name").unwrap_or_default(),
                        "repair": args.get("repair").and_then(Value::as_bool).unwrap_or(true),
                        "remove_vmware_tools": args.get("remove_vmware_tools").and_then(Value::as_bool).unwrap_or(false),
                    });
                    pretty(&r.call(Method::POST, "/v1/images/import", Some(body)).await?)
                })
                .await
            },
        ),
        tool(
            "vm_backup",
            "Back up a QEMU VM's disks to standalone qcow2 files on the server. A running VM is snapshotted briefly; with quiesce auto (default) its filesystems are frozen through the guest agent when it answers. Returns the backup name, size and whether it was quiesced.",
            object(
                json!({
                    "vm": vm_prop,
                    "all_disks": {"type": "boolean", "description": "include data disks (a directory backup), default false"},
                    "compress": {"type": "boolean", "description": "qcow2 compression, default false"},
                    "quiesce": {"type": "string", "enum": ["auto", "required", "never"], "description": "guest fsfreeze, default auto"},
                }),
                &["vm"],
            ),
            true,
            &remote,
            |r, args| async move {
                timed(Duration::from_secs(1800), async {
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let body = json!({
                        "all_disks": args.get("all_disks").and_then(Value::as_bool).unwrap_or(false),
                        "compress": args.get("compress").and_then(Value::as_bool).unwrap_or(false),
                        "quiesce": str_arg(&args, "quiesce").unwrap_or("auto"),
                    });
                    pretty(&r.call(Method::POST, &format!("/v1/vms/{id}/backup"), Some(body)).await?)
                })
                .await
            },
        ),
        tool(
            "backup_list",
            "Backups on the server, newest first: name, source VM, size, whether live and quiesced.",
            object(json!({}), &[]),
            false,
            &remote,
            |r, _args| async move { pretty(&r.call(Method::GET, "/v1/backups", None).await?) },
        ),
        tool(
            "backup_restore",
            "Restore a backup (name from backup_list) into a stopped VM in place, replacing its root and backed-up data disks.",
            object(
                json!({
                    "vm": vm_prop,
                    "name": {"type": "string", "description": "backup name"},
                }),
                &["vm", "name"],
            ),
            true,
            &remote,
            |r, args| async move {
                timed(Duration::from_secs(1800), async {
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let body = json!({"name": str_arg(&args, "name").unwrap_or_default()});
                    pretty(
                        &r.call(
                            Method::POST,
                            &format!("/v1/vms/{id}/restore-backup"),
                            Some(body),
                        )
                        .await?,
                    )
                })
                .await
            },
        ),
        tool(
            "pool_claim",
            "Claim an already-booted VM from a warm pool (milliseconds instead of a cold boot). The pool refills in the background.",
            object(
                json!({
                    "pool": {"type": "string", "description": "warm pool name"},
                    "name": {"type": "string", "description": "optional new VM name"},
                    "ttl_seconds": {"type": "integer", "minimum": 1, "description": "optional lifetime"},
                }),
                &["pool"],
            ),
            true,
            &remote,
            |r, args| async move {
                timed(Duration::from_secs(120), async {
                    let pool = str_arg(&args, "pool").unwrap_or_default();
                    let mut body = json!({});
                    if let Some(n) = str_arg(&args, "name") {
                        body["name"] = json!(n);
                    }
                    if let Some(t) = int_arg(&args, "ttl_seconds")? {
                        body["ttl_seconds"] = json!(t);
                    }
                    let v = r
                        .call(
                            Method::POST,
                            &format!("/v1/pools/{}/claim", encode_query(pool)),
                            Some(body),
                        )
                        .await?;
                    pretty(&summarize(&v)).or_else(|_| pretty(&v))
                })
                .await
            },
        ),
        tool(
            "sandbox_create",
            "Create an agent sandbox VM from a named template (or the host default) with an optional TTL.",
            object(
                json!({
                    "template": {"type": "string", "description": "sandbox template name"},
                    "name": {"type": "string"},
                    "ttl_seconds": {"type": "integer", "minimum": 1},
                }),
                &[],
            ),
            true,
            &remote,
            |r, args| async move {
                timed(Duration::from_secs(180), async {
                    let mut body = json!({});
                    for key in ["template", "name"] {
                        if let Some(v) = str_arg(&args, key) {
                            body[key] = json!(v);
                        }
                    }
                    if let Some(t) = int_arg(&args, "ttl_seconds")? {
                        body["ttl_seconds"] = json!(t);
                    }
                    pretty(&r.call(Method::POST, "/v1/sandboxes", Some(body)).await?)
                })
                .await
            },
        ),
        tool(
            "sandbox_exec",
            "Run a shell command inside a sandbox VM through the guest agent; returns exit code, stdout and stderr.",
            object(
                json!({
                    "vm": vm_prop,
                    "command": {"type": "string"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 600, "description": "default 60"},
                }),
                &["vm", "command"],
            ),
            true,
            &remote,
            |r, args| async move {
                let timeout = int_arg(&args, "timeout_seconds")?.unwrap_or(60).min(600);
                timed(Duration::from_secs(timeout + 30), async {
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let body = json!({
                        "command": str_arg(&args, "command").unwrap_or_default(),
                        "timeout_seconds": timeout,
                    });
                    pretty(
                        &r.call(
                            Method::POST,
                            &format!("/v1/sandboxes/{id}/process"),
                            Some(body),
                        )
                        .await?,
                    )
                })
                .await
            },
        ),
        tool(
            "sandbox_read_file",
            "Read a file from inside a sandbox VM (returned base64-encoded with its size).",
            object(
                json!({"vm": vm_prop, "path": {"type": "string", "description": "absolute guest path"}}),
                &["vm", "path"],
            ),
            false,
            &remote,
            |r, args| async move {
                timed(CALL_TIMEOUT, async {
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let body = json!({"path": str_arg(&args, "path").unwrap_or_default()});
                    pretty(
                        &r.call(
                            Method::POST,
                            &format!("/v1/sandboxes/{id}/fs/read"),
                            Some(body),
                        )
                        .await?,
                    )
                })
                .await
            },
        ),
        tool(
            "sandbox_write_file",
            "Write a UTF-8 text file inside a sandbox VM.",
            object(
                json!({
                    "vm": vm_prop,
                    "path": {"type": "string", "description": "absolute guest path"},
                    "content": {"type": "string"},
                    "mode": {"type": "integer", "description": "octal permission bits as a number, e.g. 420 for 0644"},
                }),
                &["vm", "path", "content"],
            ),
            true,
            &remote,
            |r, args| async move {
                use base64::Engine as _;
                timed(CALL_TIMEOUT, async {
                    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
                    let content = str_arg(&args, "content").unwrap_or_default();
                    let mut body = json!({
                        "path": str_arg(&args, "path").unwrap_or_default(),
                        "content_base64": base64::engine::general_purpose::STANDARD.encode(content),
                    });
                    if let Some(m) = int_arg(&args, "mode")? {
                        body["mode"] = json!(m);
                    }
                    pretty(
                        &r.call(
                            Method::POST,
                            &format!("/v1/sandboxes/{id}/fs/write"),
                            Some(body),
                        )
                        .await?,
                    )
                })
                .await
            },
        ),
    ]
}

async fn capture(r: Arc<Remote>, args: Value, seconds: u64) -> Result<String> {
    let id = resolve(&r, str_arg(&args, "vm").unwrap_or_default()).await?;
    let token = format!("mcp-{}", Uuid::new_v4().simple());
    let expires = chrono::Utc::now() + chrono::Duration::seconds(seconds as i64 + 60);
    let session = json!({
        "token": token,
        "namespace": "fluxvm",
        "machine": id.to_string(),
        "seconds": seconds,
        "filter": str_arg(&args, "filter").unwrap_or(""),
        "expiresAt": expires.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
    });
    r.call(
        Method::POST,
        &format!("/v1/vms/{id}/network/capture"),
        Some(session),
    )
    .await?;
    let Some(output) = str_arg(&args, "output") else {
        return pretty(&json!({"token": token, "seconds": seconds, "state": "running"}));
    };
    tokio::time::sleep(Duration::from_secs(seconds)).await;
    let path = format!("/v1/vms/{id}/network/capture/{}", encode_query(&token));
    loop {
        let (status, body) = r.get_raw(&path).await?;
        match status {
            StatusCode::OK => {
                tokio::fs::write(output, &body)
                    .await
                    .with_context(|| format!("writing {output}"))?;
                return Ok(format!(
                    "capture {token} done: wrote {} bytes to {output}",
                    body.len()
                ));
            }
            StatusCode::CONFLICT => tokio::time::sleep(Duration::from_secs(1)).await,
            _ => bail!(
                "capture download: {status}: {}",
                String::from_utf8_lossy(&body)
            ),
        }
    }
}

pub async fn serve(remote: Remote, allow_write: bool) -> Result<()> {
    let mut server = Server::new("fluxvm", env!("CARGO_PKG_VERSION"), allow_write);
    server.add(tools(Arc::new(remote)));
    server.serve(tokio::io::stdin(), tokio::io::stdout()).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_server(allow_write: bool) -> Server {
        let mut s = Server::new("t", "0", allow_write);
        let echo: ToolFn = Arc::new(|args| {
            Box::pin(async move { Ok(str_arg(&args, "msg").unwrap_or("").to_string()) })
        });
        let fail: ToolFn = Arc::new(|_| Box::pin(async { Err(anyhow!("boom")) }));
        let big: ToolFn = Arc::new(|_| Box::pin(async { Ok("é".repeat(MAX_OUTPUT)) }));
        let stop: ToolFn = Arc::new(|_| Box::pin(async { Ok("stopped".to_string()) }));
        s.add([
            Tool {
                name: "echo",
                description: "",
                schema: object(json!({"msg": {"type": "string"}}), &["msg"]),
                write: false,
                call: echo,
            },
            Tool {
                name: "fail",
                description: "",
                schema: object(json!({}), &[]),
                write: false,
                call: fail,
            },
            Tool {
                name: "big",
                description: "",
                schema: object(json!({}), &[]),
                write: false,
                call: big,
            },
            Tool {
                name: "stop",
                description: "",
                schema: object(json!({}), &[]),
                write: true,
                call: stop,
            },
        ]);
        s
    }

    async fn run(s: Server, lines: &[&str]) -> BTreeMap<String, Value> {
        let input = lines.join("\n") + "\n";
        let (client, server_end) = tokio::io::duplex(1 << 20);
        s.serve(input.as_bytes(), server_end).await.unwrap();
        let mut out = String::new();
        let mut reader = BufReader::new(client);
        let mut got = BTreeMap::new();
        loop {
            out.clear();
            let n = tokio::time::timeout(Duration::from_millis(200), reader.read_line(&mut out))
                .await
                .unwrap_or(Ok(0))
                .unwrap();
            if n == 0 {
                break;
            }
            let v: Value = serde_json::from_str(&out).unwrap();
            got.insert(v["id"].to_string(), v);
        }
        got
    }

    fn text(v: &Value) -> (&str, bool) {
        (
            v["result"]["content"][0]["text"].as_str().unwrap(),
            v["result"]["isError"].as_bool().unwrap(),
        )
    }

    #[tokio::test]
    async fn initialize_ping_and_notifications() {
        let got = run(
            test_server(false),
            &[
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                r#"{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"1999-01-01"}}"#,
                r#"{"jsonrpc":"2.0","id":3,"method":"ping"}"#,
                r#"not json"#,
                r#"{"jsonrpc":"2.0","id":4,"method":"resources/list"}"#,
            ],
        )
        .await;
        assert_eq!(got.len(), 5, "{got:?}");
        assert_eq!(got["1"]["result"]["protocolVersion"], "2024-11-05");
        assert_eq!(
            got["2"]["result"]["protocolVersion"],
            LATEST_PROTOCOL_VERSION
        );
        assert!(got["3"]["error"].is_null());
        assert_eq!(got["null"]["error"]["code"], -32700);
        assert_eq!(got["4"]["error"]["code"], -32601);
    }

    #[tokio::test]
    async fn write_tools_are_gated() {
        let names = |got: &BTreeMap<String, Value>| -> Vec<String> {
            got["1"]["result"]["tools"]
                .as_array()
                .unwrap()
                .iter()
                .map(|t| t["name"].as_str().unwrap().to_string())
                .collect()
        };
        let list = r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#;
        assert_eq!(
            names(&run(test_server(false), &[list]).await),
            ["big", "echo", "fail"]
        );
        assert_eq!(
            names(&run(test_server(true), &[list]).await),
            ["big", "echo", "fail", "stop"]
        );
        let got = run(
            test_server(false),
            &[r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"stop"}}"#],
        )
        .await;
        let (t, err) = text(&got["2"]);
        assert!(err && t.contains("--allow-write"), "{t}");
    }

    #[tokio::test]
    async fn tool_calls_and_argument_checks() {
        let got = run(
            test_server(false),
            &[
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"hi"}}}"#,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fail"}}"#,
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"echo","arguments":{"msg":"x","bogus":1}}}"#,
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"echo","arguments":{}}}"#,
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"nope"}}"#,
                r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"big"}}"#,
            ],
        )
        .await;
        assert_eq!(text(&got["1"]), ("hi", false));
        assert_eq!(text(&got["2"]), ("boom", true));
        assert!(text(&got["3"]).0.contains("unknown field"));
        assert!(text(&got["4"]).0.contains("missing"));
        assert_eq!(got["5"]["error"]["code"], -32602);
        let (t, _) = text(&got["6"]);
        assert!(t.contains("[truncated") && t.len() < MAX_OUTPUT + 200);
    }

    #[tokio::test]
    async fn tools_drive_the_rest_api() {
        use axum::{Json, Router, extract::Path, routing::get, routing::post};
        let id = Uuid::new_v4();
        let app = Router::new()
            .route(
                "/v1/vms",
                get(move || async move {
                    Json(json!({"items": [{"id": id, "name": "web", "status": "running", "backend": "qemu", "request": {"vcpus": 2, "labels": {"env": "dev"}}, "pid": 7}]}))
                }),
            )
            .route(
                "/v1/vms/{id}/network/{kind}",
                get(|Path((_, kind)): Path<(Uuid, String)>| async move { Json(json!({"kind": kind})) }),
            )
            .route(
                "/v1/vms/{id}/stop",
                post(move || async move { Json(json!({"id": id, "name": "web", "status": "stopped"})) }),
            )
            .route(
                "/v1/vms/{id}/fork",
                post(|Json(body): Json<Value>| async move {
                    let n = body["count"].as_u64().unwrap_or(0);
                    let items: Vec<Value> = (1..=n)
                        .map(|i| json!({"id": Uuid::new_v4(), "name": format!("{}-{i}", body["namePrefix"].as_str().unwrap_or("web-fork")), "status": "running"}))
                        .collect();
                    Json(json!({"items": items, "elapsed_ms": 42}))
                }),
            )
            .route(
                "/v1/vms/{id}/backup",
                post(|Json(body): Json<Value>| async move {
                    Json(json!({"name": "web-1", "quiesced": body["quiesce"] != "never", "all": body["all_disks"]}))
                }),
            );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        let remote = Arc::new(Remote::new(&addr.to_string(), None));
        let mut s = Server::new("fluxvm", "0", true);
        s.add(tools(remote));
        let got = run(
            s,
            &[
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"list_vms","arguments":{}}}"#,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"vm_network","arguments":{"vm":"web","kind":"drops","limit":5}}}"#,
                r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"vm_network","arguments":{"vm":"web","kind":"bogus"}}}"#,
                r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"vm_power","arguments":{"vm":"web","op":"stop"}}}"#,
                r#"{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"get_vm","arguments":{"vm":"missing"}}}"#,
                r#"{"jsonrpc":"2.0","id":6,"method":"tools/call","params":{"name":"vm_fork","arguments":{"vm":"web","count":3,"name_prefix":"kid"}}}"#,
                r#"{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"vm_fork","arguments":{"vm":"web","count":99}}}"#,
                r#"{"jsonrpc":"2.0","id":8,"method":"tools/call","params":{"name":"vm_backup","arguments":{"vm":"web","all_disks":true}}}"#,
            ],
        )
        .await;
        let (t, err) = text(&got["1"]);
        assert!(
            !err && t.contains("\"vcpus\": 2") && !t.contains("\"pid\""),
            "{t}"
        );
        assert!(text(&got["2"]).0.contains("\"kind\": \"drops\""));
        assert!(text(&got["3"]).1);
        assert!(text(&got["4"]).0.contains("stopped"));
        let (t, err) = text(&got["5"]);
        assert!(err && t.contains("no VM named"), "{t}");
        let (t, err) = text(&got["6"]);
        assert!(
            !err && t.contains("kid-3") && t.contains("\"elapsed_ms\": 42"),
            "{t}"
        );
        let (t, err) = text(&got["7"]);
        assert!(err && t.contains("1-32"), "{t}");
        let (t, err) = text(&got["8"]);
        assert!(
            !err && t.contains("\"quiesced\": true") && t.contains("\"all\": true"),
            "{t}"
        );
    }
}
