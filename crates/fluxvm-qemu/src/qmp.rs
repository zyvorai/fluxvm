// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! Minimal QMP client: connects fresh for each call (QEMU's QMP chardev
//! handles that fine for the low command rate here), does the required
//! capabilities-negotiation handshake, sends one command, and returns its
//! `return` value. Every connect/read/write is bounded by `timeout` — the
//! original draft this was ported from had none, which meant a wedged QEMU
//! process could hang the caller forever.

use anyhow::{Context, Result, bail};
use fluxvm_core::backend::validate_migration_transport;
use fluxvm_core::model::{MigrationMode, MigrationPhase, MigrationStartRequest, MigrationStatus};
use serde_json::{Value, json};
use std::{io::ErrorKind, path::Path, time::Duration};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, ReadHalf, WriteHalf};
use tokio::net::UnixStream;

pub async fn execute(
    socket: &Path,
    command: &str,
    args: Option<Value>,
    timeout: Duration,
) -> Result<Value> {
    tokio::time::timeout(timeout, execute_inner(socket, command, args))
        .await
        .with_context(|| format!("QMP {command} timed out after {timeout:?}"))?
}

/// True for I/O errors worth retrying the *whole handshake* (not just the
/// connect) from scratch. QEMU is started with `-qmp
/// unix:...,server=on,wait=off`, so by the time `launch()` returns its pid,
/// the socket file may not exist yet (`NotFound`/`ConnectionRefused` — the
/// listener isn't up), AND, observed on real hardware, a connection made
/// very early can be accepted and then dropped mid-handshake while QEMU's
/// device model is still initializing (`ConnectionReset`/`BrokenPipe`/a
/// clean EOF where a response line was expected). Both cases mean "ask
/// again shortly," not "QEMU rejected this."
fn is_transient_startup_error(kind: ErrorKind) -> bool {
    matches!(
        kind,
        ErrorKind::NotFound
            | ErrorKind::ConnectionRefused
            | ErrorKind::ConnectionReset
            | ErrorKind::BrokenPipe
            | ErrorKind::UnexpectedEof
    )
}

type QmpHalves = (BufReader<ReadHalf<UnixStream>>, WriteHalf<UnixStream>);

/// Connect + read the greeting + negotiate capabilities, retrying the
/// *entire* sequence from a fresh connection on any transient error (see
/// `is_transient_startup_error`) — never just the failed step, since a
/// half-completed handshake on a reset connection can't be resumed. Bounded
/// only by the caller's overall `timeout` via the wrapping
/// `tokio::time::timeout` in `execute`. Never retries once the actual
/// command has been sent (see `execute_inner`) — a command like
/// `system_powerdown` isn't safe to risk sending twice.
async fn handshake_retrying(socket: &Path) -> Result<QmpHalves> {
    let mut delay = Duration::from_millis(20);
    loop {
        match try_handshake(socket).await {
            Ok(halves) => return Ok(halves),
            Err(e) if is_transient_startup_error(e.kind()) => {
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(Duration::from_millis(500));
            }
            Err(e) => {
                return Err(e).with_context(|| format!("QMP handshake with {}", socket.display()));
            }
        }
    }
}

async fn try_handshake(socket: &Path) -> std::io::Result<QmpHalves> {
    let stream = UnixStream::connect(socket).await?;
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);

    // Greeting: QEMU sends {"QMP": {...}} immediately on connect.
    let mut greeting = String::new();
    if reader.read_line(&mut greeting).await? == 0 {
        return Err(std::io::Error::new(
            ErrorKind::UnexpectedEof,
            "connection closed before QMP greeting",
        ));
    }
    if serde_json::from_str::<Value>(&greeting)
        .ok()
        .and_then(|v| v.get("QMP").cloned())
        .is_none()
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("unexpected QMP greeting: {greeting:?}"),
        ));
    }

    // Capabilities negotiation is required before any other command works.
    write_half
        .write_all(b"{\"execute\":\"qmp_capabilities\"}\n")
        .await?;
    let mut cap_response = String::new();
    if reader.read_line(&mut cap_response).await? == 0 {
        return Err(std::io::Error::new(
            ErrorKind::UnexpectedEof,
            "connection closed before qmp_capabilities response",
        ));
    }
    if let Some(err) = serde_json::from_str::<Value>(&cap_response)
        .ok()
        .and_then(|v| v.get("error").cloned())
    {
        return Err(std::io::Error::new(
            ErrorKind::InvalidData,
            format!("qmp_capabilities rejected: {err}"),
        ));
    }

    Ok((reader, write_half))
}

// ZYVOR_RUNTIME_BOUNDARY_V1: QEMU owns migration mechanics; Fabric owns placement/orchestration.
fn migration_phase(raw: &str) -> MigrationPhase {
    match raw {
        "none" => MigrationPhase::None,
        "setup" => MigrationPhase::Setup,
        "active" => MigrationPhase::Active,
        "postcopy-active" | "postcopy-paused" | "postcopy-recover" => {
            MigrationPhase::PostcopyActive
        }
        "completed" => MigrationPhase::Completed,
        "failed" => MigrationPhase::Failed,
        "cancelled" | "cancelling" => MigrationPhase::Cancelled,
        _ => MigrationPhase::Unknown,
    }
}

fn parse_migration_status(v: &Value) -> MigrationStatus {
    let status = v
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let ram = v.get("ram");
    MigrationStatus {
        phase: migration_phase(&status),
        status,
        ram_transferred: ram
            .and_then(|r| r.get("transferred"))
            .and_then(Value::as_u64),
        ram_remaining: ram.and_then(|r| r.get("remaining")).and_then(Value::as_u64),
        ram_total: ram.and_then(|r| r.get("total")).and_then(Value::as_u64),
        total_time_ms: v.get("total-time").and_then(Value::as_u64),
        downtime_ms: v.get("downtime").and_then(Value::as_u64),
        error: v
            .get("error-desc")
            .and_then(Value::as_str)
            .map(str::to_string),
    }
}

pub async fn migration_status(socket: &Path, timeout: Duration) -> Result<MigrationStatus> {
    let value = execute(socket, "query-migrate", None, timeout).await?;
    Ok(parse_migration_status(&value))
}

pub async fn migration_start(
    socket: &Path,
    request: &MigrationStartRequest,
    timeout: Duration,
) -> Result<MigrationStatus> {
    validate_migration_transport(&request.destination)?;

    if request.multifd_channels == Some(0) {
        bail!("multifd_channels must be >= 1 when set");
    }

    let mut capabilities = Vec::new();
    if request.multifd_channels.unwrap_or(1) > 1 {
        capabilities.push(json!({"capability": "multifd", "state": true}));
    }
    if request.mode == MigrationMode::PostCopy {
        capabilities.push(json!({"capability": "postcopy-ram", "state": true}));
    }
    if !capabilities.is_empty() {
        execute(
            socket,
            "migrate-set-capabilities",
            Some(json!({"capabilities": capabilities})),
            timeout,
        )
        .await?;
    }

    let mut params = serde_json::Map::new();
    if let Some(mbps) = request.bandwidth_mbps {
        // QEMU max-bandwidth is bytes/second. Decimal Mbps is the operator-facing unit.
        params.insert(
            "max-bandwidth".into(),
            Value::from(mbps.saturating_mul(1_000_000) / 8),
        );
    }
    if let Some(ms) = request.max_downtime_ms {
        params.insert("downtime-limit".into(), Value::from(ms));
    }
    if let Some(channels) = request.multifd_channels.filter(|c| *c > 1) {
        params.insert("multifd-channels".into(), Value::from(channels));
    }
    if !params.is_empty() {
        execute(
            socket,
            "migrate-set-parameters",
            Some(Value::Object(params)),
            timeout,
        )
        .await?;
    }

    execute(
        socket,
        "migrate",
        Some(json!({"uri": request.destination})),
        timeout,
    )
    .await?;

    if request.mode == MigrationMode::PostCopy {
        // QEMU only accepts migrate-start-postcopy once pre-copy has entered
        // active state. Keep this short: the API call is orchestration setup,
        // not the long-running migration wait loop (Fabric polls status).
        for _ in 0..50 {
            let status = migration_status(socket, timeout).await?;
            match status.phase {
                MigrationPhase::Active => {
                    execute(socket, "migrate-start-postcopy", None, timeout).await?;
                    break;
                }
                MigrationPhase::Completed => return Ok(status),
                MigrationPhase::Failed | MigrationPhase::Cancelled => {
                    bail!(
                        "migration became terminal before post-copy start: {}{}",
                        status.status,
                        status
                            .error
                            .as_deref()
                            .map(|e| format!(": {e}"))
                            .unwrap_or_default()
                    );
                }
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    migration_status(socket, timeout).await
}

pub async fn migration_cancel(socket: &Path, timeout: Duration) -> Result<MigrationStatus> {
    execute(socket, "migrate_cancel", None, timeout).await?;
    migration_status(socket, timeout).await
}

/// Hot-add `add_vcpus` vCPUs into unrealized `query-hotpluggable-cpus`
/// slots (the ones reserved via `-smp maxcpus=` at launch — see
/// `fluxvm-qemu`'s `build_args`). Returns the realized vCPU count after
/// adding. Slot order is sorted by `(socket-id, core-id, thread-id)` so
/// repeated calls fill sockets/cores deterministically rather than in
/// whatever order QEMU happens to report them.
pub async fn hotplug_cpu(socket: &Path, add_vcpus: u8, timeout: Duration) -> Result<u8> {
    if add_vcpus == 0 {
        bail!("add_vcpus must be >= 1");
    }
    let entries = query_hotpluggable_cpus(socket, timeout).await?;
    let realized_before = entries
        .iter()
        .filter(|e| e.get("qom-path").is_some())
        .count();
    let mut free: Vec<&Value> = entries
        .iter()
        .filter(|e| e.get("qom-path").is_none())
        .collect();
    if free.len() < add_vcpus as usize {
        bail!(
            "not enough hotplug headroom: {} free vCPU slot(s), requested {add_vcpus} -- increase max_vcpus at creation",
            free.len()
        );
    }
    free.sort_by_key(|e| {
        let props = e.get("props");
        let at = |k: &str| {
            props
                .and_then(|p| p.get(k))
                .and_then(Value::as_i64)
                .unwrap_or(0)
        };
        (at("socket-id"), at("core-id"), at("thread-id"))
    });
    for (i, slot) in free.iter().take(add_vcpus as usize).enumerate() {
        let driver = slot
            .get("type")
            .and_then(Value::as_str)
            .context("query-hotpluggable-cpus entry missing 'type'")?;
        let mut args = slot.get("props").cloned().unwrap_or_else(|| json!({}));
        let obj = args
            .as_object_mut()
            .context("query-hotpluggable-cpus entry 'props' was not an object")?;
        obj.insert("driver".into(), Value::from(driver));
        obj.insert(
            "id".into(),
            Value::from(format!("cpu-hotplug-{}", realized_before + i)),
        );
        execute(socket, "device_add", Some(args), timeout)
            .await
            .with_context(|| format!("device_add for vCPU slot {i}"))?;
    }
    let after = query_hotpluggable_cpus(socket, timeout).await?;
    Ok(after.iter().filter(|e| e.get("qom-path").is_some()).count() as u8)
}

async fn query_hotpluggable_cpus(socket: &Path, timeout: Duration) -> Result<Vec<Value>> {
    let value = execute(socket, "query-hotpluggable-cpus", None, timeout).await?;
    value
        .as_array()
        .cloned()
        .context("query-hotpluggable-cpus did not return an array")
}

/// Hot-add `add_memory_mib` MiB of RAM as a `pc-dimm` backed by a fresh
/// `memory-backend-ram` object (the DIMM slots reserved via `-m slots=` at
/// launch). Returns the total MiB now provided by every hot-added DIMM
/// (the caller adds the VM's original boot-time memory_mib on top for a
/// full live total — this function has no way to know that figure itself).
pub async fn hotplug_memory(socket: &Path, add_memory_mib: u64, timeout: Duration) -> Result<u64> {
    if add_memory_mib == 0 {
        bail!("add_memory_mib must be >= 1");
    }
    let existing = query_memory_devices(socket, timeout).await?;
    let next_index = existing.len();
    let mem_id = format!("mem-hotplug-{next_index}");
    let dimm_id = format!("dimm-hotplug-{next_index}");
    let bytes = add_memory_mib.saturating_mul(1024 * 1024);

    // object-add's properties are flattened at the top level, unlike
    // device_add's props-merged-into-args shape used for CPU hotplug above
    // -- confirmed live: a nested "props": {"size": ...} is rejected with
    // "Parameter 'size' is missing".
    execute(
        socket,
        "object-add",
        Some(json!({"qom-type": "memory-backend-ram", "id": mem_id, "size": bytes})),
        timeout,
    )
    .await
    .context("object-add memory-backend-ram")?;

    if let Err(e) = execute(
        socket,
        "device_add",
        Some(json!({"driver": "pc-dimm", "id": dimm_id, "memdev": mem_id})),
        timeout,
    )
    .await
    {
        // Don't leave an orphaned backend object occupying address space
        // behind a DIMM that never actually attached.
        let _ = execute(socket, "object-del", Some(json!({"id": mem_id})), timeout).await;
        return Err(e).context("device_add pc-dimm");
    }

    let after = query_memory_devices(socket, timeout).await?;
    Ok(sum_memory_devices_mib(&after))
}

/// Attach an existing host TAP as a new virtio-net-pci device on
/// `hotplug-pcie-{index}`. The TAP must already be up and enslaved to the
/// guest's bridge; this function only talks QMP.
pub async fn hotplug_nic(
    socket: &Path,
    tap: &str,
    mac: Option<&str>,
    index: u8,
    timeout: Duration,
) -> Result<()> {
    let net_id = format!("net{index}");
    let nic_id = format!("nic{index}");
    execute(
        socket,
        "netdev_add",
        Some(json!({
            "type": "tap",
            "id": net_id,
            "ifname": tap,
            "script": "no",
            "downscript": "no"
        })),
        timeout,
    )
    .await
    .context("netdev_add tap")?;
    let mut args = json!({
        "driver": "virtio-net-pci",
        "id": nic_id,
        "netdev": net_id,
        "bus": format!("hotplug-pcie-{index}")
    });
    if let Some(mac) = mac {
        args.as_object_mut()
            .unwrap()
            .insert("mac".into(), Value::from(mac));
    }
    if let Err(e) = execute(socket, "device_add", Some(args), timeout).await {
        let _ = execute(socket, "netdev_del", Some(json!({"id": net_id})), timeout).await;
        return Err(e).context("device_add virtio-net-pci");
    }
    Ok(())
}

/// One command of a [`execute_session`]. `fd` is attached to that command's request as
/// `SCM_RIGHTS` ancillary data (what QMP's `getfd` requires).
pub struct Step {
    pub command: String,
    pub args: Option<Value>,
    pub fd: Option<std::os::fd::RawFd>,
}

impl Step {
    pub fn new(command: &str, args: Option<Value>) -> Self {
        Self {
            command: command.into(),
            args,
            fd: None,
        }
    }

    pub fn with_fd(mut self, fd: std::os::fd::RawFd) -> Self {
        self.fd = Some(fd);
        self
    }
}

/// Runs `steps` in order on ONE QMP connection and returns each command's `return` value.
///
/// A session (not the per-command connections everything else here uses) is required whenever a
/// command names a descriptor received earlier: QEMU keeps `getfd` descriptors on the *monitor*
/// they arrived on, and `netdev_add ... fd=<name>` resolves the name through the monitor that is
/// executing it. Runs on a blocking thread because passing a descriptor is a `sendmsg`.
pub async fn execute_session(
    socket: &Path,
    steps: Vec<Step>,
    timeout: Duration,
) -> Result<Vec<Value>> {
    let socket = socket.to_path_buf();
    tokio::task::spawn_blocking(move || session_blocking(&socket, steps, timeout))
        .await
        .context("joining QMP session task")?
}

/// `sendmsg` of `data` with `fd` attached as `SCM_RIGHTS` (the descriptor travels with the first byte).
fn send_with_fd(
    sock: std::os::fd::RawFd,
    data: &[u8],
    fd: std::os::fd::RawFd,
) -> std::io::Result<()> {
    let mut iov = libc::iovec {
        iov_base: data.as_ptr() as *mut libc::c_void,
        iov_len: data.len(),
    };
    // SAFETY: CMSG_SPACE is a pure size computation.
    let space =
        unsafe { libc::CMSG_SPACE(std::mem::size_of::<std::os::fd::RawFd>() as u32) } as usize;
    let mut control = vec![0u8; space];
    // SAFETY: an all-zero msghdr is a valid initial value for this plain C struct.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = space as _;
    // SAFETY: `control` is CMSG_SPACE bytes, so CMSG_FIRSTHDR points inside it and the CMSG_LEN /
    // CMSG_DATA writes below stay in bounds; `msg` and the buffers outlive the sendmsg call.
    let sent = unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<std::os::fd::RawFd>() as u32) as _;
        std::ptr::copy_nonoverlapping(
            &fd as *const _ as *const u8,
            libc::CMSG_DATA(cmsg),
            std::mem::size_of::<std::os::fd::RawFd>(),
        );
        libc::sendmsg(sock, &msg, 0)
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // The descriptor travelled with the first byte; anything sendmsg did not take is plain data.
    let mut off = sent as usize;
    while off < data.len() {
        // SAFETY: `data[off..]` is a valid readable range for the given length.
        let n = unsafe {
            libc::write(
                sock,
                data[off..].as_ptr() as *const libc::c_void,
                data.len() - off,
            )
        };
        if n < 0 {
            return Err(std::io::Error::last_os_error());
        }
        off += n as usize;
    }
    Ok(())
}

fn session_blocking(socket: &Path, steps: Vec<Step>, timeout: Duration) -> Result<Vec<Value>> {
    use std::io::{BufRead, BufReader as StdBufReader, Write};
    use std::os::fd::AsRawFd;
    let stream = std::os::unix::net::UnixStream::connect(socket)
        .with_context(|| format!("connecting to QMP socket {}", socket.display()))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut writer = stream.try_clone()?;
    let mut reader = StdBufReader::new(stream);

    let mut line = String::new();
    if reader
        .read_line(&mut line)
        .context("reading QMP greeting")?
        == 0
        || serde_json::from_str::<Value>(&line)
            .ok()
            .and_then(|v| v.get("QMP").cloned())
            .is_none()
    {
        bail!("unexpected QMP greeting: {line:?}");
    }
    writer.write_all(b"{\"execute\":\"qmp_capabilities\"}\n")?;
    line.clear();
    if reader
        .read_line(&mut line)
        .context("reading qmp_capabilities reply")?
        == 0
    {
        bail!("QMP connection closed before the qmp_capabilities reply");
    }
    if let Some(err) = serde_json::from_str::<Value>(&line)
        .ok()
        .and_then(|v| v.get("error").cloned())
    {
        bail!("qmp_capabilities rejected: {err}");
    }

    let mut returns = Vec::with_capacity(steps.len());
    for step in steps {
        let mut request = json!({"execute": step.command});
        if let Some(args) = step.args {
            request["arguments"] = args;
        }
        let bytes = format!("{request}\n");
        match step.fd {
            Some(fd) => {
                send_with_fd(writer.as_raw_fd(), bytes.as_bytes(), fd).with_context(|| {
                    format!("sending QMP command {} with a descriptor", step.command)
                })?
            }
            None => writer
                .write_all(bytes.as_bytes())
                .with_context(|| format!("sending QMP command {}", step.command))?,
        }
        loop {
            line.clear();
            if reader
                .read_line(&mut line)
                .context("reading QMP response")?
                == 0
            {
                bail!(
                    "QEMU closed the QMP connection without responding to {}",
                    step.command
                );
            }
            let response: Value = serde_json::from_str(&line)
                .with_context(|| format!("parsing QMP response: {line}"))?;
            if response.get("event").is_some() {
                continue;
            }
            if let Some(err) = response.get("error") {
                bail!("QMP {} failed: {err}", step.command);
            }
            returns.push(response.get("return").cloned().unwrap_or(Value::Null));
            break;
        }
    }
    Ok(returns)
}

/// Like [`hotplug_nic`], for a TAP the daemon already opened (it lives in another network
/// namespace, so QEMU cannot open it by name): the descriptor is passed with `getfd` and the
/// `netdev` references it by name. The caller keeps ownership of its own copy of `tap_fd`.
pub async fn hotplug_nic_fd(
    socket: &Path,
    tap_fd: std::os::fd::RawFd,
    mac: Option<&str>,
    index: u8,
    timeout: Duration,
) -> Result<()> {
    let net_id = format!("net{index}");
    let nic_id = format!("nic{index}");
    let fd_name = format!("fluxvm-tap{index}");
    let mut device = json!({
        "driver": "virtio-net-pci",
        "id": nic_id,
        "netdev": net_id,
        "bus": format!("hotplug-pcie-{index}")
    });
    if let Some(mac) = mac {
        device["mac"] = Value::from(mac);
    }
    let steps = vec![
        Step::new("getfd", Some(json!({"fdname": fd_name}))).with_fd(tap_fd),
        Step::new(
            "netdev_add",
            Some(json!({"type": "tap", "id": net_id, "fd": fd_name})),
        ),
        Step::new("device_add", Some(device)),
    ];
    if let Err(e) = execute_session(socket, steps, timeout).await {
        // If netdev_add succeeded before device_add failed, remove it; harmless when it never existed.
        let _ = execute(socket, "netdev_del", Some(json!({"id": net_id})), timeout).await;
        return Err(e).context("hot-adding a NIC on a passed tap descriptor");
    }
    Ok(())
}

/// Hot-add a `vhost-user-fs-pci` device on `hotplug-pcie-{port}` for a `virtiofsd` that is already
/// listening on `virtiofs_socket`. The VM must have shareable guest memory (see `shared_memory`).
/// Two commands (`chardev-add`, `device_add`); a failed `device_add` removes the chardev again.
pub async fn hotplug_virtiofs(
    socket: &Path,
    index: usize,
    virtiofs_socket: &Path,
    tag: &str,
    port: u8,
    timeout: Duration,
) -> Result<()> {
    let chardev = format!("vfsock{index}");
    let steps = vec![
        Step::new(
            "chardev-add",
            Some(json!({
                "id": chardev,
                "backend": {"type": "socket", "data": {
                    "addr": {"type": "unix", "data": {"path": virtiofs_socket.to_string_lossy()}},
                    "server": false
                }}
            })),
        ),
        Step::new(
            "device_add",
            Some(json!({
                "driver": "vhost-user-fs-pci",
                "id": format!("fsdev{index}"),
                "chardev": chardev,
                "tag": tag,
                "queue-size": 1024,
                "bus": format!("hotplug-pcie-{port}")
            })),
        ),
    ];
    if let Err(e) = execute_session(socket, steps, timeout).await {
        // Harmless when the chardev never existed.
        let _ = execute(
            socket,
            "chardev-remove",
            Some(json!({"id": chardev})),
            timeout,
        )
        .await;
        return Err(e).context("hot-adding a virtiofs share");
    }
    Ok(())
}

async fn query_memory_devices(socket: &Path, timeout: Duration) -> Result<Vec<Value>> {
    let value = execute(socket, "query-memory-devices", None, timeout).await?;
    value
        .as_array()
        .cloned()
        .context("query-memory-devices did not return an array")
}

fn sum_memory_devices_mib(devices: &[Value]) -> u64 {
    devices
        .iter()
        .filter_map(|d| d.get("data")?.get("size")?.as_u64())
        .sum::<u64>()
        / (1024 * 1024)
}

/// Save VM state to an internal snapshot tagged `name` on the VM's disk
/// (pairs with QEMU `-loadvm` / `start_from_snapshot`).
pub async fn savevm(socket: &Path, name: &str, timeout: Duration) -> Result<Value> {
    execute(
        socket,
        "human-monitor-command",
        Some(json!({"command-line": format!("savevm {name}")})),
        timeout,
    )
    .await
}

/// Alias for callers that prefer snapshot-oriented naming.
pub async fn snapshot_create(socket: &Path, name: &str, timeout: Duration) -> Result<Value> {
    savevm(socket, name, timeout).await
}

async fn execute_inner(socket: &Path, command: &str, args: Option<Value>) -> Result<Value> {
    let (mut reader, mut write_half) = handshake_retrying(socket).await?;

    let mut request = json!({"execute": command});
    if let Some(args) = args {
        request["arguments"] = args;
    }
    write_half
        .write_all(format!("{request}\n").as_bytes())
        .await
        .with_context(|| format!("sending QMP command {command}"))?;

    // QEMU may interleave asynchronous "event" lines before the command's
    // own reply; skip those rather than treating the first line as the
    // answer (the draft's real gap: it discarded events in an unbounded
    // loop with no cap — here the outer `timeout` in `execute` is the cap).
    loop {
        let mut line = String::new();
        if reader
            .read_line(&mut line)
            .await
            .context("reading QMP response")?
            == 0
        {
            bail!("QEMU closed the QMP connection without responding to {command}");
        }
        let response: Value =
            serde_json::from_str(&line).with_context(|| format!("parsing QMP response: {line}"))?;
        if response.get("event").is_some() {
            continue;
        }
        if let Some(err) = response.get("error") {
            bail!("QMP {command} failed: {err}");
        }
        return Ok(response.get("return").cloned().unwrap_or(Value::Null));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::net::UnixListener;

    async fn serve_one_command(listener: UnixListener, command: &'static str) {
        let (stream, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = stream.into_split();
        let mut reader = BufReader::new(read_half);

        write_half
            .write_all(b"{\"QMP\":{\"version\":{}}}\n")
            .await
            .unwrap();
        let mut caps = String::new();
        reader.read_line(&mut caps).await.unwrap();
        write_half.write_all(b"{\"return\":{}}\n").await.unwrap();

        let mut req = String::new();
        reader.read_line(&mut req).await.unwrap();
        let req: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(req["execute"], command);
        write_half
            .write_all(b"{\"return\":{\"status\":\"ok\"}}\n")
            .await
            .unwrap();

        // Keep the connection open briefly so the client's read isn't racing
        // a closed socket; then just let it drop.
        let mut buf = [0u8; 1];
        let _ = tokio::time::timeout(Duration::from_millis(50), reader.read(&mut buf)).await;
    }

    #[tokio::test]
    async fn succeeds_immediately_when_the_socket_already_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(serve_one_command(listener, "stop"));

        let result = execute(&path, "stop", None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result["status"], "ok");
        server.await.unwrap();
    }

    /// Regression test: the real bug was that `create()` returns as soon as
    /// QEMU is spawned (`-qmp ...,wait=off`), before QEMU has necessarily
    /// created the QMP socket file at all — a caller pausing immediately
    /// afterward (a warm pool's backfill loop, with no delay in between)
    /// hit "connecting to QMP socket: No such file or directory" on real
    /// hardware. This simulates that exact window: the socket file doesn't
    /// exist yet when `execute` is first called.
    #[tokio::test]
    async fn retries_the_connect_until_the_socket_appears() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        // Deliberately do NOT bind yet — execute() must retry past ENOENT.
        let path_for_server = path.clone();
        let server = tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(150)).await;
            let listener = UnixListener::bind(&path_for_server).unwrap();
            serve_one_command(listener, "cont").await;
        });

        let result = execute(&path, "cont", None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result["status"], "ok");
        server.await.unwrap();
    }

    /// Regression test for a second, later-stage instance of the same real
    /// bug: on real hardware, even after the connect-retry fix above, a
    /// warm pool's create-then-immediately-pause sequence still failed —
    /// this time the connection was accepted and the greeting arrived, but
    /// QEMU reset the connection while still negotiating capabilities
    /// (device model not fully up yet). Simulates a listener that resets
    /// the first connection mid-handshake and only completes a real
    /// handshake on the second — `execute` must retry the *whole* thing,
    /// not just the connect.
    #[tokio::test]
    async fn retries_the_whole_handshake_after_a_mid_handshake_reset() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = tokio::spawn(async move {
            // First connection: send the greeting, then drop without ever
            // answering qmp_capabilities — the client sees EOF/reset mid-handshake.
            let (stream, _) = listener.accept().await.unwrap();
            let (_read_half, mut write_half) = stream.into_split();
            write_half
                .write_all(b"{\"QMP\":{\"version\":{}}}\n")
                .await
                .unwrap();
            drop(write_half);

            // Second connection: a normal, complete handshake + command.
            serve_one_command(listener, "stop").await;
        });

        let result = execute(&path, "stop", None, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(result["status"], "ok");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn gives_up_once_the_overall_timeout_elapses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock"); // never created
        let err = execute(&path, "stop", None, Duration::from_millis(150))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("timed out"),
            "unexpected error: {err:#}"
        );
    }
}

#[cfg(test)]
mod migration_contract_tests {
    use super::*;

    #[test]
    fn parses_qemu_migration_progress() {
        let status = parse_migration_status(&json!({
            "status": "active",
            "ram": {"transferred": 75, "remaining": 25, "total": 100},
            "total-time": 456,
            "downtime": 7
        }));
        assert_eq!(status.phase, MigrationPhase::Active);
        assert_eq!(status.ram_transferred, Some(75));
        assert_eq!(status.ram_remaining, Some(25));
        assert_eq!(status.ram_total, Some(100));
        assert_eq!(status.total_time_ms, Some(456));
        assert_eq!(status.downtime_ms, Some(7));
    }

    #[test]
    fn rejects_shell_backed_migration_uri() {
        assert!(validate_migration_transport("exec:ssh host nc 4444").is_err());
        assert!(validate_migration_transport("tcp:10.0.0.4:4444").is_ok());
        assert!(validate_migration_transport("unix:/run/fluxvm/incoming.sock").is_ok());
    }

    #[test]
    fn maps_postcopy_states() {
        for state in ["postcopy-active", "postcopy-paused", "postcopy-recover"] {
            assert_eq!(migration_phase(state), MigrationPhase::PostcopyActive);
        }
    }
}

#[cfg(test)]
mod hotplug_tests {
    use super::*;
    use tokio::net::UnixListener;

    /// `execute()` opens a fresh connection per command (see the module
    /// doc), so a scripted multi-command exchange needs one accepted
    /// connection per step -- this serves `steps` in order, each on its own
    /// connection, asserting the expected command name and replying with
    /// the given canned `return` value.
    async fn serve_script(listener: UnixListener, steps: Vec<(&'static str, Value)>) {
        for (expect_command, reply) in steps {
            let (stream, _) = listener.accept().await.unwrap();
            let (read_half, mut write_half) = stream.into_split();
            let mut reader = BufReader::new(read_half);

            write_half
                .write_all(b"{\"QMP\":{\"version\":{}}}\n")
                .await
                .unwrap();
            let mut caps = String::new();
            reader.read_line(&mut caps).await.unwrap();
            write_half.write_all(b"{\"return\":{}}\n").await.unwrap();

            let mut req = String::new();
            reader.read_line(&mut req).await.unwrap();
            let req: Value = serde_json::from_str(&req).unwrap();
            assert_eq!(req["execute"], expect_command, "unexpected command");

            let resp = json!({"return": reply});
            write_half
                .write_all(format!("{resp}\n").as_bytes())
                .await
                .unwrap();
        }
    }

    fn cpu_slot(realized: bool, socket_id: i64, core_id: i64) -> Value {
        let mut v = json!({
            "type": "host-x86_64-cpu",
            "props": {"socket-id": socket_id, "core-id": core_id, "thread-id": 0},
        });
        if realized {
            v["qom-path"] = Value::from(format!("/machine/peripheral/cpu-{socket_id}-{core_id}"));
        }
        v
    }

    #[tokio::test]
    async fn hotplug_cpu_fills_free_slots_in_socket_core_order() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();

        // 1 realized (socket 0) + 3 free slots listed out of order
        // (sockets 2,1,3); requesting 2 must fill sockets 1 then 2 -- the
        // two lowest -- not whatever order they were reported in.
        let before = vec![
            cpu_slot(true, 0, 0),
            cpu_slot(false, 2, 0),
            cpu_slot(false, 1, 0),
            cpu_slot(false, 3, 0),
        ];
        let after = vec![
            cpu_slot(true, 0, 0),
            cpu_slot(true, 2, 0),
            cpu_slot(true, 1, 0),
            cpu_slot(false, 3, 0),
        ];

        let server = tokio::spawn(async move {
            for step in 0..4 {
                let (stream, _) = listener.accept().await.unwrap();
                let (read_half, mut write_half) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                write_half
                    .write_all(b"{\"QMP\":{\"version\":{}}}\n")
                    .await
                    .unwrap();
                let mut caps = String::new();
                reader.read_line(&mut caps).await.unwrap();
                write_half.write_all(b"{\"return\":{}}\n").await.unwrap();

                let mut req = String::new();
                reader.read_line(&mut req).await.unwrap();
                let req: Value = serde_json::from_str(&req).unwrap();
                match step {
                    0 => {
                        assert_eq!(req["execute"], "query-hotpluggable-cpus");
                        let resp = json!({"return": before});
                        write_half
                            .write_all(format!("{resp}\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    1 => {
                        assert_eq!(req["execute"], "device_add");
                        assert_eq!(
                            req["arguments"]["socket-id"], 1,
                            "must fill socket 1 before socket 2"
                        );
                        write_half.write_all(b"{\"return\":{}}\n").await.unwrap();
                    }
                    2 => {
                        assert_eq!(req["execute"], "device_add");
                        assert_eq!(req["arguments"]["socket-id"], 2);
                        write_half.write_all(b"{\"return\":{}}\n").await.unwrap();
                    }
                    3 => {
                        assert_eq!(req["execute"], "query-hotpluggable-cpus");
                        let resp = json!({"return": after});
                        write_half
                            .write_all(format!("{resp}\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
            }
        });

        let realized = hotplug_cpu(&path, 2, Duration::from_secs(5)).await.unwrap();
        assert_eq!(realized, 3);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn hotplug_cpu_rejects_more_than_available_headroom() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let steps = vec![(
            "query-hotpluggable-cpus",
            Value::Array(vec![cpu_slot(true, 0, 0), cpu_slot(false, 1, 0)]),
        )];
        let server = tokio::spawn(serve_script(listener, steps));

        let err = hotplug_cpu(&path, 5, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("not enough hotplug headroom"),
            "unexpected error: {err:#}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn hotplug_cpu_rejects_zero() {
        let path = std::path::PathBuf::from("/nonexistent/qmp.sock");
        let err = hotplug_cpu(&path, 0, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("add_vcpus must be >= 1"));
    }

    #[tokio::test]
    async fn hotplug_memory_adds_a_dimm_and_reports_new_total() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();

        // Real QEMU rejects a nested `"props": {"size": ...}` on object-add
        // ("Parameter 'size' is missing") -- confirmed live against a real
        // VM. This server asserts the flattened shape so that regression
        // can't creep back in silently the way it did the first time.
        let server = tokio::spawn(async move {
            for step in 0..4 {
                let (stream, _) = listener.accept().await.unwrap();
                let (read_half, mut write_half) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                write_half
                    .write_all(b"{\"QMP\":{\"version\":{}}}\n")
                    .await
                    .unwrap();
                let mut caps = String::new();
                reader.read_line(&mut caps).await.unwrap();
                write_half.write_all(b"{\"return\":{}}\n").await.unwrap();

                let mut req = String::new();
                reader.read_line(&mut req).await.unwrap();
                let req: Value = serde_json::from_str(&req).unwrap();
                match step {
                    0 => {
                        assert_eq!(req["execute"], "query-memory-devices");
                        write_half.write_all(b"{\"return\":[]}\n").await.unwrap();
                    }
                    1 => {
                        assert_eq!(req["execute"], "object-add");
                        assert_eq!(req["arguments"]["qom-type"], "memory-backend-ram");
                        assert_eq!(
                            req["arguments"]["size"], 1073741824u64,
                            "size must be a flattened top-level argument, not nested under props"
                        );
                        assert!(
                            req["arguments"].get("props").is_none(),
                            "object-add must not nest properties under 'props'"
                        );
                        write_half.write_all(b"{\"return\":{}}\n").await.unwrap();
                    }
                    2 => {
                        assert_eq!(req["execute"], "device_add");
                        assert_eq!(req["arguments"]["driver"], "pc-dimm");
                        write_half.write_all(b"{\"return\":{}}\n").await.unwrap();
                    }
                    3 => {
                        assert_eq!(req["execute"], "query-memory-devices");
                        let resp =
                            json!({"return": [{"type": "dimm", "data": {"size": 1073741824u64}}]});
                        write_half
                            .write_all(format!("{resp}\n").as_bytes())
                            .await
                            .unwrap();
                    }
                    _ => unreachable!(),
                }
            }
        });

        let total_mib = hotplug_memory(&path, 1024, Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(total_mib, 1024);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn hotplug_memory_rolls_back_backend_object_on_device_add_failure() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("qmp.sock");
        let listener = UnixListener::bind(&path).unwrap();

        // Serve: query (empty) -> object-add ok -> device_add ERRORS -> object-del (rollback).
        let server = tokio::spawn(async move {
            for step in 0..4 {
                let (stream, _) = listener.accept().await.unwrap();
                let (read_half, mut write_half) = stream.into_split();
                let mut reader = BufReader::new(read_half);
                write_half
                    .write_all(b"{\"QMP\":{\"version\":{}}}\n")
                    .await
                    .unwrap();
                let mut caps = String::new();
                reader.read_line(&mut caps).await.unwrap();
                write_half.write_all(b"{\"return\":{}}\n").await.unwrap();

                let mut req = String::new();
                reader.read_line(&mut req).await.unwrap();
                let req: Value = serde_json::from_str(&req).unwrap();
                match step {
                    0 => {
                        assert_eq!(req["execute"], "query-memory-devices");
                        write_half.write_all(b"{\"return\":[]}\n").await.unwrap();
                    }
                    1 => {
                        assert_eq!(req["execute"], "object-add");
                        write_half.write_all(b"{\"return\":{}}\n").await.unwrap();
                    }
                    2 => {
                        assert_eq!(req["execute"], "device_add");
                        write_half
                            .write_all(b"{\"error\":{\"desc\":\"no slots where allocated\"}}\n")
                            .await
                            .unwrap();
                    }
                    3 => {
                        assert_eq!(req["execute"], "object-del");
                        write_half.write_all(b"{\"return\":{}}\n").await.unwrap();
                    }
                    _ => unreachable!(),
                }
            }
        });

        let err = hotplug_memory(&path, 1024, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("device_add pc-dimm"));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn hotplug_memory_rejects_zero() {
        let path = std::path::PathBuf::from("/nonexistent/qmp.sock");
        let err = hotplug_memory(&path, 0, Duration::from_secs(1))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("add_memory_mib must be >= 1"));
    }
}

#[cfg(test)]
mod fd_session_tests {
    use super::*;
    use std::io::{BufRead, BufReader as StdBufReader, Write};
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixListener as StdListener;

    /// (command, arguments, descriptor received with that request's bytes)
    type Seen = (String, Value, Option<(u64, u64)>);

    /// `recvmsg` one QMP line and any SCM_RIGHTS descriptor; returns the line and the received
    /// descriptor's (dev, ino) so the test can prove it is the very file that was sent.
    fn recv_line(sock: &std::os::unix::net::UnixStream) -> (String, Option<(u64, u64)>) {
        let mut buf = vec![0u8; 4096];
        let mut iov = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<i32>() as u32) } as usize;
        let mut control = vec![0u8; space];
        let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        msg.msg_controllen = space as _;
        let n = unsafe { libc::recvmsg(sock.as_raw_fd(), &mut msg, 0) };
        assert!(n > 0, "recvmsg failed");
        let mut ident = None;
        unsafe {
            let c = libc::CMSG_FIRSTHDR(&msg);
            if !c.is_null()
                && (*c).cmsg_level == libc::SOL_SOCKET
                && (*c).cmsg_type == libc::SCM_RIGHTS
            {
                let mut fd: i32 = -1;
                std::ptr::copy_nonoverlapping(libc::CMSG_DATA(c), &mut fd as *mut _ as *mut u8, 4);
                let mut st: libc::stat = std::mem::zeroed();
                assert_eq!(libc::fstat(fd, &mut st), 0);
                ident = Some((st.st_dev as u64, st.st_ino as u64));
                libc::close(fd);
            }
        }
        buf.truncate(n as usize);
        (String::from_utf8_lossy(&buf).trim().to_string(), ident)
    }

    /// A QMP server that records every command; `fail` makes `device_add` return an error.
    fn serve(listener: StdListener, fail: bool) -> std::thread::JoinHandle<Vec<Seen>> {
        std::thread::spawn(move || {
            let mut all = Vec::new();
            // The session, then (on failure) the separate netdev_del connection.
            for _ in 0..if fail { 2 } else { 1 } {
                let (stream, _) = listener.accept().unwrap();
                let mut w = stream.try_clone().unwrap();
                w.write_all(b"{\"QMP\":{\"version\":{}}}\n").unwrap();
                let mut r = StdBufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                r.read_line(&mut line).unwrap(); // qmp_capabilities
                w.write_all(b"{\"return\":{}}\n").unwrap();
                loop {
                    let (text, ident) = recv_line(&stream);
                    if text.is_empty() {
                        break;
                    }
                    let req: Value = serde_json::from_str(&text).unwrap();
                    let cmd = req["execute"].as_str().unwrap().to_string();
                    all.push((cmd.clone(), req["arguments"].clone(), ident));
                    let reply = if fail && cmd == "device_add" {
                        "{\"error\":{\"class\":\"GenericError\",\"desc\":\"no free slot\"}}\n"
                    } else {
                        "{\"return\":{}}\n"
                    };
                    w.write_all(reply.as_bytes()).unwrap();
                    if cmd == "device_add" || cmd == "netdev_del" {
                        break;
                    }
                }
            }
            all
        })
    }

    fn ident_of(f: &std::fs::File) -> (u64, u64) {
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::fstat(f.as_raw_fd(), &mut st) }, 0);
        (st.st_dev as u64, st.st_ino as u64)
    }

    #[tokio::test]
    async fn getfd_carries_the_descriptor_and_netdev_names_it_in_the_same_session() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("qmp.sock");
        let server = serve(StdListener::bind(&sock).unwrap(), false);
        let file = std::fs::File::open("/dev/null").unwrap(); // any fd; identity is what is checked

        hotplug_nic_fd(
            &sock,
            file.as_raw_fd(),
            Some("02:00:00:00:00:02"),
            0,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let seen = server.join().unwrap();
        let cmds: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(
            cmds,
            ["getfd", "netdev_add", "device_add"],
            "one ordered session"
        );
        assert_eq!(seen[0].1["fdname"], "fluxvm-tap0");
        assert_eq!(
            seen[0].2,
            Some(ident_of(&file)),
            "getfd must carry the very descriptor we sent"
        );
        assert!(
            seen[1].2.is_none() && seen[2].2.is_none(),
            "only getfd carries a descriptor"
        );
        assert_eq!(
            seen[1].1,
            json!({"type": "tap", "id": "net0", "fd": "fluxvm-tap0"})
        );
        assert_eq!(seen[2].1["driver"], "virtio-net-pci");
        assert_eq!(seen[2].1["netdev"], "net0");
        assert_eq!(seen[2].1["bus"], "hotplug-pcie-0");
        assert_eq!(seen[2].1["mac"], "02:00:00:00:00:02");
    }

    #[tokio::test]
    async fn virtiofs_hotplug_adds_the_chardev_then_the_device_in_one_session() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("qmp.sock");
        let server = serve(StdListener::bind(&sock).unwrap(), false);

        hotplug_virtiofs(
            &sock,
            2,
            Path::new("/run/fluxvm/vfs.sock"),
            "fs2",
            7,
            Duration::from_secs(5),
        )
        .await
        .unwrap();

        let seen = server.join().unwrap();
        let cmds: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(cmds, ["chardev-add", "device_add"]);
        assert_eq!(seen[0].1["id"], "vfsock2");
        assert_eq!(
            seen[0].1["backend"]["data"]["addr"]["data"]["path"],
            "/run/fluxvm/vfs.sock"
        );
        assert_eq!(seen[0].1["backend"]["data"]["server"], false);
        assert_eq!(seen[1].1["driver"], "vhost-user-fs-pci");
        assert_eq!(seen[1].1["chardev"], "vfsock2");
        assert_eq!(seen[1].1["tag"], "fs2");
        assert_eq!(seen[1].1["bus"], "hotplug-pcie-7");
    }

    #[tokio::test]
    async fn a_failed_device_add_removes_the_netdev_on_a_second_connection() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("qmp.sock");
        let server = serve(StdListener::bind(&sock).unwrap(), true);
        let file = std::fs::File::open("/dev/null").unwrap();

        let err = hotplug_nic_fd(&sock, file.as_raw_fd(), None, 1, Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(format!("{err:#}").contains("no free slot"), "{err:#}");

        let seen = server.join().unwrap();
        let cmds: Vec<&str> = seen.iter().map(|s| s.0.as_str()).collect();
        assert_eq!(cmds, ["getfd", "netdev_add", "device_add", "netdev_del"]);
        assert_eq!(seen[3].1, json!({"id": "net1"}));
        assert_eq!(
            seen[1].1["fd"], "fluxvm-tap1",
            "the port index is part of the names"
        );
    }

    #[tokio::test]
    async fn a_missing_socket_is_a_clear_error_not_a_hang() {
        let dir = tempfile::tempdir().unwrap();
        let err = hotplug_nic_fd(
            &dir.path().join("nope.sock"),
            0,
            None,
            0,
            Duration::from_secs(1),
        )
        .await
        .unwrap_err();
        assert!(
            format!("{err:#}").contains("connecting to QMP socket"),
            "{err:#}"
        );
    }
}
