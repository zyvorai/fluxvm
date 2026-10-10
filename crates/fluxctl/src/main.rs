// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

use anyhow::{Context, Result};
use base64::{Engine, engine::general_purpose::STANDARD as B64};
use clap::{ColorChoice, CommandFactory, FromArgMatches, Parser, Subcommand};
use fluxvm_api as api;
use fluxvm_core::{
    config::Config,
    model::{
        BackendKind, ClaimOverrides, CreateVmRequest, DirectMode, DirectSpec, MigrationMode,
        MigrationReceiverRequest, MigrationStartRequest, ResourcePatch,
    },
};
use fluxvm_guest_protocol::AgentResponse;
use fluxvm_image::{self as image, BuildImageRequest};
use fluxvm_scheduler::{SandboxCreateRequest, VmManager};
use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    sync::Arc,
};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;

mod compose;
mod contexts;
mod create;
mod fleet_client;
mod launch_agent;
mod mcp;
mod mcp_install;
mod output;
mod remote;
mod run;
mod sandbox_run;
mod stack;
mod stack_fleet;
mod status;
mod styles;

#[derive(Parser)]
#[command(
    name = "fluxctl",
    version,
    about = "CLI to install, manage, and troubleshoot FluxVM hosts",
    long_about = styles::LONG_ABOUT,
    help_template = styles::HELP_TEMPLATE,
    styles = styles::STYLES,
    arg_required_else_help = true,
    propagate_version = true,
)]
struct Cli {
    #[arg(long, env = "FLUXVM_CONFIG", help_heading = "Global Flags")]
    config: Option<PathBuf>,
    /// Output format for list-style commands (`list`, `list-images`,
    /// `snapshot-list`, `events`, `sandbox list`).
    #[arg(
        id = "output_format",
        short = 'o',
        long = "output-format",
        global = true,
        value_enum,
        default_value_t = output::OutputFormat::Json,
        env = "FLUXCTL_OUTPUT",
        help_heading = "Global Flags"
    )]
    output: output::OutputFormat,
    /// Drive a remote daemon over REST (e.g. `http://host:7788`) instead of
    /// the local state dir. Covers the core VM verbs.
    #[arg(long, env = "FLUXVM_URL", global = true, help_heading = "Global Flags")]
    server: Option<String>,
    /// Bearer token for `--server`.
    #[arg(
        long = "server-token",
        env = "FLUXVM_TOKEN",
        global = true,
        hide_env_values = true,
        help_heading = "Global Flags"
    )]
    server_token: Option<String>,
    /// Named remote from `fluxctl context add` (`local` forces local mode).
    /// Defaults to the current context, if one is set.
    #[arg(
        long,
        env = "FLUXCTL_CONTEXT",
        global = true,
        help_heading = "Global Flags"
    )]
    context: Option<String>,
    #[command(subcommand)]
    command: Command,
}

/// Run a stack on a node of a `fluxvm-agent central` fleet. The node's own API is then called with `--server-token`.
#[derive(clap::Args, Clone, Default)]
struct StackFleet {
    /// Base URL of the fleet registry, e.g. `http://fleet-registry:7799`.
    #[arg(long)]
    fleet: Option<String>,
    /// Bearer token of the fleet registry.
    #[arg(long, env = "FLUXVM_AGENT_TOKEN", hide_env_values = true)]
    fleet_token: Option<String>,
}

#[derive(Subcommand)]
enum ServiceCommand {
    /// Write ~/Library/LaunchAgents/dev.zyvor.fluxvm.plist (with the global --config, if given) and load it.
    Install,
    /// Unload and delete it.
    Uninstall,
    /// Whether it is installed and running.
    Status,
}

#[derive(Subcommand)]
enum McpCommand {
    /// Serve FluxVM tools over MCP stdio. Talks to the daemon over REST
    /// (`--server`/`FLUXVM_URL`, the current context, else `listen` from
    /// the config). Read tools only, unless `--allow-write`.
    Serve {
        /// Also offer tools that change state (VM power, packet capture).
        #[arg(long)]
        allow_write: bool,
    },
    /// Register `fluxctl mcp serve` with an MCP client (Claude Code, Cursor, Claude Desktop, Codex, VS Code,
    /// Windsurf, Gemini CLI) by editing its config file. `--server`, `--context` and `--config` are carried over.
    Install {
        #[arg(value_enum)]
        client: mcp_install::Client,
        /// Write the project's config in the current directory instead of the user-wide one.
        #[arg(long)]
        project: bool,
        /// Let the client use write tools (VM power, input, sign-in, snapshots).
        #[arg(long)]
        allow_write: bool,
        /// Also store `--server-token` in the config file (plain text).
        #[arg(long)]
        with_token: bool,
        /// Server name in the client's config.
        #[arg(long, default_value = "fluxvm")]
        name: String,
        /// Print the entry and the file it would go in without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove the entry added by `mcp install`.
    Uninstall {
        #[arg(value_enum)]
        client: mcp_install::Client,
        #[arg(long)]
        project: bool,
        #[arg(long, default_value = "fluxvm")]
        name: String,
    },
    /// Which clients have FluxVM configured.
    Status {
        #[arg(long)]
        project: bool,
        #[arg(long, default_value = "fluxvm")]
        name: String,
    },
}

#[derive(Subcommand)]
enum Command {
    #[command(next_help_heading = "Basic Commands")]
    /// Start the FluxVM control-plane daemon (REST API).
    Serve,
    /// Open the daemon's web dashboard (`/console`): VMs and containers by stack, power actions, logs. The page asks
    /// for the API token itself; it is never put in the URL.
    Dashboard {
        /// Only print the URL.
        #[arg(long)]
        no_open: bool,
    },
    /// Run `fluxctl serve` as a launchd LaunchAgent of the logged-in user (macOS): started at login, restarted if it
    /// exits.
    Service {
        #[command(subcommand)]
        command: ServiceCommand,
    },
    /// Display status. With no id: Cilium-style host panel. With an id:
    /// that VM's record (machinectl `status`/`show`).
    Status {
        /// Print host binary / kernel paths (host panel only).
        #[arg(long, short = 'v')]
        verbose: bool,
        /// VM id — when set, print that VM instead of the host panel.
        #[arg(value_parser = output::parse_vm_ref)]
        id: Option<Uuid>,
    },
    /// Daemon liveness probe. Hits `GET /healthz` on `listen` (no auth).
    Healthz,
    /// Daemon readiness probe. Hits `GET /readyz` on `listen` (no auth).
    Readyz,
    /// Prometheus text metrics from the running daemon (`GET /metrics`).
    Metrics {
        /// Bearer token when `auth.require` is on (also `FLUXVM_TOKEN`).
        #[arg(long, env = "FLUXVM_TOKEN")]
        token: Option<String>,
    },
    #[command(next_help_heading = "Lifecycle Commands")]
    /// Create a VM from a JSON spec file, or on the `vz` backend from `--name` and `--image` plus `apple.*` flags
    /// (`--guest`, `--display`, `--rosetta`, `--provision-*`, ...); flags override a `--spec` file's fields.
    Create(create::CreateArgs),
    /// List VMs. `-l env=dev,team!=x,gpu` filters by label selector.
    List {
        #[arg(short = 'l', long = "selector")]
        selector: Option<String>,
        /// Also list the container warm pool's waiting VMs.
        #[arg(long)]
        all: bool,
    },
    /// Get a VM by id.
    Get {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Relaunch a Stopped VM from its existing disk (skips image
    /// clone/cloud-init reseed — see VmManager::start). `-l` for bulk.
    Start {
        #[command(flatten)]
        target: Target,
    },
    /// Stop a VM, or every VM matching `-l`.
    Stop {
        #[command(flatten)]
        target: Target,
    },
    Pause {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    Resume {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Delete a VM, or every VM matching `-l` (needs `--yes` for bulk).
    Delete {
        #[command(flatten)]
        target: Target,
    },
    /// Stop (graceful, then forced) and start again. REST:
    /// `POST /v1/vms/{id}/restart`. `-l` for bulk.
    Restart {
        #[command(flatten)]
        target: Target,
    },
    /// Set or remove VM labels: `key=value` sets, `key-` removes. REST:
    /// `PATCH /v1/vms/{id}` with `{"labels": {...}}`.
    Label {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(required = true, value_parser = parse_label_edit)]
        labels: Vec<(String, Option<String>)>,
    },
    /// Rename a VM (catalog images use `rename`). REST:
    /// `PATCH /v1/vms/{id}` with `{"name": "..."}`.
    RenameVm {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        new_name: String,
    },
    /// Copy a stopped VM into a new VM (disk flattened, fresh MAC, labels
    /// kept). REST: `POST /v1/vms/{id}/clone` `{"name": "..."}`.
    CloneVm {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        new_name: String,
    },
    /// Fork a running flux-vm VM into N running copies sharing one memory
    /// snapshot. REST: `POST /v1/vms/{id}/fork` `{"count": N}`.
    ForkVm {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(short = 'n', long, default_value_t = 1)]
        count: u32,
        /// Child names are `<prefix>-<n>` (default `<vm>-fork`).
        #[arg(long)]
        prefix: Option<String>,
    },
    /// Block until a VM reaches a state: `running`, `stopped`, `paused`,
    /// `failed`, or `agent` (guest agent answers a ping).
    Wait {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long = "for", default_value = "running", value_parser = ["running", "stopped", "paused", "failed", "agent"])]
        for_state: String,
        /// Give up after this many seconds (exit non-zero).
        #[arg(long, default_value_t = 120)]
        timeout: u64,
    },
    /// Alias for `delete` (machinectl `terminate`).
    #[command(hide = true)]
    Terminate {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    #[command(next_help_heading = "Runtime Control")]
    /// Freeze every process in the VM's cgroup via the cgroup v2 freezer
    /// (`cgroup.freeze`) — a kernel-level stop that works even if the VMM's
    /// own control socket is unresponsive, unlike `pause` (QMP/API-level
    /// vCPU stop, tracked as the VM's `Paused` status). REST equivalent:
    /// `POST /v1/vms/{id}/freeze`. See docs/operations.md's "Resource
    /// control (cgroup v2)" section.
    Freeze {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Thaw a VM previously frozen with `freeze`. REST equivalent:
    /// `POST /v1/vms/{id}/thaw`.
    Thaw {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Report whether a VM's cgroup is currently frozen. REST equivalent:
    /// `GET /v1/vms/{id}/frozen`.
    Frozen {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Apply cgroup v2 resource-control settings to a running VM — CPU
    /// quota, memory limit, I/O weight, max PIDs, and/or host CPU pinning.
    /// REST equivalent: `POST /v1/vms/{id}/resources`. See
    /// docs/operations.md's "Resource control (cgroup v2)" section. Every
    /// flag is optional and, like the `ResourcePatch` body it becomes, only
    /// the fields you actually pass are touched — omitting a flag leaves
    /// that control untouched, it does not reset it. At least one flag is
    /// required; a bare `fluxctl resources <id>` with nothing to change is
    /// rejected rather than silently doing nothing.
    /// Alias `set-limit` matches machinectl.
    #[command(visible_alias = "set-limit")]
    Resources {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// CPU quota as a percentage of one core (150 = 1.5 cores).
        #[arg(long)]
        cpu_quota_percent: Option<u32>,
        /// Memory limit in bytes.
        #[arg(long)]
        memory_max_bytes: Option<u64>,
        /// I/O weight, 1-10000 (cgroup default: 100).
        #[arg(long)]
        io_weight: Option<u32>,
        /// Maximum number of PIDs allowed in the VM's cgroup.
        #[arg(long)]
        pids_max: Option<u64>,
        /// Host CPU cores to pin the VM to, in the same set syntax
        /// `cpuset.cpus` itself reads back, e.g. `0-3`, `0,2,4`, or
        /// `0-1,4-5`.
        #[arg(long)]
        cpuset_cpus: Option<String>,
    },
    /// Read back the VM's current cgroup cpuset pin. REST equivalent:
    /// `GET /v1/vms/{id}/cpuset`. Write via `resources --cpuset-cpus`.
    Cpuset {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Cgroup-derived resource metrics for a VM (CPU%, memory bytes, disk
    /// read/write). REST equivalent: `GET /v1/vms/{id}/stats`.
    Stats {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// PSI (Pressure Stall Information) for the VM's cgroup — cpu/memory/io
    /// some+full with avg10/60/300. REST equivalent:
    /// `GET /v1/vms/{id}/pressure`.
    Pressure {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Read or set the virtio-balloon of a running KVM-engine VM: memory the
    /// guest gives back to the host. REST: `GET|POST /v1/vms/{id}/balloon`.
    Balloon {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// Balloon size in MiB to request (0 deflates). Omit to read it.
        #[arg(long)]
        set_mib: Option<u64>,
    },
    /// Save a screenshot of a running vz VM's display (Linux or macOS guest)
    /// as a PNG. REST: `GET /v1/vms/{id}/screenshot`.
    Screenshot {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long = "out", default_value = "screen.png")]
        output: PathBuf,
        /// Scale down to this many pixels wide.
        #[arg(long)]
        max_width: Option<u32>,
    },
    /// Send keyboard and mouse input to a running vz VM's display, e.g.
    /// '{"action":"click","x":600,"y":400}' or '{"action":"key","key":"c","modifiers":["control"]}'.
    /// Coordinates are screenshot pixels. REST: `POST /v1/vms/{id}/input`.
    Input {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// JSON input actions, run in order.
        actions: Vec<String>,
        /// Type this text (US layout) after the actions; `\n` is Enter.
        #[arg(long)]
        text: Option<String>,
    },
    /// Per-VM guest sign-in kept in the host's login Keychain, typed into the
    /// guest's login screen on request. REST: `/v1/vms/{id}/signin`.
    Signin {
        #[command(subcommand)]
        command: SigninCommand,
    },
    /// Memory use of a VM's VMM process: PSS, private and shared pages, and
    /// balloon state. REST: `GET /v1/vms/{id}/memory`.
    Memory {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Day-2 hotplug of CPU, memory, NIC, or a virtiofs share onto a running
    /// VM. REST equivalents: `POST /v1/vms/{id}/hotplug/{cpu,memory,nic,share}`.
    Hotplug {
        #[command(subcommand)]
        command: HotplugCommand,
    },
    /// Save full VM state under a tag so a later `start-from-snapshot` can
    /// restore it. REST equivalent: `POST /v1/vms/{id}/snapshot`.
    Snapshot {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        tag: String,
    },
    /// List a VM's snapshots. REST: `GET /v1/vms/{id}/snapshots`.
    SnapshotList {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Delete one snapshot tag. REST: `DELETE /v1/vms/{id}/snapshots/{tag}`.
    SnapshotDelete {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        tag: String,
    },
    /// Export a VM's root disk to a standalone qcow2 (live VMs via a
    /// short-lived internal snapshot). Default destination:
    /// `<state_dir>/backups/<name>-<utc>.qcow2`. REST: `POST /v1/vms/{id}/backup`.
    /// Scheduled snapshots: label a VM `fluxvm.io/snapshot-every=6h`
    /// (optional `fluxvm.io/snapshot-keep=7`).
    Backup {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        dest: Option<PathBuf>,
        /// Name under `<state_dir>/backups` instead of `<name>-<utc>`.
        #[arg(long, conflicts_with = "dest")]
        name: Option<String>,
        #[arg(long, default_value_t = false)]
        compress: bool,
        /// Also back up data disks: `dest` becomes a directory of
        /// `root.qcow2` + `<disk>.qcow2`, consistent with each other.
        #[arg(long, default_value_t = false)]
        all_disks: bool,
        /// Freeze guest filesystems via the guest agent: auto (when it
        /// answers), required, or never.
        #[arg(long, default_value = "auto", value_parser = parse_quiesce)]
        quiesce: fluxvm_core::model::BackupQuiesce,
    },
    /// Backups under `<state_dir>/backups`, newest first. REST: `GET /v1/backups`.
    Backups,
    /// Delete a backup by name. REST: `DELETE /v1/backups/{name}`.
    BackupDelete { name: String },
    /// Restore a backup into a stopped VM in place (root and data disks).
    /// REST: `POST /v1/vms/{id}/restore-backup`.
    RestoreBackup {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        name: String,
    },
    /// Named VM specs: save once, create many. REST: `/v1/vm-templates[/{name}]`,
    /// `POST /v1/vm-templates/{name}/instantiate`.
    VmTemplate {
        #[command(subcommand)]
        command: TemplateCommand,
    },
    /// Named remote daemons (kubeconfig-style). With a current context set,
    /// VM verbs go to that server; `--context local` or `context unset`
    /// returns to local mode.
    Context {
        #[command(subcommand)]
        command: ContextCommand,
    },
    /// Data disks (QEMU): list, attach, resize, detach. REST:
    /// `/v1/vms/{id}/disks[/{name}]`.
    Disk {
        #[command(subcommand)]
        command: DiskCommand,
    },
    /// Relaunch a VM from a previously saved snapshot tag. REST equivalent:
    /// `POST /v1/vms/{id}/start-from-snapshot`.
    StartFromSnapshot {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        tag: String,
    },
    #[command(next_help_heading = "Guest Access")]
    /// Interactive guest login over vsock PTY (machinectl `login`/`shell`).
    /// Requires `agent.enabled`. With a trailing command, runs it via vsock
    /// `exec` instead of opening a PTY (machinectl `shell NAME cmd…`).
    #[command(visible_aliases = ["login", "shell"])]
    Console {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long, default_value_t = 80)]
        cols: u16,
        #[arg(long, default_value_t = 24)]
        rows: u16,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// Attach to the VM's serial port (QEMU). No guest agent needed — shows
    /// bootloader/kernel output and a serial getty. Ctrl-] detaches. REST:
    /// websocket `GET /v1/vms/{id}/serial`.
    Serial {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Connect stdin/stdout to a vz VM's named console port (`apple.console_ports`, `/dev/virtio-ports/<name>` in the
    /// guest). Ctrl-] detaches. REST: websocket `GET /v1/vms/{id}/ports/{name}`.
    PortConnect {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        name: String,
    },
    /// Bring up the VMs described in `fluxvm.toml`: create what is missing, start what is stopped, recreate what
    /// changed, in dependency order, and make the services reachable by name. Naming a service brings up only it and
    /// what it depends on.
    Up {
        #[arg(short = 'f', long, default_value = "fluxvm.toml")]
        file: PathBuf,
        services: Vec<String>,
        #[command(flatten)]
        fleet: StackFleet,
        /// With --fleet: this node (overrides `placement.node`; also a drained one).
        #[arg(long, requires = "fleet")]
        node: Option<String>,
        /// With --fleet: only nodes with this label, `key=value` (added to `placement.labels`). Repeatable.
        #[arg(long = "node-selector", value_parser = parse_label, requires = "fleet")]
        node_selector: Vec<(String, String)>,
    },
    /// Delete the stack's VMs, last-started first (`--keep` only stops them).
    Down {
        #[arg(short = 'f', long, default_value = "fluxvm.toml")]
        file: PathBuf,
        /// Stack name, instead of reading it from the file.
        #[arg(long)]
        stack: Option<String>,
        #[arg(long)]
        keep: bool,
        #[command(flatten)]
        fleet: StackFleet,
    },
    /// List the stack's VMs with status and address.
    Ps {
        #[arg(short = 'f', long, default_value = "fluxvm.toml")]
        file: PathBuf,
        #[arg(long)]
        stack: Option<String>,
        #[command(flatten)]
        fleet: StackFleet,
    },
    /// Convert a docker-compose.yml into a stack file of container services (printed, or written with -o). What
    /// cannot be carried over (bind mounts, UDP, build, …) is listed on stderr.
    ImportCompose {
        #[arg(default_value = "docker-compose.yml")]
        file: PathBuf,
        /// Stack name; default: the compose file's `name`, else its directory's name.
        #[arg(long)]
        name: Option<String>,
        /// Write here instead of stdout (an existing file is not overwritten).
        #[arg(long = "out")]
        output: Option<PathBuf>,
    },
    /// Internal: relay stdin/stdout to a guest's vsock port through a runner's proxy socket. Used as ssh's ProxyCommand for
    /// guests with no network card.
    #[command(hide = true)]
    VsockProxy {
        socket: PathBuf,
        #[arg(default_value_t = 22)]
        port: u32,
    },
    /// Boot a throwaway VM, SSH into it, and delete it when the session ends (`--keep` to retain it).
    /// `fluxctl run` on a Mac uses the built-in `debian-13`; elsewhere pass an image.
    /// Everything after `--` runs in the guest instead of a shell.
    Run {
        /// Image name or path (default on macOS: debian-13; also debian-12, ubuntu-24.04, ubuntu-26.04,
        /// fedora-44, centos-stream-10, almalinux-10, rocky-10, kali).
        image: Option<String>,
        #[arg(long)]
        name: Option<String>,
        #[arg(long, default_value_t = 2)]
        cpus: u8,
        #[arg(long, default_value_t = 2048)]
        memory_mib: u64,
        /// Forward 127.0.0.1:HOST to guest port GUEST (TCP). Repeatable.
        #[arg(short = 'p', long = "publish", value_name = "HOST:GUEST")]
        ports: Vec<String>,
        /// Share a host directory into the guest: HOST:GUEST[:ro]. Repeatable.
        #[arg(short = 'v', long = "volume", value_name = "HOST:GUEST[:ro]")]
        volumes: Vec<String>,
        /// Guest login user (default: your local user name).
        #[arg(long, short = 'l')]
        user: Option<String>,
        /// Keep the VM after the session instead of deleting it.
        #[arg(long)]
        keep: bool,
        /// Cold-boot a fresh VM every time instead of restoring the warm snapshot (macOS).
        #[arg(long)]
        no_warm: bool,
        #[arg(last = true)]
        command: Vec<String>,
    },
    /// SSH into the guest at its `guest_ip` via the host OpenSSH client.
    /// Needs a reachable address and `sshd` in the guest — distinct from
    /// `console`/`login` (vsock agent PTY).
    Ssh {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// Login user (default: the user the VM's cloud-init created, else root).
        #[arg(long, short = 'l')]
        user: Option<String>,
        #[arg(long, short = 'p', default_value_t = 22)]
        port: u16,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        ssh_args: Vec<String>,
    },
    /// Show one VM's record (machinectl `status`/`show`). Same JSON as `get`.
    Show {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Guest power-off via vsock agent (`shutdown -h now`). Distinct from
    /// `stop`, which tears the VMM down from the host.
    Poweroff {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Guest reboot via vsock agent.
    Reboot {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Force-kill the VMM without guest ACPI powerdown (machinectl `kill`).
    /// Prefer `stop` for a clean shutdown.
    Kill {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Bind a host directory into the guest as virtiofs (machinectl `bind`).
    /// Same as `hotplug share`.
    Bind {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// Absolute host directory to share.
        host_path: PathBuf,
        #[arg(long, default_value_t = false)]
        read_only: bool,
    },
    /// Start this VM automatically when `fluxctl serve` boots (machinectl
    /// `enable`). Marker under `state_dir/autostart/{id}`.
    Enable {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Clear the autostart mark (machinectl `disable`).
    Disable {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Tail the VM's captured console log file. REST equivalent:
    /// `GET /v1/vms/{id}/logs?lines=&follow=`.
    Logs {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// How many trailing lines to print (default 100).
        #[arg(long, default_value_t = 100)]
        lines: usize,
        /// Keep following new lines (like `tail -f`).
        #[arg(long, default_value_t = false)]
        follow: bool,
    },
    /// Run a command inside the guest over vsock (requires agent.enabled in the VM spec).
    Exec {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        /// JSON confinement policy (fluxvm-procbox policy shape) applied
        /// inside the guest with Landlock + seccomp; the response reports
        /// what was enforced.
        #[arg(long)]
        policy: Option<PathBuf>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Health-check the vsock guest agent (requires agent.enabled) without
    /// spending a real `exec` round trip just to find out it's reachable —
    /// distinct from `qga ping`, which checks the QEMU guest-agent channel.
    Ping {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Copy a local file into the guest over vsock (requires agent.enabled)
    /// — the REST `/agent/put-file` route's CLI equivalent, previously only
    /// reachable by hand-rolling the HTTP call yourself.
    CopyTo {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// Path to the file on this host.
        local: PathBuf,
        /// Destination path inside the guest; parent directories are
        /// created as needed.
        remote: String,
        /// Unix permission bits to set on the guest-side file, e.g. `600`.
        /// Defaults to `644` if unset.
        #[arg(long)]
        mode: Option<u32>,
    },
    /// Copy a file out of the guest over vsock (requires agent.enabled) —
    /// the REST `/agent/get-file` route's CLI equivalent. The guest file's
    /// own Unix permission bits are restored on the copy this host writes.
    CopyFrom {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// Path to the file inside the guest.
        remote: String,
        /// Path to write on this host.
        local: PathBuf,
    },
    /// QEMU guest-agent (virtio-serial) helpers — Zyvor/GuestKit Windows agent.
    Qga {
        #[command(subcommand)]
        command: QgaCommand,
    },
    #[command(next_help_heading = "Images & Pools")]
    BuildImage {
        #[arg(long)]
        spec: PathBuf,
    },
    /// Import a VMware/other VM (OVA, OVF, VMDK, VHD(X), qcow2) as raw disks
    /// under state_dir/images/imported/NAME, repairing the boot disk for
    /// virtio. REST: `POST /v1/images/import`.
    ImportImage {
        /// Host path of the .ova/.ovf/disk (on the server with --server).
        source: PathBuf,
        #[arg(long)]
        name: String,
        /// Skip the offline guest repair.
        #[arg(long)]
        no_repair: bool,
        /// Uninstall open-vm-tools/vmware-tools packages, not only disable them.
        #[arg(long)]
        remove_vmware_tools: bool,
    },
    /// Manage the named/checksummed/optionally-signed image catalog (see
    /// config.catalog). Referencing a catalog name in a VM spec's `image`
    /// field (instead of a raw path) is handled automatically by `create` —
    /// these subcommands are only for building/signing/administering the
    /// catalog itself, and work offline against `catalog.path` with no
    /// `fluxctl serve` required.
    Catalog {
        #[command(subcommand)]
        command: CatalogCommand,
    },
    /// OCI images for `vz` sandboxes (macOS): each image's rootfs is built once per manifest digest and cached
    /// under `<state_dir>/oci`. See docs/oci-sandboxes.md.
    Oci {
        #[command(subcommand)]
        command: OciCommand,
    },
    /// Private VM-to-VM networks between `vz` guests (`apple.networks`, `oci.networks`). See docs/macos.md.
    Vznet {
        #[command(subcommand)]
        command: VznetCommand,
    },
    /// Virtualization.framework device state of a running `vz` VM, and the Mac's own capabilities. REST: `/v1/host/apple`
    /// and `/v1/vms/{id}/vz/*`. See docs/macos.md.
    Vz {
        #[command(subcommand)]
        command: VzCommand,
    },
    /// List image catalog entries (machinectl `list-images`).
    ListImages,
    /// Show one catalog entry (machinectl `image-status` / `show-image`).
    #[command(visible_alias = "show-image")]
    ImageStatus { name: String },
    /// Clone a catalog entry (machinectl `clone`).
    Clone { name: String, new_name: String },
    /// Rename a catalog entry (machinectl `rename`).
    Rename { name: String, new_name: String },
    /// Mark a catalog entry read-only (machinectl `read-only`). Use `--off`
    /// to unlock.
    ReadOnly {
        name: String,
        #[arg(long, default_value_t = false)]
        off: bool,
    },
    /// Remove a catalog entry (machinectl `remove`). For VMs use `terminate`.
    Remove { name: String },
    /// Remove orphaned catalog download cache (machinectl `clean`).
    Clean,
    /// Fetch a remote image into the catalog (machinectl `pull-raw`).
    PullRaw {
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "qcow2")]
        format: String,
    },
    /// Register a local image file in the catalog (machinectl `import-raw`).
    ImportRaw {
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "qcow2")]
        format: String,
    },
    /// Export a catalog entry's file (machinectl `export-raw`).
    ExportRaw { name: String, dest: PathBuf },
    /// Not supported — FluxVM images are raw/qcow2, not tar. Use `pull-raw`.
    PullTar {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },
    /// Not supported — use `import-raw` for a local disk image.
    ImportTar {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },
    /// Not supported — use `import-raw` for a local disk image.
    ImportFs {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },
    /// Not supported — use `export-raw`.
    ExportTar {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },
    /// Image transfers are synchronous in FluxVM; always empty (machinectl
    /// `list-transfers`).
    ListTransfers,
    #[command(name = "cancel")]
    CancelTransfer {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },
    /// Edit is not applicable — change resources with `set-limit`/`resources`,
    /// or recreate from an updated spec.
    Edit {
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, hide = true)]
        _args: Vec<String>,
    },
    /// Manage warm VM pools — pre-booted, paused VMs handed out on claim in
    /// roughly resume time instead of full create time.
    Pool {
        #[command(subcommand)]
        command: PoolCommand,
    },
    #[command(next_help_heading = "Network Policy")]
    /// Per-VM network policy and dataplane introspection
    /// (`/v1/vms/{id}/network/*`). Distinct from `group`/`cnp`/`dataplane`,
    /// which are host-wide.
    Network {
        #[command(subcommand)]
        command: NetworkCommand,
    },
    /// Security groups for the VM-edge dataplane.
    Group {
        #[command(subcommand)]
        command: GroupCommand,
    },
    /// CNP documents compiled onto FluxVM security groups.
    Cnp {
        #[command(subcommand)]
        command: CnpCommand,
    },
    /// Reserved + group numeric identities.
    Identity {
        #[command(subcommand)]
        command: IdentityCommand,
    },
    /// Production dataplane health, ipcache, and FQDN refresh.
    Dataplane {
        #[command(subcommand)]
        command: DataplaneCommand,
    },
    #[command(next_help_heading = "Observability")]
    /// Correlate Runtime Intelligence with VM-edge policy and flow state.
    /// Works as a direct one-shot and does not require the intelligence HTTP daemon.
    Diagnose {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Live VM Flight Recorder events from KVM/scheduler/block/vhost eBPF probes.
    Trace {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long, default_value_t = 5)]
        seconds: u64,
        #[arg(long, default_value_t = 128)]
        limit: usize,
        /// json | jsonl
        #[arg(long, default_value = "json")]
        output: String,
    },
    /// Snapshot of identities, groups, CNPs, and labeled VMs.
    Observe,
    /// VM lifecycle / audit events from `state_dir/events.jsonl`. REST:
    /// `GET /v1/events`, `GET /v1/events/stream` (SSE).
    Events {
        /// Only events for this VM (id, name, or id prefix).
        #[arg(long, value_parser = output::parse_vm_ref)]
        vm: Option<Uuid>,
        /// Event-name prefix, e.g. `vm.` or `quota.deny`.
        #[arg(long)]
        event: Option<String>,
        /// Only events after this RFC 3339 timestamp.
        #[arg(long)]
        since: Option<chrono::DateTime<chrono::Utc>>,
        /// Newest N events (default 100).
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Keep printing new events as they are appended.
        #[arg(long, short = 'f', default_value_t = false)]
        follow: bool,
    },
    /// Per-token quota limits and usage. With `--token` (or `FLUXVM_TOKEN`)
    /// asks the running daemon (`GET /v1/quotas/me`); otherwise computes
    /// locally for `--name` (a configured token name).
    Quota {
        #[arg(long, env = "FLUXVM_TOKEN")]
        token: Option<String>,
        #[arg(long)]
        name: Option<String>,
    },
    /// Print a shell completion script: `fluxctl completions zsh > _fluxctl`.
    Completions { shell: clap_complete::Shell },
    /// Model Context Protocol server for AI agents (Hermes Agent, ...).
    Mcp {
        #[command(subcommand)]
        command: McpCommand,
    },
    /// Hubble-lite flows and CiliumEndpoint views.
    Hubble {
        #[command(subcommand)]
        command: HubbleCommand,
    },
    #[command(next_help_heading = "Cluster")]
    /// Live VM migration -- source-side VMM transport only (QEMU and Cloud
    /// Hypervisor; see docs/runtime-boundary.md's runtime contract v1), plus
    /// the target-side `receiver` arm that prepares a QEMU migrate-incoming
    /// listener. Fabric owns host selection, storage, and target-arming; this
    /// is the standalone-mode escape hatch for triggering the same
    /// `/v1/vms/{id}/migration/*` and `/v1/migration/receivers` REST
    /// primitives without Fabric or a raw HTTP call.
    Migrate {
        #[command(subcommand)]
        command: MigrateCommand,
    },
    /// Agent-sandbox track: create/list/snapshot sandboxes and reach their
    /// guest filesystem / process APIs. REST equivalents under `/v1/sandboxes*`.
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommand,
    },
    /// Manage a multi-host fleet through its central registry
    /// (`fluxvm-agent central`) — see docs/operations.md's "Distributed
    /// node-agent" section. Previously every one of these operations meant
    /// a raw `curl` call against `/fleet/*`; this closes the same
    /// no-CLI-equivalent gap `migrate`/`ping`/`copy-to` already closed for
    /// the per-node REST API, for the fleet-wide one.
    Fleet {
        /// Base URL of the `fluxvm-agent central` instance, e.g.
        /// `http://fleet-registry:7799`.
        #[arg(long, env = "CENTRAL_URL")]
        central: String,
        /// Bearer token matching `fluxvm-agent central --token`. Omit if
        /// the registry has no token configured.
        #[arg(long, env = "FLUXVM_AGENT_TOKEN")]
        token: Option<String>,
        #[command(subcommand)]
        command: FleetCommand,
    },
}

/// One VM by id/name/prefix, or every VM matching a label selector.
#[derive(clap::Args, Debug, Clone)]
#[group(skip)]
struct Target {
    #[arg(value_parser = output::parse_vm_ref, required_unless_present = "selector", conflicts_with = "selector")]
    id: Option<Uuid>,
    /// Label selector, e.g. `env=dev,team!=core,gpu`.
    #[arg(short = 'l', long = "selector")]
    selector: Option<String>,
    /// Confirm a destructive bulk (`-l`) operation.
    #[arg(long, default_value_t = false)]
    yes: bool,
}

#[derive(Subcommand)]
enum FleetCommand {
    /// List every registered node, each with its live `healthy`/`cordoned`
    /// state and free capacity. REST equivalent: `GET /fleet/nodes`.
    Nodes,
    /// Exactly one node's own record -- the same shape a `Nodes` list entry
    /// has, without fetching and filtering the whole fleet just to check one
    /// node's `healthy`/`cordoned`/free-capacity state. REST equivalent:
    /// `GET /fleet/nodes/{name}`.
    Node { name: String },
    /// Exclude a node from automatic (residual-capacity) placement without
    /// touching any VM already on it or deregistering the node — same
    /// semantics as `kubectl cordon`. REST equivalent:
    /// `POST /fleet/nodes/{name}/cordon`.
    Cordon { name: String },
    /// Clear a node's cordon, re-admitting it to automatic placement. REST
    /// equivalent: `POST /fleet/nodes/{name}/uncordon`.
    Uncordon { name: String },
    /// Permanently forget a decommissioned node's registry entry. Only
    /// works once the node's heartbeat has already gone stale — the
    /// registry rejects deregistering a still-healthy node (409), since its
    /// very next heartbeat would just re-add it. REST equivalent:
    /// `DELETE /fleet/nodes/{name}`.
    Deregister { name: String },
    /// Fleet-wide capacity summary computed from each node's last
    /// heartbeat — no proxy calls to any node's own `fluxctl serve`. REST
    /// equivalent: `GET /fleet/capacity`.
    Capacity,
    /// Create a VM through the fleet: residual-capacity placement picks a
    /// healthy, uncordoned node unless `--node` names one explicitly (which
    /// bypasses placement entirely, same as `kubectl` with `spec.nodeName`
    /// set — including landing on a cordoned node and ignoring any
    /// `--node-selector`). REST equivalent: `POST /fleet/vms`.
    Create {
        /// Path to a `CreateVmRequest` JSON spec, same shape `fluxvm
        /// create --spec` takes.
        #[arg(long)]
        spec: PathBuf,
        /// Exact node name to create on, bypassing automatic placement.
        #[arg(long)]
        node: Option<String>,
        /// Restrict automatic placement to a node whose labels (set via
        /// `fluxvm-agent node --label key=value`) match, as `key=value`.
        /// Repeatable. Ignored when `--node` is also given. Merged with
        /// (and overriding) any `"nodeSelector"` already in the spec file,
        /// the same override relationship `--node` has with the spec's own
        /// `"node"` field.
        #[arg(long = "node-selector", value_parser = parse_label)]
        node_selector: Vec<(String, String)>,
    },
    /// The fleet-wide VM list, each entry tagged with which node it's on.
    /// Any node this couldn't account for (unreachable, stale, or erroring)
    /// is named in the response's `unreachable_nodes` field rather than
    /// silently missing from `items`. REST equivalent: `GET /fleet/vms`.
    Vms,
    /// The VMs on exactly one node, queried directly against that node
    /// rather than filtered out of the fleet-wide list — works even when
    /// other nodes in the fleet are unreachable. REST equivalent:
    /// `GET /fleet/nodes/{name}/vms`.
    NodeVms { name: String },
    /// Delete a VM on a specific node through the fleet proxy. REST
    /// equivalent: `DELETE /fleet/vms/{node}/{id}`.
    Delete { node: String, id: Uuid },
}

#[derive(Subcommand)]
enum SigninCommand {
    /// Store the sign-in; the password is prompted for (echo off) or read
    /// from stdin when it isn't a terminal.
    Set {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// Username typed before the password by `--mode username`/`username_tab`.
        #[arg(long = "user")]
        username: Option<String>,
    },
    /// Whether a sign-in is stored, and its username (never the password).
    Status {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Remove the stored sign-in.
    Clear {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Type the stored sign-in into the VM's display.
    Type {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// password, username (username, Enter, password) or username_tab.
        #[arg(long, default_value = "password")]
        mode: String,
        /// Don't press Enter after the password.
        #[arg(long)]
        no_submit: bool,
    },
}

#[derive(Subcommand)]
enum QgaCommand {
    /// guest-ping over the VM's QGA unix socket.
    Ping {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Run PowerShell (-Command) inside the guest via QGA guest-exec.
    Powershell {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Raw guest-exec (path + args).
    Exec {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        path: String,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        args: Vec<String>,
    },
    /// Open an inbound Windows firewall port (live PowerShell).
    FirewallOpen {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        port: u16,
        #[arg(long, default_value = "tcp")]
        protocol: String,
        #[arg(long)]
        timeout_seconds: Option<u64>,
    },
    /// Remove a Windows firewall rule by display name.
    FirewallClose {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        name: String,
        #[arg(long)]
        timeout_seconds: Option<u64>,
    },
}

#[derive(Subcommand)]
enum MigrateCommand {
    /// Start a live migration to `destination` (a `tcp:host:port` or
    /// `unix:/path` URI -- `exec:` is rejected by the same shared allowlist
    /// the REST route validates against). Requires the VM to already be
    /// Running; both QEMU and Cloud Hypervisor sources are supported.
    Start {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        destination: String,
        /// "pre-copy" (default) or "post-copy".
        #[arg(long, default_value = "pre-copy")]
        mode: String,
        #[arg(long)]
        bandwidth_mbps: Option<u64>,
        #[arg(long)]
        max_downtime_ms: Option<u64>,
        #[arg(long)]
        multifd_channels: Option<u8>,
    },
    /// Poll migration progress. QEMU only -- Cloud Hypervisor's
    /// send-migration is fire-and-forget and exposes no status-polling
    /// primitive (see docs/runtime-boundary.md); this errors clearly for a
    /// Cloud Hypervisor VM rather than hanging or guessing.
    Status {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Cancel an in-flight migration. QEMU only, same reason as `status`.
    Cancel {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Target-side QEMU migrate-incoming receivers
    /// (`POST/DELETE /v1/migration/receivers…`). Pair with `migrate start`
    /// on the source after `activate`.
    Receiver {
        #[command(subcommand)]
        command: MigrateReceiverCommand,
    },
}

#[derive(Subcommand)]
enum MigrateReceiverCommand {
    /// Reserve a QEMU incoming receiver on this host. REST equivalent:
    /// `POST /v1/migration/receivers`.
    Create {
        /// Shared disk path both hosts already open (receiver does not copy it).
        #[arg(long)]
        disk: PathBuf,
        #[arg(long, default_value = "raw")]
        disk_format: String,
        #[arg(long)]
        vcpus: u8,
        #[arg(long)]
        memory_mib: u64,
        /// Empty or `host`. Other CPU models are rejected.
        #[arg(long, default_value = "")]
        cpu_model: String,
        /// Empty or a `q35...` machine type.
        #[arg(long, default_value = "")]
        machine: String,
        #[arg(long, default_value = "0.0.0.0")]
        listen_host: String,
        /// Address the source dials. Required when `listen_host` is a wildcard.
        #[arg(long, default_value = "")]
        advertise_host: String,
        /// `0` binds an ephemeral port.
        #[arg(long, default_value_t = 0)]
        listen_port: u16,
        #[arg(long)]
        expires_in_seconds: Option<u64>,
    },
    /// Arm `migrate-incoming` with the receiver's token. REST equivalent:
    /// `POST /v1/migration/receivers/{id}/activate`.
    Activate {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        token: String,
    },
    /// Tear down a receiver reservation. REST equivalent:
    /// `DELETE /v1/migration/receivers/{id}`.
    Delete {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum HotplugCommand {
    /// Add unrealized vCPUs reserved via `max_vcpus` at create time.
    /// REST: `POST /v1/vms/{id}/hotplug/cpu`.
    Cpu {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        add_vcpus: u8,
    },
    /// Add RAM as a new DIMM into slots reserved via `max_memory_mib`.
    /// REST: `POST /v1/vms/{id}/hotplug/memory`.
    Memory {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        add_memory_mib: u64,
    },
    /// Hot-add a virtio-net NIC (bridged or bridge-less direct). Exactly one
    /// of `--bridge` or `--outer` is required. REST:
    /// `POST /v1/vms/{id}/hotplug/nic`.
    Nic {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        bridge: Option<String>,
        #[arg(long)]
        mac: Option<String>,
        /// Outer device for bridge-less direct attach (mutually exclusive with `--bridge`).
        #[arg(long)]
        outer: Option<String>,
        #[arg(long)]
        netns_path: Option<String>,
        /// Direct attach mode: `peer-veth` (default) or `l2-uplink`.
        #[arg(long, default_value = "peer-veth")]
        mode: String,
        /// Guest IPv4 addresses for `l2-uplink` ARP steering (repeatable).
        #[arg(long)]
        guest_ip: Vec<String>,
    },
    /// Hot-remove an extra NIC by MAC or tap name and delete its TAP. REST:
    /// `POST /v1/vms/{id}/hotplug/nic/unplug`.
    NicUnplug {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long, required_unless_present = "tap", conflicts_with = "tap")]
        mac: Option<String>,
        #[arg(long)]
        tap: Option<String>,
    },
    /// Hot-add a virtiofs share. REST: `POST /v1/vms/{id}/hotplug/share`.
    Share {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        host_path: PathBuf,
        #[arg(long, default_value_t = false)]
        read_only: bool,
    },
}

#[derive(Subcommand)]
enum SandboxCommand {
    /// Create a sandbox from a JSON `SandboxCreateRequest` file. REST:
    /// `POST /v1/sandboxes`.
    Create {
        #[arg(long)]
        spec: PathBuf,
    },
    /// List sandboxes (FluxVm backend or workspace with `sandbox-proxy.json`).
    /// REST: `GET /v1/sandboxes`.
    List,
    /// Run a container image in its own lightweight VM (vz, macOS), print its
    /// console and exit with its exit code: `fluxctl sandbox run alpine:3.22 --rm -- echo hi`.
    /// REST: `POST /v1/sandboxes` with `oci`, then `GET /v1/sandboxes/{id}/logs`.
    Run(Box<sandbox_run::RunArgs>),
    /// A sandbox's console tail, with a container sandbox's exit code. REST:
    /// `GET /v1/sandboxes/{id}/logs`.
    Logs {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long, default_value_t = 200)]
        lines: usize,
    },
    /// Fill the warm `vz` sandbox pool to COUNT slots in the daemon's
    /// background (macOS; needs --server). REST: `POST /v1/sandboxes/warm`.
    Warm {
        #[arg(long)]
        count: usize,
    },
    /// Sandbox counts, warm-pool state and host memory pressure. REST:
    /// `GET /v1/sandboxes/density`.
    Density,
    /// Snapshot sandbox disk/state to a host path. REST:
    /// `POST /v1/sandboxes/{id}/snapshot`.
    Snapshot {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        path: PathBuf,
    },
    /// Read a file from the sandbox guest over vsock. REST:
    /// `POST /v1/sandboxes/{id}/fs/read`.
    FsRead {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        path: String,
    },
    /// Write a local file into the sandbox guest over vsock. REST:
    /// `POST /v1/sandboxes/{id}/fs/write`.
    FsWrite {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        /// Destination path inside the guest.
        #[arg(long)]
        path: String,
        /// Local file to upload.
        #[arg(long)]
        local: PathBuf,
        #[arg(long)]
        mode: Option<u32>,
    },
    /// Run a command in the sandbox guest over vsock. REST:
    /// `POST /v1/sandboxes/{id}/process`.
    Process {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// Run a command in an isolated copy of the sandbox and keep the result
    /// as a pending changeset; the sandbox itself is not touched. REST:
    /// `POST /v1/sandboxes/{id}/speculate`.
    Speculate {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        timeout_seconds: Option<u64>,
        /// Directory to diff (repeatable). Required for VM sandboxes.
        #[arg(long = "path")]
        paths: Vec<String>,
        /// Seconds the changeset stays decidable (default 3600, max 86400).
        #[arg(long)]
        ttl_seconds: Option<u64>,
        #[arg(trailing_var_arg = true, allow_hyphen_values = true, required = true)]
        command: Vec<String>,
    },
    /// List a sandbox's changesets. REST: `GET /v1/sandboxes/{id}/changesets`.
    Changesets {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Show one changeset. REST: `GET /v1/sandboxes/{id}/changesets/{cs}`.
    Changeset {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        cs: Uuid,
    },
    /// Approve a pending changeset. REST: `POST .../changesets/{cs}/approve`.
    Approve {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        cs: Uuid,
    },
    /// Reject a changeset and drop its staged files. REST:
    /// `POST .../changesets/{cs}/reject`.
    Reject {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        cs: Uuid,
    },
    /// Apply an approved changeset to the real sandbox (refuses on conflict).
    /// REST: `POST .../changesets/{cs}/apply`.
    Apply {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        cs: Uuid,
    },
}

#[derive(Subcommand)]
enum TemplateCommand {
    List,
    Show {
        name: String,
    },
    /// Save a template from a spec file or an existing VM's spec.
    Save {
        name: String,
        #[arg(long, conflicts_with = "from_vm", required_unless_present = "from_vm")]
        spec: Option<PathBuf>,
        #[arg(long, value_parser = output::parse_vm_ref)]
        from_vm: Option<Uuid>,
        #[arg(long)]
        description: Option<String>,
        /// Overwrite an existing template of the same name.
        #[arg(long, default_value_t = false)]
        replace: bool,
    },
    Delete {
        name: String,
    },
    /// Create a VM from a template.
    Create {
        template: String,
        vm_name: String,
        /// Label for the new VM (repeatable): `--label env=dev`.
        #[arg(long = "label", value_parser = parse_label_pair)]
        labels: Vec<(String, String)>,
    },
}

/// `fluxctl input` arguments as a JSON action list: each argument is one action object (or a list of them), then
/// `--text` as a `type` action.
/// Reads a secret from the terminal with echo off, or the first line of stdin when it isn't a terminal.
fn read_secret(prompt: &str) -> Result<String> {
    use std::io::{BufRead, IsTerminal, Write};
    let stdin = std::io::stdin();
    let mut line = String::new();
    if stdin.is_terminal() {
        eprint!("{prompt}");
        std::io::stderr().flush().ok();
        let fd = libc::STDIN_FILENO;
        // SAFETY: termios is plain data filled in by tcgetattr on a valid fd.
        let mut saved: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(fd, &mut saved) } != 0 {
            return Err(std::io::Error::last_os_error()).context("reading terminal mode");
        }
        let mut quiet = saved;
        quiet.c_lflag &= !libc::ECHO;
        quiet.c_lflag |= libc::ECHONL;
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &quiet) };
        let read = stdin.lock().read_line(&mut line);
        unsafe { libc::tcsetattr(fd, libc::TCSANOW, &saved) };
        read.context("reading password")?;
    } else {
        stdin
            .lock()
            .read_line(&mut line)
            .context("reading password from stdin")?;
    }
    let secret = line.trim_end_matches(['\r', '\n']).to_string();
    if secret.is_empty() {
        anyhow::bail!("empty password");
    }
    Ok(secret)
}

fn input_actions(args: &[String], text: Option<String>) -> Result<Vec<serde_json::Value>> {
    let mut out = Vec::new();
    for a in args {
        match serde_json::from_str(a).with_context(|| format!("not a JSON input action: {a}"))? {
            serde_json::Value::Array(list) => out.extend(list),
            v @ serde_json::Value::Object(_) => out.push(v),
            _ => anyhow::bail!("an input action is a JSON object: {a}"),
        }
    }
    if let Some(t) = text {
        out.push(serde_json::json!({"action": "type", "text": t}));
    }
    if out.is_empty() {
        anyhow::bail!("give at least one JSON action or --text");
    }
    Ok(out)
}

fn parse_label_pair(s: &str) -> Result<(String, String)> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => anyhow::bail!("expected key=value, got '{s}'"),
    }
}

#[derive(Subcommand)]
enum ContextCommand {
    /// Saved contexts (tokens are never printed).
    List,
    /// Save or overwrite a context.
    Add {
        name: String,
        #[arg(long)]
        server: String,
        #[arg(long, conflicts_with = "token_keychain")]
        token: Option<String>,
        /// Read the token from this Keychain generic-password service (account: the context name) instead of storing
        /// it, e.g. after `security add-generic-password -s fluxvm-api -a NAME -w`.
        #[arg(long)]
        token_keychain: Option<String>,
    },
    /// Make a context current.
    Use {
        name: String,
    },
    /// Print the current context.
    Current,
    /// Clear the current context (back to local mode).
    Unset,
    Delete {
        name: String,
    },
}

fn parse_quiesce(s: &str) -> Result<fluxvm_core::model::BackupQuiesce, String> {
    serde_json::from_value(serde_json::Value::String(s.to_string()))
        .map_err(|_| format!("{s:?}: use auto, required or never"))
}

#[derive(Subcommand)]
enum DiskCommand {
    /// Root disk plus every data disk.
    List {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Create a data disk, attach an existing image file or block
    /// device with --path, or overlay a shared image with --backing (QEMU);
    /// hot-added when the VM is running. On vz the disk applies at the next
    /// start (a USB image disk at once), and --url attaches an NBD export.
    Attach {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        name: String,
        #[arg(long, required_unless_present_any = ["path", "backing", "url"], conflicts_with_all = ["path", "backing", "url"])]
        size_gib: Option<u64>,
        /// Existing qcow2/raw file or block device; detach leaves it in place.
        #[arg(long, conflicts_with_all = ["backing", "url"])]
        path: Option<PathBuf>,
        /// qcow2/raw image to put a new qcow2 overlay on; never written.
        #[arg(long)]
        backing: Option<PathBuf>,
        /// vz: image (default), block (--path /dev/diskN) or nbd (--url).
        #[arg(long, value_parser = ["image", "block", "nbd"])]
        kind: Option<String>,
        /// vz: nbd://host:port/export or nbd+unix:///export?socket=PATH.
        #[arg(long, conflicts_with = "backing")]
        url: Option<String>,
        /// vz: attach read-only.
        #[arg(long)]
        read_only: bool,
        /// vz: host caching of an image file.
        #[arg(long, value_parser = ["automatic", "cached", "uncached"])]
        caching: Option<String>,
        /// vz: full (default), fsync (image files) or none.
        #[arg(long, value_parser = ["full", "fsync", "none"])]
        sync: Option<String>,
        /// vz: virtio (default), nvme or usb.
        #[arg(long, value_parser = ["virtio", "nvme", "usb"])]
        controller: Option<String>,
    },
    /// Grow `root` or a data disk (live or stopped).
    Resize {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        name: String,
        #[arg(long)]
        size_gib: u64,
    },
    /// Unplug and delete a data disk.
    Detach {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        name: String,
    },
}

#[derive(Subcommand)]
enum CnpCommand {
    List,
    Get {
        name: String,
    },
    Apply {
        #[arg(long)]
        spec: PathBuf,
    },
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum IdentityCommand {
    List,
}

#[derive(Subcommand)]
enum DataplaneCommand {
    Health,
    Ipcache,
    /// Netns-sandbox `/28` IPAM pool utilization (capacity, allocated, free,
    /// and whether it's near exhaustion) — see docs/network-fabric.md.
    IpamStatus,
    RefreshDns,
    /// Show the VM-edge migration gate and schema generation.
    MigrationState {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Freeze creation of new flows while preserving established conntrack.
    MigrationQuiesce {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Export a migration-consistent conntrack/observability snapshot.
    MigrationExport {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Import network state on the destination and leave it in restoring mode.
    MigrationRestore {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        input: PathBuf,
    },
    /// Re-enable new flows after destination cutover, or cancel source quiesce.
    MigrationResume {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
}

#[derive(Subcommand)]
enum HubbleCommand {
    /// Packet flows (Hubble-style). Color by default; `--output plain` / `normal` for no ANSI.
    Observe {
        /// color | plain | normal | json
        #[arg(long, default_value = "color")]
        output: String,
        /// One-line summaries vs full hop path.
        #[arg(long, short = 'd')]
        detailed: bool,
        #[arg(long, default_value_t = 64)]
        limit: usize,
        /// FORWARDED | DROPPED | AUDIT | all
        #[arg(long, default_value = "all")]
        verdict: String,
        /// tcp | udp | icmp | all
        #[arg(long, default_value = "all")]
        protocol: String,
    },
    /// Alias for `observe --detailed`.
    Flow {
        #[arg(long, default_value = "color")]
        output: String,
        #[arg(long, default_value_t = 64)]
        limit: usize,
        #[arg(long, default_value = "all")]
        verdict: String,
        #[arg(long, default_value = "all")]
        protocol: String,
    },
    Endpoints,
}

#[derive(Subcommand)]
enum NetworkCommand {
    /// Declared VM network policy. REST: `GET /v1/vms/{id}/network/policy`.
    Policy {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Replace the VM network policy from a JSON file. REST:
    /// `POST /v1/vms/{id}/network/policy`.
    SetPolicy {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        spec: PathBuf,
    },
    /// Declared + group-merged effective policy. REST:
    /// `GET /v1/vms/{id}/network/effective`.
    Effective {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Dataplane attachment status for the VM. REST:
    /// `GET /v1/vms/{id}/network/status`.
    Status {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Per-VM dataplane counters. REST: `GET /v1/vms/{id}/network/stats`.
    Stats {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Recent flows for the VM. REST: `GET /v1/vms/{id}/network/flows`.
    Flows {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long, default_value_t = 100)]
        limit: usize,
    },
}

#[derive(Subcommand)]
enum GroupCommand {
    List,
    Get {
        name: String,
    },
    Set {
        name: String,
        #[arg(long)]
        label: Vec<String>,
        #[arg(long)]
        allow_cidr: Vec<String>,
        #[arg(long)]
        deny_cidr: Vec<String>,
        #[arg(long)]
        allow_port: Vec<String>,
        #[arg(long)]
        default_allow: Option<bool>,
        #[arg(long)]
        allow_icmp: bool,
        #[arg(long)]
        priority: Option<u32>,
        #[arg(long)]
        description: Option<String>,
        #[arg(long)]
        max_egress_mbps: Option<u32>,
        #[arg(long)]
        max_egress_pps: Option<u32>,
    },
    Delete {
        name: String,
    },
}

#[derive(Subcommand)]
enum OciCommand {
    /// Pull an image and build its rootfs, e.g. `alpine:3.22` or `ghcr.io/org/app@sha256:…`.
    Pull {
        image: String,
        /// `linux/arm64` (default) or `linux/amd64` (runs under Rosetta).
        #[arg(long)]
        platform: Option<String>,
    },
    /// List cached images, most recently used first.
    Ls,
    /// Remove a cached image by digest, 12+ character digest prefix, or the reference it was pulled as.
    Rm { image: String },
    /// Remove every cached image no sandbox was started from, and every blob no remaining image needs.
    Prune,
}

#[derive(Subcommand)]
enum VzCommand {
    /// What this Mac's Virtualization.framework offers (OS, vmnet, custom Virtio, Secure Boot, Rosetta).
    Host,
    /// Apple's newest macOS restore image (what `--image macos --install` uses) and whether it is cached;
    /// `--download` fetches it now (about 25 GB).
    Ipsw {
        #[arg(long)]
        download: bool,
    },
    /// EFI Secure Boot state of a running guest (the pre-boot snapshot while it runs).
    SecureBoot {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Driver state and counters of the custom Virtio device; `--reset` asks it to re-negotiate.
    CustomVirtio {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        reset: bool,
    },
    /// USB devices on the VM's controllers. `--physical` lists host accessories granted to FluxVMUSBAccess.app;
    /// `--attach <registry_id>` passes one through (needs `--physical`).
    Usb {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long)]
        physical: bool,
        #[arg(long, requires = "physical")]
        attach: Option<u64>,
    },
}

#[derive(Subcommand)]
enum VznetCommand {
    /// Networks in use, their subnets and members (`--json` for the raw `GET /v1/vznets`).
    Ls {
        #[arg(long)]
        json: bool,
    },
}

/// `fluxctl vznet ls` as a table.
fn print_vznets(items: &serde_json::Value, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(items)?);
        return Ok(());
    }
    let nets = items.as_array().cloned().unwrap_or_default();
    if nets.is_empty() {
        println!("no private networks in use");
        return Ok(());
    }
    println!("{:<24} {:<16} {:<8} MEMBERS", "NETWORK", "SUBNET", "SWITCH");
    for n in nets {
        let s = |k: &str| n[k].as_str().unwrap_or("").to_string();
        let members: Vec<String> = n["members"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|m| {
                format!(
                    "{}={} ({})",
                    m["vm_name"].as_str().unwrap_or(""),
                    m["address"]
                        .as_str()
                        .unwrap_or("")
                        .split('/')
                        .next()
                        .unwrap_or(""),
                    m["status"].as_str().unwrap_or("")
                )
            })
            .collect();
        println!(
            "{:<24} {:<16} {:<8} {}",
            s("name"),
            s("subnet"),
            if n["switch_running"].as_bool() == Some(true) {
                "up"
            } else {
                "idle"
            },
            members.join(", ")
        );
    }
    Ok(())
}

// Parsed once per invocation, so the size difference costs nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum CatalogCommand {
    /// Generate a fresh Ed25519 keypair for signing catalog entries. The
    /// private key is only ever printed here — store it yourself (this
    /// project has no opinion on how); put the public key into
    /// config.catalog.trusted_signers to require it going forward.
    Keygen,
    /// Sign a catalog entry and print it as JSON, or append it to
    /// --catalog-file if given (creating the file with an empty array
    /// first if it doesn't exist yet).
    ///
    /// `disable_version_flag` keeps `--version` as the image version
    /// instead of clap's auto-generated flag (same id, debug-assert panic).
    #[command(disable_version_flag = true)]
    Sign {
        /// Base64 Ed25519 private key, as printed by `catalog keygen`.
        #[arg(long)]
        key: String,
        #[arg(long)]
        name: String,
        #[arg(long)]
        source: String,
        #[arg(long)]
        sha256: String,
        #[arg(long, default_value = "qcow2")]
        format: String,
        #[arg(long)]
        distro: Option<String>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        arch: Option<String>,
        /// Which CI pipeline produced these image bytes, e.g.
        /// "github-actions/build-images.yml" -- asserted by you, the
        /// signer, same posture as everything else on this command: not
        /// independently verified against the actual CI system, but
        /// tamper-evident (covered by the signature) once set.
        #[arg(long)]
        build_pipeline: Option<String>,
        /// The specific run/job id within --build-pipeline that produced
        /// this image.
        #[arg(long)]
        build_run_id: Option<String>,
        /// The source commit SHA the build was triggered from.
        #[arg(long)]
        build_commit: Option<String>,
        #[arg(long)]
        catalog_file: Option<PathBuf>,
    },
    /// List every catalog entry, each with a computed `signature_valid` /
    /// `signed_by` (see `GET /v1/images/catalog`). Reads `catalog.json`
    /// directly — works with no `fluxctl serve` running.
    List,
    /// Register a new catalog entry: fetches `source` first if it's a URL,
    /// then hashes whatever actually landed on disk (never trusts a
    /// caller-supplied sha256). The entry starts unsigned — sign it
    /// separately with `catalog sign` if `trusted_signers` is configured.
    Add {
        name: String,
        /// Local path or http(s):// URL.
        #[arg(long)]
        source: String,
        #[arg(long, default_value = "qcow2")]
        format: String,
    },
    /// Remove a catalog entry. Refuses a `read_only` entry — `catalog
    /// unlock` it first.
    Remove { name: String },
    /// Rename a catalog entry. Clears its signature and `signed_at` — a
    /// signature covers the entry's name (see `canonical_payload`), so a
    /// renamed entry's old signature no longer vouches for it. Refuses a
    /// `read_only` entry.
    Rename { name: String, new_name: String },
    /// Clone a catalog entry under a new name. The clone is unsigned, same
    /// reasoning as `rename`.
    Clone { name: String, target_name: String },
    /// Copy a catalog entry's resolved local file to `dest` (fetching it
    /// first if `source` is a URL not yet cached).
    Export { name: String, dest: PathBuf },
    /// Mark a catalog entry read-only, protecting it from `remove`/`rename`
    /// — for a base image other entries get `clone`d from.
    Lock { name: String },
    /// Clear a catalog entry's read-only flag.
    Unlock { name: String },
    /// Remove cached downloads under `state_dir/downloads` that no current
    /// catalog entry's `source` still references by filename.
    Clean,
}

#[derive(Subcommand)]
enum PoolCommand {
    Create {
        #[arg(long)]
        spec: PathBuf,
    },
    List,
    Get {
        name: String,
    },
    /// Claim one ready VM from the pool. Replenishment is fired off as a
    /// background task so this command stays fast, which means it only
    /// reliably completes if `fluxctl serve` is already running against
    /// the same state_dir — this one-shot process exits right after
    /// printing the claimed VM, taking any still-in-flight replenishment
    /// down with it. Prefer `POST /v1/pools/{name}/claim` against a running
    /// `serve` daemon for guaranteed backfill.
    Claim {
        name: String,
        #[arg(long)]
        vm_name: Option<String>,
        #[arg(long)]
        ttl_seconds: Option<u64>,
    },
    /// Change a pool's target size without deleting and recreating it from
    /// the same spec. Growing blocks until the pool actually reaches its
    /// new size, same reasoning (and same `backfill_pool_sync` call) as
    /// `pool create` -- this is a one-shot process, so it can't rely on its
    /// own background backfill task surviving past printing the result.
    /// Shrinking happens synchronously either way: excess ready members are
    /// deleted immediately, not left for a reaper tick.
    Resize {
        name: String,
        #[arg(long)]
        size: usize,
    },
    Delete {
        name: String,
    },
}

async fn manager(cfg: Config) -> Result<Arc<VmManager>> {
    VmManager::new(cfg)
}

/// GET a path on the running daemon at `cfg.listen`. Used by healthz/readyz/metrics.
async fn daemon_get(cfg: &Config, path: &str, token: Option<&str>) -> Result<String> {
    let base = if cfg.listen.starts_with("http://") || cfg.listen.starts_with("https://") {
        cfg.listen.clone()
    } else {
        format!("http://{}", cfg.listen)
    };
    let url = format!("{}{}", base.trim_end_matches('/'), path);
    let http = reqwest::Client::new();
    let mut req = http.get(&url);
    if let Some(token) = token {
        req = req.bearer_auth(token);
    }
    let resp = req
        .send()
        .await
        .with_context(|| format!("GET {url} (is fluxctl serve running on listen?)"))?;
    let status = resp.status();
    let body = resp.text().await.context("reading daemon response body")?;
    if !status.is_success() {
        anyhow::bail!("GET {url} returned {status}: {body}");
    }
    Ok(body)
}

/// Interactive vsock PTY session with the local TTY in raw mode so
/// keystrokes (Ctrl-C, arrows, …) reach the guest instead of the host shell.
async fn run_console_session(m: &VmManager, id: Uuid, cols: u16, rows: u16) -> Result<()> {
    use fluxvm_guest_protocol::PtyFrame;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let (cols, rows) = terminal_size().unwrap_or((cols, rows));
    let _raw = RawTerminal::enter()?;
    let console = m.open_console(id, cols, rows).await?;
    let (mut reader, mut writer) = tokio::io::split(console);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<PtyFrame>(64);
    let writer_task = async move {
        while let Some(frame) = rx.recv().await {
            writer.write_all(&frame.encode()).await?;
            writer.flush().await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let resize_tx = tx.clone();
    let resize_task = async move {
        let mut winch =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
        let mut last = (cols, rows);
        while winch.recv().await.is_some() {
            if let Some(size) = terminal_size()
                && size != last
            {
                last = size;
                if resize_tx
                    .send(PtyFrame::Resize {
                        cols: size.0,
                        rows: size.1,
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let stdin_task = async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 || tx.send(PtyFrame::Data(buf[..n].to_vec())).await.is_err() {
                break;
            }
        }
        Ok::<(), anyhow::Error>(())
    };
    let to_guest = async move {
        tokio::select! {
            r = writer_task => r,
            r = stdin_task => r,
            r = resize_task => r,
        }
    };
    let to_host = async move {
        let mut stdout = tokio::io::stdout();
        tokio::io::copy(&mut reader, &mut stdout).await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = to_guest => result?,
        result = to_host => result?,
    }
    Ok(())
}

/// Ctrl-] ends a serial session, as in telnet/virsh console.
const SERIAL_ESCAPE: u8 = 0x1d;

async fn run_serial_session(m: &VmManager, id: Uuid) -> Result<()> {
    run_stream_session(m.open_serial(id).await?, &format!("{id} serial console")).await
}

async fn run_stream_session(stream: tokio::net::UnixStream, what: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprintln!("Connected to {what}. Escape: Ctrl-]\r");
    }
    let _raw = RawTerminal::enter()?;
    let (mut reader, mut writer) = stream.into_split();
    let to_guest = async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            if interactive && let Some(pos) = chunk.iter().position(|b| *b == SERIAL_ESCAPE) {
                writer.write_all(&chunk[..pos]).await?;
                break;
            }
            writer.write_all(chunk).await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    let to_host = async move {
        let mut stdout = tokio::io::stdout();
        let mut buf = [0u8; 4096];
        loop {
            let n = reader.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            stdout.write_all(&buf[..n]).await?;
            stdout.flush().await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = to_guest => result?,
        result = to_host => result?,
    }
    Ok(())
}

/// [`run_serial_session`] over the daemon's `/v1/vms/{id}/serial` websocket.
async fn run_remote_serial(r: &remote::Remote, id: Uuid) -> Result<()> {
    run_remote_stream(
        r,
        &format!("/v1/vms/{id}/serial"),
        &format!("{id} serial console"),
    )
    .await
}

async fn run_remote_stream(r: &remote::Remote, path: &str, what: &str) -> Result<()> {
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;
    let ws = r.websocket(path).await?;
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprintln!("Connected to {what}. Escape: Ctrl-]\r");
    }
    let _raw = RawTerminal::enter()?;
    let (mut tx, mut rx) = ws.split();
    let to_guest = async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 1024];
        loop {
            let n = stdin.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            let chunk = &buf[..n];
            let (data, done) = match chunk.iter().position(|b| *b == SERIAL_ESCAPE) {
                Some(pos) if interactive => (&chunk[..pos], true),
                _ => (chunk, false),
            };
            if !data.is_empty() {
                tx.send(Message::Binary(data.to_vec().into())).await?;
            }
            if done {
                break;
            }
        }
        let _ = tx.send(Message::Close(None)).await;
        Ok::<(), anyhow::Error>(())
    };
    let to_host = async move {
        let mut stdout = tokio::io::stdout();
        while let Some(msg) = rx.next().await {
            match msg? {
                Message::Binary(b) => stdout.write_all(&b).await?,
                Message::Text(t) => stdout.write_all(t.as_bytes()).await?,
                Message::Close(_) => break,
                _ => continue,
            }
            stdout.flush().await?;
        }
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! {
        result = to_guest => result?,
        result = to_host => result?,
    }
    Ok(())
}

/// `(cols, rows)` of the controlling terminal, if stdout is a TTY.
fn terminal_size() -> Option<(u16, u16)> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut ws) };
    (rc == 0 && ws.ws_col > 0 && ws.ws_row > 0).then_some((ws.ws_col, ws.ws_row))
}

/// Puts stdin into termios raw mode while held; restores on drop.
struct RawTerminal {
    fd: i32,
    original: libc::termios,
}

impl RawTerminal {
    fn enter() -> Result<Self> {
        if !std::io::stdin().is_terminal() {
            // Non-interactive pipe: leave cooked mode alone.
            return Ok(Self {
                fd: -1,
                original: unsafe { std::mem::zeroed() },
            });
        }
        let fd = libc::STDIN_FILENO;
        let mut original = unsafe { std::mem::zeroed() };
        let rc = unsafe { libc::tcgetattr(fd, &mut original) };
        if rc != 0 {
            anyhow::bail!("tcgetattr failed: {}", std::io::Error::last_os_error());
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        let rc = unsafe { libc::tcsetattr(fd, libc::TCSANOW, &raw) };
        if rc != 0 {
            anyhow::bail!("tcsetattr failed: {}", std::io::Error::last_os_error());
        }
        Ok(Self { fd, original })
    }
}

impl Drop for RawTerminal {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe {
                libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
            }
        }
    }
}

/// Tail `path` like the REST `/v1/vms/{id}/logs` handler: print the last
/// `lines` lines, then optionally follow new ones.
async fn tail_vm_log(path: &Path, lines: usize, follow: bool) -> Result<()> {
    use std::collections::VecDeque;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let file = tokio::fs::File::open(path)
        .await
        .with_context(|| format!("opening VM log {}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut line = String::new();
    let mut tail: VecDeque<String> = VecDeque::with_capacity(lines);
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => break,
            Ok(_) => {
                if tail.len() == lines {
                    tail.pop_front();
                }
                tail.push_back(std::mem::take(&mut line));
            }
            Err(e) => return Err(e).context("reading VM log"),
        }
    }
    let mut stdout = tokio::io::stdout();
    for l in &tail {
        stdout.write_all(l.as_bytes()).await?;
    }
    stdout.flush().await?;
    if !follow {
        return Ok(());
    }
    loop {
        line.clear();
        match reader.read_line(&mut line).await {
            Ok(0) => tokio::time::sleep(std::time::Duration::from_millis(300)).await,
            Ok(_) => {
                stdout.write_all(line.as_bytes()).await?;
                stdout.flush().await?;
            }
            Err(e) => return Err(e).context("following VM log"),
        }
    }
}

/// Parses `migrate start --mode`, matching `MigrationMode`'s own
/// `#[serde(rename_all = "kebab-case")]` spelling ("pre-copy"/"post-copy")
/// exactly rather than inventing a separate CLI vocabulary for the same two
/// values the wire format already uses.
fn parse_migration_mode(s: &str) -> Result<MigrationMode> {
    match s {
        "pre-copy" => Ok(MigrationMode::PreCopy),
        "post-copy" => Ok(MigrationMode::PostCopy),
        other => anyhow::bail!(
            "unknown migration mode {other:?}, expected \"pre-copy\" or \"post-copy\""
        ),
    }
}

/// Parses `fleet create --node-selector key=value`. Splits on the FIRST
/// `=` only, so a value containing `=` (unusual, but not invalid) still
/// round-trips. Same shape as `fluxvm-agent node --label`'s own parser —
/// duplicated rather than shared, since the two live in different binary
/// crates and this is a two-line function.
fn parse_label(s: &str) -> Result<(String, String)> {
    match s.split_once('=') {
        Some((k, v)) if !k.is_empty() => Ok((k.to_string(), v.to_string())),
        _ => anyhow::bail!("expected key=value, got '{s}'"),
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum BulkOp {
    Start,
    Stop,
    Restart,
    Delete,
}

impl BulkOp {
    async fn apply(
        self,
        m: &Arc<VmManager>,
        id: Uuid,
    ) -> Result<Option<fluxvm_core::model::VmRecord>> {
        Ok(match self {
            BulkOp::Start => Some(m.start(id).await?),
            BulkOp::Stop => Some(m.stop(id).await?),
            BulkOp::Restart => Some(m.restart(id).await?),
            BulkOp::Delete => {
                m.delete(id).await?;
                None
            }
        })
    }
}

/// Single id keeps the legacy output (the VM record); `-l` prints one
/// result per matched VM and fails if any of them failed.
async fn run_bulk(m: &Arc<VmManager>, target: Target, op: BulkOp) -> Result<()> {
    if let Some(id) = target.id {
        if let Some(vm) = op.apply(m, id).await? {
            println!("{}", serde_json::to_string_pretty(&vm)?);
        }
        return Ok(());
    }
    let sel = target
        .selector
        .as_deref()
        .context("pass a VM id or -l <selector>")?;
    let selector = fluxvm_core::model::LabelSelector::parse(sel)?;
    let matched: Vec<_> = m
        .list()
        .await
        .into_iter()
        .filter(|vm| selector.matches(&vm.labels))
        .collect();
    if op == BulkOp::Delete && !target.yes {
        let names: Vec<_> = matched.iter().map(|v| v.name.as_str()).collect();
        anyhow::bail!(
            "refusing to delete {} VM(s) matching {sel:?} without --yes: {}",
            matched.len(),
            names.join(", ")
        );
    }
    let mut results = Vec::new();
    let mut failed = 0usize;
    for vm in matched {
        match op.apply(m, vm.id).await {
            Ok(rec) => results.push(serde_json::json!({
                "id": vm.id, "name": vm.name, "ok": true,
                "status": rec.map(|r| r.status),
            })),
            Err(e) => {
                failed += 1;
                results.push(serde_json::json!({
                    "id": vm.id, "name": vm.name, "ok": false, "error": format!("{e:#}"),
                }));
            }
        }
    }
    println!("{}", serde_json::to_string_pretty(&results)?);
    if failed > 0 {
        anyhow::bail!("{op:?} failed for {failed} VM(s)");
    }
    Ok(())
}

/// Parses `label` edits: `key=value` sets, `key-` removes.
fn parse_label_edit(s: &str) -> Result<(String, Option<String>)> {
    if let Some((k, v)) = s.split_once('=') {
        if k.is_empty() {
            anyhow::bail!("expected key=value or key-, got '{s}'");
        }
        return Ok((k.to_string(), Some(v.to_string())));
    }
    match s.strip_suffix('-') {
        Some(k) if !k.is_empty() => Ok((k.to_string(), None)),
        _ => anyhow::bail!("expected key=value or key-, got '{s}'"),
    }
}

/// Poll until `id` reaches `state` (or the guest agent answers, for `agent`).
async fn wait_for_vm(m: &VmManager, id: Uuid, state: &str, timeout: u64) -> Result<()> {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
    loop {
        let vm = m.get(id).await?;
        let status = serde_json::to_value(vm.status)?
            .as_str()
            .unwrap_or_default()
            .to_string();
        let reached = if state == "agent" {
            status == "running" && m.agent_ping(id).await.is_ok()
        } else {
            status == state
        };
        if reached {
            println!(
                "{}",
                serde_json::json!({"id": id, "reached": state, "status": status})
            );
            return Ok(());
        }
        if state != "failed" && status == "failed" {
            anyhow::bail!(
                "VM {id} failed while waiting for {state}: {}",
                vm.error.unwrap_or_default()
            );
        }
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out after {timeout}s waiting for {state} (status={status})");
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

fn run_context(command: ContextCommand, format: output::OutputFormat) -> Result<()> {
    let mut c = contexts::Contexts::load()?;
    match command {
        ContextCommand::List => {
            return output::print_list(format, &c.summary(), output::CONTEXT_COLUMNS);
        }
        ContextCommand::Current => {
            println!("{}", c.current.as_deref().unwrap_or(remote::LOCAL_CONTEXT));
            return Ok(());
        }
        ContextCommand::Add {
            name,
            server,
            token,
            token_keychain,
        } => {
            if name == remote::LOCAL_CONTEXT {
                anyhow::bail!("'{name}' is reserved for local mode");
            }
            c.add(
                &name,
                contexts::Endpoint {
                    server,
                    token,
                    token_keychain,
                },
            )?
        }
        ContextCommand::Use { name } => c.use_context(&name)?,
        ContextCommand::Unset => c.current = None,
        ContextCommand::Delete { name } => c.remove(&name)?,
    }
    c.save()?;
    println!(
        "{}",
        serde_json::json!({"ok": true, "current": c.current, "path": contexts::path()})
    );
    Ok(())
}

/// `--server` dispatch for the core VM verbs; everything else needs a local host.
fn load_stack_file(file: &Path) -> Result<(stack::StackFile, PathBuf)> {
    let text = std::fs::read_to_string(file)
        .with_context(|| format!("reading {} (use -f to name the stack file)", file.display()))?;
    let dir = file
        .canonicalize()?
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    Ok((stack::parse(&text)?, dir))
}

fn import_compose(file: &Path, name: Option<&str>, output: Option<&Path>) -> Result<()> {
    let text =
        std::fs::read_to_string(file).with_context(|| format!("reading {}", file.display()))?;
    let name = match name {
        Some(n) => n.to_owned(),
        None => {
            let declared = serde_yaml::from_str::<serde_yaml::Value>(&text)
                .ok()
                .and_then(|d| d.get("name")?.as_str().map(str::to_owned));
            let dir = file.canonicalize()?;
            let dir = dir.parent().and_then(Path::file_name).map(|d| {
                d.to_string_lossy()
                    .to_ascii_lowercase()
                    .replace(['_', '.', ' '], "-")
            });
            declared.or(dir).context("name the stack with --name")?
        }
    };
    let c = compose::convert(&text, &name)?;
    for w in &c.warnings {
        eprintln!("warning: {w}");
    }
    match output {
        None => print!("{}", c.toml),
        Some(path) => {
            use std::io::Write;
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
                .with_context(|| format!("creating {}", path.display()))?
                .write_all(c.toml.as_bytes())?;
            eprintln!(
                "wrote {}; review it, then `fluxctl up -f {}`",
                path.display(),
                path.display()
            );
        }
    }
    Ok(())
}

/// The stack file when it exists; with `--stack NAME` a missing file is fine.
/// `up|down|ps --fleet`: the stack's node is found (or, for `up`, chosen) through the registry, then driven over its
/// own REST API like `--server`.
async fn run_stack_on_fleet(
    central: &str,
    fleet_token: Option<String>,
    node_token: Option<String>,
    command: Command,
) -> Result<()> {
    let ft = fleet_token.as_deref();
    let node_api = |n: &stack_fleet::Node| remote::Remote::new(&n.url, node_token.clone());
    match command {
        Command::Up {
            file,
            services,
            node,
            node_selector,
            ..
        } => {
            let (f, dir) = load_stack_file(&file)?;
            let only = (!services.is_empty()).then_some(services.as_slice());
            let n =
                stack_fleet::place(central, ft, &f, only, node.as_deref(), &node_selector).await?;
            eprintln!("stack {} on node {} ({})", f.name, n.name, n.url);
            stack::up(&node_api(&n), &f, &dir, only).await
        }
        Command::Down {
            file,
            stack: name,
            keep,
            ..
        } => {
            let f = stack_for(&file, name.as_deref())?;
            let name =
                name.unwrap_or_else(|| f.as_ref().map(|f| f.name.clone()).unwrap_or_default());
            let (nodes, holding, unknown) = stack_fleet::locate(central, ft, &name).await?;
            for n in nodes.iter().filter(|n| holding.contains(&n.name)) {
                eprintln!("node {}:", n.name);
                stack::down(&node_api(n), &name, f.as_ref(), keep).await?;
            }
            if !unknown.is_empty() {
                anyhow::bail!(
                    "could not check {} for VMs of {name}",
                    unknown.into_iter().collect::<Vec<_>>().join(", ")
                );
            }
            Ok(())
        }
        Command::Ps {
            file, stack: name, ..
        } => {
            let f = stack_for(&file, name.as_deref())?;
            let name =
                name.unwrap_or_else(|| f.as_ref().map(|f| f.name.clone()).unwrap_or_default());
            let (nodes, holding, unknown) = stack_fleet::locate(central, ft, &name).await?;
            for n in nodes.iter().filter(|n| holding.contains(&n.name)) {
                for [svc, vm, status, ip] in stack::ps(&node_api(n), &name).await? {
                    println!("{svc:<16} {vm:<28} {status:<10} {ip:<16} {}", n.name);
                }
            }
            for n in unknown {
                eprintln!("warning: could not list the VMs on node {n}");
            }
            Ok(())
        }
        _ => unreachable!("only stack commands take --fleet"),
    }
}

fn stack_for(file: &Path, name: Option<&str>) -> Result<Option<stack::StackFile>> {
    match load_stack_file(file) {
        Ok((f, _)) => Ok(Some(f)),
        Err(_) if name.is_some() => Ok(None),
        Err(e) => Err(e),
    }
}

async fn run_remote(
    r: &remote::Remote,
    command: Command,
    format: output::OutputFormat,
) -> Result<()> {
    use reqwest::Method;
    use serde_json::json;
    let pretty = |v: &serde_json::Value| -> Result<()> {
        println!("{}", serde_json::to_string_pretty(v)?);
        Ok(())
    };
    let bulk = |target: Target, op: &'static str| async move {
        if let Some(id) = target.id {
            return pretty(&r.vm_op(id, op).await?);
        }
        let sel = target.selector.context("pass a VM id or -l <selector>")?;
        let matched = r.list_vms(Some(&sel)).await?;
        if op == "delete" && !target.yes {
            let names: Vec<_> = matched
                .iter()
                .filter_map(|v| v.get("name").and_then(|n| n.as_str()))
                .collect();
            anyhow::bail!(
                "refusing to delete {} VM(s) matching {sel:?} without --yes: {}",
                matched.len(),
                names.join(", ")
            );
        }
        let mut results = Vec::new();
        let mut failed = 0usize;
        for vm in matched {
            let (Some(id), name) = (
                vm.get("id")
                    .and_then(|v| v.as_str())
                    .and_then(|s| s.parse::<Uuid>().ok()),
                vm.get("name").cloned().unwrap_or_default(),
            ) else {
                continue;
            };
            match r.vm_op(id, op).await {
                Ok(rec) => results.push(json!({
                    "id": id, "name": name, "ok": true, "status": rec.get("status"),
                })),
                Err(e) => {
                    failed += 1;
                    results.push(
                        json!({"id": id, "name": name, "ok": false, "error": format!("{e:#}")}),
                    );
                }
            }
        }
        pretty(&serde_json::Value::Array(results))?;
        if failed > 0 {
            anyhow::bail!("{op} failed for {failed} VM(s)");
        }
        Ok(())
    };
    match command {
        Command::List { selector, all } => output::print_list(
            format,
            &r.list_vms_all(selector.as_deref(), all).await?,
            output::VM_COLUMNS,
        )?,
        Command::Get { id } | Command::Status { id: Some(id), .. } => {
            pretty(&r.call(Method::GET, &format!("/v1/vms/{id}"), None).await?)?
        }
        Command::Vznet {
            command: VznetCommand::Ls { json },
        } => print_vznets(
            &r.call(Method::GET, "/v1/vznets", None).await?["items"],
            json,
        )?,
        Command::Start { target } => bulk(target, "start").await?,
        Command::Stop { target } => bulk(target, "stop").await?,
        Command::Restart { target } => bulk(target, "restart").await?,
        Command::Delete { target } => bulk(target, "delete").await?,
        Command::Pause { id } => pretty(&r.vm_op(id, "pause").await?)?,
        Command::Resume { id } => pretty(&r.vm_op(id, "resume").await?)?,
        Command::Label { id, labels } => {
            let labels: serde_json::Map<String, serde_json::Value> =
                labels.into_iter().map(|(k, v)| (k, json!(v))).collect();
            pretty(
                &r.call(
                    Method::PATCH,
                    &format!("/v1/vms/{id}"),
                    Some(json!({"labels": labels})),
                )
                .await?,
            )?
        }
        Command::RenameVm { id, new_name } => pretty(
            &r.call(
                Method::PATCH,
                &format!("/v1/vms/{id}"),
                Some(json!({"name": new_name})),
            )
            .await?,
        )?,
        Command::CloneVm { id, new_name } => pretty(
            &r.call(
                Method::POST,
                &format!("/v1/vms/{id}/clone"),
                Some(json!({"name": new_name})),
            )
            .await?,
        )?,
        Command::ImportImage {
            source,
            name,
            no_repair,
            remove_vmware_tools,
        } => pretty(
            &r.call(
                Method::POST,
                "/v1/images/import",
                Some(json!({
                    "source": source,
                    "name": name,
                    "repair": !no_repair,
                    "remove_vmware_tools": remove_vmware_tools,
                })),
            )
            .await?,
        )?,
        Command::ForkVm { id, count, prefix } => {
            let mut body = json!({"count": count});
            if let Some(p) = prefix {
                body["namePrefix"] = json!(p);
            }
            pretty(
                &r.call(Method::POST, &format!("/v1/vms/{id}/fork"), Some(body))
                    .await?,
            )?
        }
        Command::Snapshot { id, tag } => pretty(
            &r.call(
                Method::POST,
                &format!("/v1/vms/{id}/snapshot"),
                Some(json!({"tag": tag})),
            )
            .await?,
        )?,
        Command::SnapshotList { id } => {
            let v = r
                .call(Method::GET, &format!("/v1/vms/{id}/snapshots"), None)
                .await?;
            output::print_list(format, &v["items"], output::SNAPSHOT_COLUMNS)?
        }
        Command::SnapshotDelete { id, tag } => {
            r.call(
                Method::DELETE,
                &format!("/v1/vms/{id}/snapshots/{tag}"),
                None,
            )
            .await?;
            println!("{}", json!({"ok": true, "deleted": tag}));
        }
        Command::Backup {
            id,
            dest,
            name,
            compress,
            all_disks,
            quiesce,
        } => {
            if dest.is_some() {
                anyhow::bail!(
                    "--dest is local-only; remote backups land in the server's state_dir/backups"
                );
            }
            pretty(
                &r.call(
                    Method::POST,
                    &format!("/v1/vms/{id}/backup"),
                    Some(
                        json!({"name": name, "compress": compress, "all_disks": all_disks, "quiesce": quiesce}),
                    ),
                )
                .await?,
            )?
        }
        Command::Backups => pretty(&r.call(Method::GET, "/v1/backups", None).await?)?,
        Command::BackupDelete { name } => {
            r.call(Method::DELETE, &format!("/v1/backups/{name}"), None)
                .await?;
            println!("{}", json!({"ok": true, "deleted": name}));
        }
        Command::RestoreBackup { id, name } => pretty(
            &r.call(
                Method::POST,
                &format!("/v1/vms/{id}/restore-backup"),
                Some(json!({"name": name})),
            )
            .await?,
        )?,
        Command::Disk { command } => match command {
            DiskCommand::List { id } => {
                let v = r
                    .call(Method::GET, &format!("/v1/vms/{id}/disks"), None)
                    .await?;
                output::print_list(format, &v["items"], output::DISK_COLUMNS)?
            }
            DiskCommand::Attach {
                id,
                name,
                size_gib,
                path,
                backing,
                kind,
                url,
                read_only,
                caching,
                sync,
                controller,
            } => {
                let mut body =
                    json!({"name": name, "size_gib": size_gib, "path": path, "backing": backing});
                let vz = json!({"kind": kind, "url": url, "read_only": read_only.then_some(true),
                    "caching": caching, "sync": sync, "controller": controller});
                for (k, v) in vz.as_object().into_iter().flatten() {
                    if !v.is_null() {
                        body[k] = v.clone();
                    }
                }
                pretty(
                    &r.call(Method::POST, &format!("/v1/vms/{id}/disks"), Some(body))
                        .await?,
                )?
            }
            DiskCommand::Resize { id, name, size_gib } => pretty(
                &r.call(
                    Method::PATCH,
                    &format!("/v1/vms/{id}/disks/{name}"),
                    Some(json!({"size_gib": size_gib})),
                )
                .await?,
            )?,
            DiskCommand::Detach { id, name } => {
                r.call(Method::DELETE, &format!("/v1/vms/{id}/disks/{name}"), None)
                    .await?;
                println!("{}", json!({"ok": true, "detached": name}));
            }
        },
        Command::Events {
            vm,
            event,
            since,
            limit,
            follow,
        } => {
            let mut q = Vec::new();
            if let Some(vm) = vm {
                q.push(format!("vm={vm}"));
            }
            if let Some(e) = event {
                q.push(format!("event={}", remote::encode_query(&e)));
            }
            let tail_query = q.join("&");
            if let Some(s) = since {
                q.push(format!("since={}", remote::encode_query(&s.to_rfc3339())));
            }
            q.push(format!("limit={limit}"));
            let v = r
                .call(Method::GET, &format!("/v1/events?{}", q.join("&")), None)
                .await?;
            output::print_list(format, &v["items"], output::EVENT_COLUMNS)?;
            if follow {
                r.follow_events(&tail_query, |ev| print_event_line(format, &ev))
                    .await?;
            }
        }
        Command::Serial { id } => run_remote_serial(r, id).await?,
        Command::PortConnect { id, name } => {
            run_remote_stream(
                r,
                &format!("/v1/vms/{id}/ports/{name}"),
                &format!("{id} port {name}"),
            )
            .await?
        }
        Command::Create(args) => {
            let body = create::create_body(&args)?;
            pretty(&r.call(Method::POST, "/v1/vms", Some(body)).await?)?
        }
        Command::VmTemplate { command } => match command {
            TemplateCommand::List => {
                let v = r.call(Method::GET, "/v1/vm-templates", None).await?;
                output::print_list(format, &v["items"], output::TEMPLATE_COLUMNS)?
            }
            TemplateCommand::Show { name } => pretty(
                &r.call(Method::GET, &format!("/v1/vm-templates/{name}"), None)
                    .await?,
            )?,
            TemplateCommand::Save {
                name,
                spec,
                from_vm,
                description,
                replace,
            } => {
                let spec = match (spec, from_vm) {
                    (Some(p), _) => serde_json::from_slice(&std::fs::read(p)?)?,
                    (None, Some(id)) => {
                        r.call(Method::GET, &format!("/v1/vms/{id}"), None).await?["request"].take()
                    }
                    (None, None) => unreachable!("clap requires --spec or --from-vm"),
                };
                pretty(
                    &r.call(
                        Method::POST,
                        "/v1/vm-templates",
                        Some(json!({"name": name, "description": description, "spec": spec, "replace": replace})),
                    )
                    .await?,
                )?
            }
            TemplateCommand::Delete { name } => {
                r.call(Method::DELETE, &format!("/v1/vm-templates/{name}"), None)
                    .await?;
                println!("{}", json!({"ok": true, "deleted": name}));
            }
            TemplateCommand::Create {
                template,
                vm_name,
                labels,
            } => {
                let labels: serde_json::Map<String, serde_json::Value> =
                    labels.into_iter().map(|(k, v)| (k, json!(v))).collect();
                pretty(
                    &r.call(
                        Method::POST,
                        &format!("/v1/vm-templates/{template}/instantiate"),
                        Some(json!({"name": vm_name, "labels": labels})),
                    )
                    .await?,
                )?
            }
        },
        Command::Quota { .. } => pretty(&r.call(Method::GET, "/v1/quotas/me", None).await?)?,
        Command::Healthz => pretty(&r.call(Method::GET, "/healthz", None).await?)?,
        Command::Readyz => pretty(&r.call(Method::GET, "/readyz", None).await?)?,
        Command::Wait {
            id,
            for_state,
            timeout,
        } if for_state != "agent" => {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout);
            loop {
                let vm = r.call(Method::GET, &format!("/v1/vms/{id}"), None).await?;
                let status = vm["status"].as_str().unwrap_or_default().to_string();
                if status == for_state {
                    println!(
                        "{}",
                        json!({"id": id, "reached": for_state, "status": status})
                    );
                    return Ok(());
                }
                if status == "failed" {
                    anyhow::bail!(
                        "VM {id} failed while waiting for {for_state}: {}",
                        vm["error"]
                    );
                }
                if std::time::Instant::now() >= deadline {
                    anyhow::bail!(
                        "timed out after {timeout}s waiting for {for_state} (status={status})"
                    );
                }
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
            }
        }
        Command::Vz { command } => match command {
            VzCommand::Host => pretty(&r.call(Method::GET, "/v1/host/apple", None).await?)?,
            VzCommand::Ipsw { download } => pretty(
                &r.call(
                    if download { Method::POST } else { Method::GET },
                    "/v1/host/apple/ipsw",
                    download.then(|| json!({})),
                )
                .await?,
            )?,
            VzCommand::SecureBoot { id } => pretty(
                &r.call(Method::GET, &format!("/v1/vms/{id}/vz/secure-boot"), None)
                    .await?,
            )?,
            VzCommand::CustomVirtio { id, reset: true } => pretty(
                &r.call(
                    Method::POST,
                    &format!("/v1/vms/{id}/vz/custom-virtio/reset"),
                    Some(json!({})),
                )
                .await?,
            )?,
            VzCommand::CustomVirtio { id, reset: false } => pretty(
                &r.call(Method::GET, &format!("/v1/vms/{id}/vz/custom-virtio"), None)
                    .await?,
            )?,
            VzCommand::Usb {
                id,
                physical: true,
                attach: Some(registry_id),
            } => pretty(
                &r.call(
                    Method::POST,
                    &format!("/v1/vms/{id}/vz/usb/physical"),
                    Some(json!({"registry_id": registry_id})),
                )
                .await?,
            )?,
            VzCommand::Usb {
                id, physical: true, ..
            } => pretty(
                &r.call(Method::GET, &format!("/v1/vms/{id}/vz/usb/physical"), None)
                    .await?,
            )?,
            VzCommand::Usb { id, .. } => pretty(
                &r.call(Method::GET, &format!("/v1/vms/{id}/vz/usb"), None)
                    .await?,
            )?,
        },
        Command::Balloon { id, set_mib } => match set_mib {
            Some(mib) => pretty(
                &r.call(
                    Method::POST,
                    &format!("/v1/vms/{id}/balloon"),
                    Some(json!({"balloon_mib": mib})),
                )
                .await?,
            )?,
            None => pretty(
                &r.call(Method::GET, &format!("/v1/vms/{id}/balloon"), None)
                    .await?,
            )?,
        },
        Command::Screenshot {
            id,
            output,
            max_width,
        } => {
            let mut path = format!("/v1/vms/{id}/screenshot");
            if let Some(w) = max_width {
                path.push_str(&format!("?max_width={w}"));
            }
            let (status, body) = r.get_raw(&path).await?;
            if !status.is_success() {
                anyhow::bail!("screenshot: {status}: {}", String::from_utf8_lossy(&body));
            }
            std::fs::write(&output, &body)
                .with_context(|| format!("writing {}", output.display()))?;
            println!("{}", output.display());
        }
        Command::Input { id, actions, text } => {
            let actions = input_actions(&actions, text)?;
            pretty(
                &r.call(
                    Method::POST,
                    &format!("/v1/vms/{id}/input"),
                    Some(json!({"actions": actions})),
                )
                .await?,
            )?
        }
        Command::Signin { command } => match command {
            SigninCommand::Set { id, username } => {
                let password = read_secret("password: ")?;
                pretty(
                    &r.call(
                        Method::PUT,
                        &format!("/v1/vms/{id}/signin"),
                        Some(json!({"username": username, "password": password})),
                    )
                    .await?,
                )?
            }
            SigninCommand::Status { id } => pretty(
                &r.call(Method::GET, &format!("/v1/vms/{id}/signin"), None)
                    .await?,
            )?,
            SigninCommand::Clear { id } => pretty(
                &r.call(Method::DELETE, &format!("/v1/vms/{id}/signin"), None)
                    .await?,
            )?,
            SigninCommand::Type {
                id,
                mode,
                no_submit,
            } => pretty(
                &r.call(
                    Method::POST,
                    &format!("/v1/vms/{id}/signin"),
                    Some(json!({"mode": mode, "submit": !no_submit})),
                )
                .await?,
            )?,
        },
        Command::Memory { id } => pretty(
            &r.call(Method::GET, &format!("/v1/vms/{id}/memory"), None)
                .await?,
        )?,
        Command::Sandbox { command } => {
            let base = |id: Uuid| format!("/v1/sandboxes/{id}");
            match command {
                SandboxCommand::Speculate {
                    id,
                    timeout_seconds,
                    paths,
                    ttl_seconds,
                    command,
                } => {
                    let mut body = json!({
                        "command": command.join(" "),
                        "timeout_seconds": timeout_seconds,
                        "ttl_seconds": ttl_seconds,
                    });
                    if !paths.is_empty() {
                        body["paths"] = json!(paths);
                    }
                    pretty(
                        &r.call(Method::POST, &format!("{}/speculate", base(id)), Some(body))
                            .await?,
                    )?
                }
                SandboxCommand::Changesets { id } => pretty(
                    &r.call(Method::GET, &format!("{}/changesets", base(id)), None)
                        .await?,
                )?,
                SandboxCommand::Changeset { id, cs } => pretty(
                    &r.call(Method::GET, &format!("{}/changesets/{cs}", base(id)), None)
                        .await?,
                )?,
                SandboxCommand::Approve { id, cs } => pretty(
                    &r.call(
                        Method::POST,
                        &format!("{}/changesets/{cs}/approve", base(id)),
                        None,
                    )
                    .await?,
                )?,
                SandboxCommand::Reject { id, cs } => pretty(
                    &r.call(
                        Method::POST,
                        &format!("{}/changesets/{cs}/reject", base(id)),
                        None,
                    )
                    .await?,
                )?,
                SandboxCommand::Apply { id, cs } => pretty(
                    &r.call(
                        Method::POST,
                        &format!("{}/changesets/{cs}/apply", base(id)),
                        None,
                    )
                    .await?,
                )?,
                SandboxCommand::Warm { count } => pretty(
                    &r.call(
                        Method::POST,
                        "/v1/sandboxes/warm",
                        Some(json!({ "count": count })),
                    )
                    .await?,
                )?,
                SandboxCommand::Density => {
                    pretty(&r.call(Method::GET, "/v1/sandboxes/density", None).await?)?
                }
                SandboxCommand::Run(args) => {
                    let code = sandbox_run::run(sandbox_run::Target::Remote(r), &args).await?;
                    std::process::exit(code);
                }
                SandboxCommand::Logs { id, lines } => pretty(&serde_json::to_value(
                    sandbox_run::Target::Remote(r).logs(id, lines).await?,
                )?)?,
                _ => anyhow::bail!(
                    "this sandbox command is not available with --server; supported: run, logs, \
                     speculate, changesets, changeset, approve, reject, apply, warm, density"
                ),
            }
        }
        Command::Ssh {
            id,
            user,
            port,
            ssh_args,
        } => {
            let vm = r.call(Method::GET, &format!("/v1/vms/{id}"), None).await?;
            let ip = vm["guest_ip"]
                .as_str()
                .context("VM has no guest_ip yet — wait for it to boot")?;
            let user = user
                .or_else(|| {
                    vm["request"]["cloud_init"]["user"]
                        .as_str()
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "root".into());
            run::ssh_to(ip, &user, port, vm["backend"] == "vz", &ssh_args).await?;
        }
        Command::Up { file, services, .. } => {
            let (f, dir) = load_stack_file(&file)?;
            let only = (!services.is_empty()).then_some(services.as_slice());
            stack::up(r, &f, &dir, only).await?;
        }
        Command::Down {
            file,
            stack: name,
            keep,
            ..
        } => {
            let f = stack_for(&file, name.as_deref())?;
            let name =
                name.unwrap_or_else(|| f.as_ref().map(|f| f.name.clone()).unwrap_or_default());
            stack::down(r, &name, f.as_ref(), keep).await?;
        }
        Command::Ps {
            file, stack: name, ..
        } => {
            let f = stack_for(&file, name.as_deref())?;
            let name =
                name.unwrap_or_else(|| f.as_ref().map(|f| f.name.clone()).unwrap_or_default());
            for [svc, vm, status, ip] in stack::ps(r, &name).await? {
                println!("{svc:<16} {vm:<28} {status:<10} {ip}");
            }
        }
        Command::Run {
            image,
            name,
            cpus,
            memory_mib,
            ports,
            volumes,
            user,
            keep,
            no_warm,
            command,
        } => {
            let code = run::run(
                r,
                run::RunOptions {
                    image,
                    name,
                    cpus,
                    memory_mib,
                    ports,
                    volumes,
                    user,
                    keep,
                    no_warm,
                    command,
                },
            )
            .await?;
            std::process::exit(code);
        }
        _ => anyhow::bail!(
            "this command is not available with --server; supported: run, ssh, create, vm-template, list, get, \
             status <vm>, start, stop, restart, delete, pause, resume, label, rename-vm, clone-vm, fork-vm, import-image, snapshot, \
             snapshot-list, snapshot-delete, backup, disk, events [-f], serial, quota, healthz, \
             readyz, wait (not --for agent)"
        ),
    }
    Ok(())
}

/// Print events from the shared log, then optionally tail it.
async fn print_events(
    cfg: &Config,
    format: output::OutputFormat,
    filter: fluxvm_scheduler::EventFilter,
    follow: bool,
) -> Result<()> {
    let log = fluxvm_scheduler::events::EventLog::new(&cfg.state_dir);
    let items = log.list(&filter)?;
    output::print_list(format, &items, output::EVENT_COLUMNS)?;
    if !follow {
        return Ok(());
    }
    let mut offset = log.end_offset();
    let tail_filter = fluxvm_scheduler::EventFilter {
        limit: None,
        ..filter
    };
    loop {
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        let (events, next) = log.read_from(offset, &tail_filter)?;
        offset = next;
        for ev in events {
            print_event_line(format, &ev)?;
        }
    }
}

/// One followed event: JSON line, or a `ts  event  vm  k=v,...` row.
fn print_event_line(
    format: output::OutputFormat,
    ev: &fluxvm_scheduler::events::VmEvent,
) -> Result<()> {
    match format {
        output::OutputFormat::Json => println!("{}", serde_json::to_string(ev)?),
        _ => println!(
            "{}  {}  {}  {}",
            ev.ts.to_rfc3339(),
            ev.event,
            ev.vm_id
                .map(|i| i.to_string())
                .unwrap_or_else(|| "-".into()),
            ev.fields
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
    Ok(())
}

/// Parses `--cpuset-cpus`' set syntax (`"0-3"`, `"0,2,4"`, `"0-1,4-5"`) into
/// a sorted, deduplicated list of CPU ids — the same notation
/// `fluxvm_cgroup::cpuset` reads `cpuset.cpus`/`cpuset.cpus.effective` back
/// as (see `parse_set`/`format_set` there), so a value copied straight out
/// of `fluxctl resources`'s own prior output, or read directly from
/// `cpuset.cpus`, round-trips. Deliberately its own, independent parser
/// rather than importing that one: this one additionally rejects an empty
/// spec (ambiguous here — the flag is `Option<String>`, so "clear the
/// pinning" is already expressed by simply omitting the flag, not by
/// passing an empty string) and a reversed range like `"5-2"` (silently
/// empty under plain `start..=end`, which would apply an empty cpuset
/// instead of erroring the way a typo like this should).
fn parse_cpuset_spec(s: &str) -> Result<Vec<u32>> {
    let trimmed = s.trim();
    if trimmed.is_empty() {
        anyhow::bail!(
            "--cpuset-cpus was empty; omit the flag entirely to leave cpuset pinning untouched"
        );
    }
    let mut ids = Vec::new();
    for part in trimmed.split(',') {
        let part = part.trim();
        if part.is_empty() {
            anyhow::bail!("--cpuset-cpus {trimmed:?} has an empty entry between commas");
        }
        match part.split_once('-') {
            Some((start_str, end_str)) => {
                let start: u32 = start_str.trim().parse().with_context(|| {
                    format!("--cpuset-cpus {trimmed:?}: invalid range start {start_str:?}")
                })?;
                let end: u32 = end_str.trim().parse().with_context(|| {
                    format!("--cpuset-cpus {trimmed:?}: invalid range end {end_str:?}")
                })?;
                if start > end {
                    anyhow::bail!("--cpuset-cpus {trimmed:?}: range {start}-{end} has start > end");
                }
                ids.extend(start..=end);
            }
            None => {
                let id: u32 = part.parse().with_context(|| {
                    format!("--cpuset-cpus {trimmed:?}: invalid cpu id {part:?}")
                })?;
                ids.push(id);
            }
        }
    }
    ids.sort_unstable();
    ids.dedup();
    Ok(ids)
}

/// Reads a local file for `copy-to`, rejecting anything already too big for
/// the guest agent's own file-transfer cap before spending a base64 encode
/// and a vsock round trip on content the agent would just reject anyway —
/// see `fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES` and
/// `fluxvm-guest-agent`'s own `put_file`, which enforces the same limit
/// guest-side on the decoded bytes.
fn read_local_file_for_copy_to(path: &Path) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if bytes.len() > fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES {
        anyhow::bail!(
            "{} is {} bytes, exceeds the guest agent's {}-byte file-transfer limit",
            path.display(),
            bytes.len(),
            fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES,
        );
    }
    Ok(bytes)
}

/// Writes a `copy-from` response's content to `local`, restoring the same
/// Unix permission bits the guest reported the file had — so a copied-out
/// script, key, or config keeps behaving the way its mode implies instead of
/// silently landing at this process's umask default. Returns the number of
/// bytes written.
#[cfg(unix)]
fn write_copy_from_response(local: &Path, content_base64: &str, mode: u32) -> Result<usize> {
    use std::os::unix::fs::PermissionsExt;
    let bytes = B64
        .decode(content_base64)
        .context("decoding file content from guest agent")?;
    std::fs::write(local, &bytes).with_context(|| format!("writing {}", local.display()))?;
    std::fs::set_permissions(local, std::fs::Permissions::from_mode(mode & 0o777))
        .with_context(|| format!("setting permissions on {}", local.display()))?;
    Ok(bytes.len())
}

/// Non-Unix hosts have no `mode` bits of their own to restore — write the
/// content and leave permissions at whatever this platform defaults to.
#[cfg(not(unix))]
fn write_copy_from_response(local: &Path, content_base64: &str, _mode: u32) -> Result<usize> {
    let bytes = B64
        .decode(content_base64)
        .context("decoding file content from guest agent")?;
    std::fs::write(local, &bytes).with_context(|| format!("writing {}", local.display()))?;
    Ok(bytes.len())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "fluxvm=info,tower_http=info".into()),
        )
        .init();
    if let Some(r) = remote::from_argv_env() {
        output::seed_vm_index(r.vm_index().await);
    }
    let cli = {
        let color = if std::env::var_os("NO_COLOR").is_some() {
            ColorChoice::Never
        } else if std::env::var_os("FORCE_COLOR").is_some()
            || std::env::var_os("CLICOLOR_FORCE").is_some()
            || std::io::stdout().is_terminal()
        {
            ColorChoice::Always
        } else {
            ColorChoice::Auto
        };
        let mut cmd = Cli::command()
            .color(color)
            .override_usage("fluxctl [OPTIONS] <COMMAND>")
            .after_help(styles::after_help())
            // Clap cannot group subcommands into sections (Cobra can). Hide the
            // flat Commands list so our Cilium-style grouped after_help is the
            // only command listing; parsing/completions are unaffected.
            .mut_subcommands(|s| s.hide(true));
        let matches = cmd.get_matches_mut();
        Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
    };
    if let Command::Completions { shell } = &cli.command {
        use std::io::Write;
        let mut buf = Vec::new();
        clap_complete::generate(*shell, &mut Cli::command(), "fluxctl", &mut buf);
        match std::io::stdout().write_all(&buf) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {}
            other => other?,
        }
        return Ok(());
    }
    if let Command::VsockProxy { socket, port } = &cli.command {
        return fluxvm_apple::ssh::vsock_proxy(socket, *port);
    }
    if let Command::ImportCompose { file, name, output } = &cli.command {
        return import_compose(file, name.as_deref(), output.as_deref());
    }
    if let Command::Mcp { command } = &cli.command {
        let out = match command {
            McpCommand::Serve { .. } => None,
            McpCommand::Install {
                client,
                project,
                allow_write,
                with_token,
                name,
                dry_run,
            } => {
                let exe = std::env::current_exe().context("locating fluxctl")?;
                let exe = exe.canonicalize().unwrap_or(exe);
                let mut args = Vec::new();
                if let Some(c) = &cli.context {
                    args.extend(["--context".to_owned(), c.clone()]);
                }
                args.extend(["mcp".to_owned(), "serve".to_owned()]);
                if *allow_write {
                    args.push("--allow-write".into());
                }
                let mut env = Vec::new();
                if let Some(s) = &cli.server {
                    env.push(("FLUXVM_URL".to_owned(), s.clone()));
                }
                if let Some(c) = &cli.config {
                    let c = c.canonicalize().unwrap_or_else(|_| c.clone());
                    env.push(("FLUXVM_CONFIG".to_owned(), c.display().to_string()));
                }
                if *with_token {
                    let t = cli
                        .server_token
                        .clone()
                        .context("--with-token needs --server-token or FLUXVM_TOKEN")?;
                    env.push(("FLUXVM_TOKEN".to_owned(), t));
                }
                let entry = mcp_install::Entry {
                    command: exe.display().to_string(),
                    args,
                    env,
                };
                Some(mcp_install::install(
                    *client, *project, name, &entry, *dry_run,
                )?)
            }
            McpCommand::Uninstall {
                client,
                project,
                name,
            } => Some(mcp_install::uninstall(*client, *project, name)?),
            McpCommand::Status { project, name } => Some(mcp_install::status(*project, name)?),
        };
        if let Some(out) = out {
            if let (McpCommand::Install { dry_run: true, .. }, Some(snippet)) =
                (command, out.get("entry").and_then(|v| v.as_str()))
            {
                eprintln!("# {}", out["path"].as_str().unwrap_or_default());
                println!("{snippet}");
            } else {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            return Ok(());
        }
    }
    if let Command::Service { command } = &cli.command {
        let out = match command {
            ServiceCommand::Install => {
                let plist = launch_agent::install(cli.config.as_deref())?;
                serde_json::json!({"ok": true, "plist": plist, "label": launch_agent::LABEL})
            }
            ServiceCommand::Uninstall => {
                serde_json::json!({"ok": true, "removed": launch_agent::uninstall()?})
            }
            ServiceCommand::Status => launch_agent::status()?,
        };
        println!("{}", serde_json::to_string_pretty(&out)?);
        return Ok(());
    }
    let format = cli.output;
    if let Command::Mcp {
        command: McpCommand::Serve { allow_write },
    } = &cli.command
    {
        let remote = match remote::endpoint(
            cli.server.clone(),
            cli.server_token.clone(),
            cli.context.as_deref(),
        )? {
            Some(r) => r,
            None => {
                let cfg = Config::load(cli.config.as_deref())?;
                remote::Remote::new(&cfg.listen, cli.server_token.clone())
            }
        };
        return mcp::serve(remote, *allow_write).await;
    }
    if let Command::Context { command } = cli.command {
        return run_context(command, format);
    }
    if let Command::Dashboard { no_open } = cli.command {
        let base = match remote::endpoint(cli.server.clone(), None, cli.context.as_deref())? {
            Some(r) => r.base().to_owned(),
            None => {
                let listen = Config::load(cli.config.as_deref())?.listen;
                let listen = listen
                    .replace("0.0.0.0", "127.0.0.1")
                    .replace("[::]", "[::1]");
                remote::Remote::new(&listen, None).base().to_owned()
            }
        };
        let url = format!("{base}/console");
        println!("{url}");
        if !no_open && cfg!(target_os = "macos") {
            std::process::Command::new("/usr/bin/open")
                .arg(&url)
                .status()
                .context("opening the browser")?;
        }
        return Ok(());
    }
    if let Command::Up { fleet, .. } | Command::Down { fleet, .. } | Command::Ps { fleet, .. } =
        &cli.command
        && let Some(central) = fleet.fleet.clone()
    {
        return run_stack_on_fleet(
            &central,
            fleet.fleet_token.clone(),
            cli.server_token.clone(),
            cli.command,
        )
        .await;
    }
    if !matches!(cli.command, Command::Serve)
        && let Some(r) = remote::endpoint(
            cli.server.clone(),
            cli.server_token.clone(),
            cli.context.as_deref(),
        )?
    {
        return run_remote(&r, cli.command, format).await;
    }
    let cfg = Config::load(cli.config.as_deref())?;
    if let Command::Events {
        vm,
        event,
        since,
        limit,
        follow,
    } = &cli.command
    {
        let filter = fluxvm_scheduler::EventFilter {
            vm: *vm,
            since: *since,
            event: event.clone(),
            limit: Some(*limit),
        };
        return print_events(&cfg, format, filter, *follow).await;
    }
    if let Command::Quota {
        token: Some(token), ..
    } = &cli.command
    {
        println!("{}", daemon_get(&cfg, "/v1/quotas/me", Some(token)).await?);
        return Ok(());
    }

    // `status` without an id is the host panel (no write access required).
    // With an id it is machinectl-style VM status and needs the manager.
    if let Command::Status { verbose, id: None } = &cli.command {
        let m = manager(cfg.clone()).await.ok();
        status::print_status(m.as_deref(), &cfg, *verbose).await?;
        return Ok(());
    }
    // Daemon probes talk HTTP to `listen` — no local VmManager / cgroup needed.
    if matches!(
        cli.command,
        Command::Healthz | Command::Readyz | Command::Metrics { .. }
    ) {
        match cli.command {
            Command::Healthz => {
                println!("{}", daemon_get(&cfg, "/healthz", None).await?);
            }
            Command::Readyz => {
                println!("{}", daemon_get(&cfg, "/readyz", None).await?);
            }
            Command::Metrics { token } => {
                print!("{}", daemon_get(&cfg, "/metrics", token.as_deref()).await?);
            }
            _ => unreachable!(),
        }
        return Ok(());
    }

    let m = manager(cfg.clone()).await?;

    match cli.command {
        Command::Status {
            verbose: _,
            id: Some(id),
        } => {
            println!("{}", serde_json::to_string_pretty(&m.get(id).await?)?);
        }
        Command::Status { id: None, .. }
        | Command::Healthz
        | Command::Readyz
        | Command::Metrics { .. }
        | Command::Completions { .. }
        | Command::VsockProxy { .. }
        | Command::ImportCompose { .. }
        | Command::Service { .. }
        | Command::Dashboard { .. }
        | Command::Mcp { .. }
        | Command::Events { .. }
        | Command::Context { .. }
        | Command::Quota { token: Some(_), .. } => unreachable!("handled above"),
        Command::Quota { token: None, name } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.token_quota_usage(name.as_deref()).await?)?
            );
        }
        Command::Restart { target } => run_bulk(&m, target, BulkOp::Restart).await?,
        Command::Label { id, labels } => {
            let patch = fluxvm_core::model::VmPatch {
                name: None,
                labels: labels.into_iter().collect(),
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&m.patch(id, patch).await?)?
            );
        }
        Command::RenameVm { id, new_name } => {
            let patch = fluxvm_core::model::VmPatch {
                name: Some(new_name),
                ..Default::default()
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&m.patch(id, patch).await?)?
            );
        }
        Command::Wait {
            id,
            for_state,
            timeout,
        } => wait_for_vm(&m, id, &for_state, timeout).await?,
        Command::CloneVm { id, new_name } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.clone_vm(id, new_name, None).await?)?
            );
        }
        Command::ForkVm { id, count, prefix } => {
            let items = m.fork_vm(id, count, prefix, None).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"items": items}))?
            );
        }
        Command::SnapshotList { id } => {
            output::print_list(
                format,
                &m.list_vm_snapshots(id).await?,
                output::SNAPSHOT_COLUMNS,
            )?;
        }
        Command::SnapshotDelete { id, tag } => {
            m.delete_vm_snapshot(id, &tag).await?;
            println!("{}", serde_json::json!({"ok": true, "deleted": tag}));
        }
        Command::Serial { id } => run_serial_session(&m, id).await?,
        Command::PortConnect { id, name } => {
            run_stream_session(
                m.open_console_port(id, &name).await?,
                &format!("{id} port {name}"),
            )
            .await?
        }
        Command::VmTemplate { command } => match command {
            TemplateCommand::List => {
                output::print_list(format, &m.list_vm_templates()?, output::TEMPLATE_COLUMNS)?
            }
            TemplateCommand::Show { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.get_vm_template(&name)?)?
                )
            }
            TemplateCommand::Save {
                name,
                spec,
                from_vm,
                description,
                replace,
            } => {
                let req = match (spec, from_vm) {
                    (Some(p), _) => fluxvm_scheduler::templates::spec_from_json(
                        &name,
                        serde_json::from_slice(&std::fs::read(p)?)?,
                    )?,
                    (None, Some(id)) => m.get(id).await?.request,
                    (None, None) => unreachable!("clap requires --spec or --from-vm"),
                };
                let t = m.save_vm_template(&name, description, req, replace).await?;
                println!("{}", serde_json::to_string_pretty(&t)?);
            }
            TemplateCommand::Delete { name } => {
                m.delete_vm_template(&name).await?;
                println!("{}", serde_json::json!({"ok": true, "deleted": name}));
            }
            TemplateCommand::Create {
                template,
                vm_name,
                labels,
            } => {
                let mut vm = m
                    .create(m.vm_template_request(&template, &vm_name)?)
                    .await?;
                if !labels.is_empty() {
                    vm = m
                        .patch(
                            vm.id,
                            fluxvm_core::model::VmPatch {
                                name: None,
                                labels: labels.into_iter().map(|(k, v)| (k, Some(v))).collect(),
                            },
                        )
                        .await?;
                }
                println!("{}", serde_json::to_string_pretty(&vm)?);
            }
        },
        Command::Backup {
            id,
            dest,
            name,
            compress,
            all_disks,
            quiesce,
        } => {
            let opts = fluxvm_core::model::BackupOptions {
                dest,
                name,
                compress,
                all_disks,
                quiesce,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&m.backup_vm(id, opts).await?)?
            )
        }
        Command::Backups => println!("{}", serde_json::to_string_pretty(&m.list_backups())?),
        Command::BackupDelete { name } => {
            m.delete_backup(&name)?;
            println!("{}", serde_json::json!({"ok": true, "deleted": name}));
        }
        Command::RestoreBackup { id, name } => println!(
            "{}",
            serde_json::to_string_pretty(&m.restore_backup(id, &name).await?)?
        ),
        Command::Disk { command } => match command {
            DiskCommand::List { id } => {
                output::print_list(format, &m.list_vm_disks(id).await?, output::DISK_COLUMNS)?;
            }
            DiskCommand::Attach {
                id,
                name,
                size_gib,
                path,
                backing,
                kind,
                url,
                read_only,
                caching,
                sync,
                controller,
            } => {
                if m.get(id).await?.backend == fluxvm_core::model::BackendKind::Vz {
                    let disk: fluxvm_core::model::AppleDisk = serde_json::from_value(
                        serde_json::json!({
                            "path": path.unwrap_or_default(), "kind": kind.as_deref().unwrap_or("image"),
                            "url": url, "read_only": read_only,
                            "caching": caching.as_deref().unwrap_or("automatic"),
                            "sync": sync.as_deref().unwrap_or("full"),
                            "controller": controller.as_deref().unwrap_or("virtio"),
                        }),
                    )?;
                    let info = m.attach_vz_disk(id, &name, disk, size_gib).await?;
                    println!("{}", serde_json::to_string_pretty(&info)?);
                    return Ok(());
                }
                let info = match (size_gib, path, backing) {
                    (_, Some(path), _) => m.attach_existing_vm_disk(id, &name, &path).await?,
                    (_, None, Some(backing)) => {
                        m.attach_overlay_vm_disk(id, &name, &backing).await?
                    }
                    (Some(size), None, None) => m.attach_vm_disk(id, &name, size).await?,
                    (None, None, None) => anyhow::bail!("set --size-gib, --path or --backing"),
                };
                println!("{}", serde_json::to_string_pretty(&info)?)
            }
            DiskCommand::Resize { id, name, size_gib } => println!(
                "{}",
                serde_json::to_string_pretty(&m.resize_vm_disk(id, &name, size_gib).await?)?
            ),
            DiskCommand::Detach { id, name } => {
                m.detach_vm_disk(id, &name).await?;
                println!("{}", serde_json::json!({"ok": true, "detached": name}));
            }
        },
        Command::Serve => {
            if cfg.auth.must_authenticate(&cfg.listen) && !cfg.auth.has_credentials() {
                anyhow::bail!(
                    "auth is required for listen={} but no [[auth.tokens]] and OIDC is not \
                     configured — add tokens, set auth.oidc_issuer+oidc_audience, or bind \
                     127.0.0.1 / set auth.require=false for loopback-only lab use",
                    cfg.listen
                );
            }
            if cfg.jailer_required() && !cfg.jailer.enabled {
                anyhow::bail!(
                    "Firecracker jailer is required (jailer.enforce or auth.require on \
                     non-loopback listen={}) but jailer.enabled is false — set \
                     [jailer] enabled = true (and an absolute firecracker_binary), or \
                     clear jailer.enforce / use loopback listen for lab",
                    cfg.listen
                );
            }
            if cfg.jailer.enabled {
                tracing::info!(
                    uid = cfg.jailer.uid,
                    gid = cfg.jailer.gid,
                    "Firecracker jailer enabled"
                );
            }
            m.store.rebuild_quota_ledger().await?;
            m.reap_migration_receivers().await;
            m.sync_receiver_host_quota().await?;
            if !cfg.auth.has_credentials() {
                tracing::warn!(
                    listen = %cfg.listen,
                    "API auth is OFF (no [[auth.tokens]] / OIDC); every request is admin"
                );
            }
            if cfg.auth.oidc_enabled() {
                tracing::info!(
                    issuer = ?cfg.auth.oidc_issuer,
                    audience = ?cfg.auth.oidc_audience,
                    "OIDC bearer JWT validation enabled alongside static tokens"
                );
            } else if cfg.auth.oidc_issuer.is_some() {
                tracing::warn!("auth.oidc_issuer set without auth.oidc_audience — OIDC disabled");
            }
            if let Some((rps, burst)) = cfg.auth.rate_limit_enabled() {
                tracing::info!(rps, burst, "REST API rate limiting enabled");
            } else if cfg.auth.rate_limit_rps.is_some() != cfg.auth.rate_limit_burst.is_some() {
                tracing::warn!(
                    "auth.rate_limit_rps and auth.rate_limit_burst must both be set — rate limiting disabled"
                );
            }
            m.start_reaper();
            m.spawn_autopause_loop();
            m.start_autostart_vms().await;
            if !cfg.sandbox.egress_proxy_listen.is_empty() {
                let addr: std::net::SocketAddr = cfg.sandbox.egress_proxy_listen.parse()?;
                if let Err(e) = fluxvm_network::egress::apply_egress_redirect(addr.port()) {
                    tracing::warn!(error = %e, "egress redirect nftables apply failed");
                }
                let sandbox_cfg = cfg.sandbox.clone();
                tokio::spawn(async move {
                    if let Err(e) = fluxvm_network::egress_proxy::serve(addr, sandbox_cfg).await {
                        tracing::error!(error = %e, "egress proxy exited");
                    }
                });
            }
            #[cfg(target_os = "macos")]
            api::self_control::spawn(m.clone(), &cfg.state_dir);
            let app = api::router(m);
            if cfg.tls.enabled() {
                // rustls 0.23: select a process-wide CryptoProvider (ring) before
                // any ServerConfig / axum-server TLS bind.
                let _ = rustls::crypto::ring::default_provider().install_default();
                let addr: std::net::SocketAddr = cfg.listen.parse()?;
                let cert = cfg.tls.cert.clone().unwrap();
                let key = cfg.tls.key.clone().unwrap();
                let rustls_config = if let Some(ca) = cfg.tls.client_ca.clone() {
                    build_mtls_config(&cert, &key, &ca).await?
                } else {
                    axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert, &key)
                        .await
                        .context("loading TLS cert/key")?
                };
                tracing::info!(
                    listen = %cfg.listen,
                    mtls = cfg.tls.mtls_enabled(),
                    "API listening (TLS)"
                );
                axum_server::bind_rustls(addr, rustls_config)
                    .serve(app.into_make_service())
                    .await?;
            } else {
                let listener = TcpListener::bind(&cfg.listen).await?;
                tracing::info!(listen=%cfg.listen, "API listening");
                axum::serve(listener, app).await?;
            }
        }
        Command::Create(args) => {
            let req: CreateVmRequest = serde_json::from_value(create::create_body(&args)?)?;
            println!("{}", serde_json::to_string_pretty(&m.create(req).await?)?);
        }
        Command::List { selector, all } => {
            let mut items = m.list().await;
            items.retain(|vm| fluxvm_scheduler::vm_listed(vm, all, selector.as_deref()));
            if let Some(sel) = selector.as_deref() {
                let sel = fluxvm_core::model::LabelSelector::parse(sel)?;
                items.retain(|vm| sel.matches(&vm.labels));
            }
            output::print_list(format, &items, output::VM_COLUMNS)?
        }
        Command::Get { id } => println!("{}", serde_json::to_string_pretty(&m.get(id).await?)?),
        Command::Diagnose { id } => {
            let vm = m.get(id).await?;
            let pin_root = std::env::var("FLUXVM_INTEL_PIN_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| fluxvm_intelligence::DEFAULT_PIN_ROOT.into());
            let snapshot = fluxvm_intelligence::snapshot_record(&vm, &pin_root)?;
            let effective = m.network_effective(id).await?;
            let policy: fluxvm_network::dataplane::VmNetworkPolicy = serde_json::from_value(
                effective
                    .get("effective")
                    .cloned()
                    .context("network/effective response has no effective policy")?,
            )?;
            let pod_policy = m.pod_network_policy(id).await?;
            let flows = m.network_flows(id, 256).await?;
            let reasons = fluxvm_network::ebpf::drop_reasons(&m.cfg.sandbox.dataplane, id, 256)
                .unwrap_or_default();
            let report = fluxvm_intelligence::diagnose_vm_with_reasons(
                &snapshot,
                &policy,
                pod_policy.as_ref(),
                &flows,
                &reasons,
            );
            println!("{}", serde_json::to_string_pretty(&report)?);
        }
        Command::Trace {
            id,
            seconds,
            limit,
            output,
        } => {
            m.get(id).await?;
            let pin_root = std::env::var("FLUXVM_INTEL_PIN_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(|_| fluxvm_intelligence::DEFAULT_PIN_ROOT.into());
            let events = fluxvm_intelligence::trace_events(id, &pin_root, seconds, limit)?;
            match output.to_ascii_lowercase().as_str() {
                "json" => println!("{}", serde_json::to_string_pretty(&events)?),
                "jsonl" => {
                    for event in events {
                        println!("{}", serde_json::to_string(&event)?);
                    }
                }
                other => anyhow::bail!("unsupported trace output {other:?}; use json or jsonl"),
            }
        }
        Command::Start { target } => run_bulk(&m, target, BulkOp::Start).await?,
        Command::Stop { target } => run_bulk(&m, target, BulkOp::Stop).await?,
        Command::Pause { id } => println!("{}", serde_json::to_string_pretty(&m.pause(id).await?)?),
        Command::Resume { id } => {
            println!("{}", serde_json::to_string_pretty(&m.resume(id).await?)?)
        }
        Command::Freeze { id } => {
            m.freeze(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::Thaw { id } => {
            m.thaw(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::Frozen { id } => {
            let frozen = m.is_frozen(id).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"frozen": frozen}))?
            );
        }
        Command::Resources {
            id,
            cpu_quota_percent,
            memory_max_bytes,
            io_weight,
            pids_max,
            cpuset_cpus,
        } => {
            if cpu_quota_percent.is_none()
                && memory_max_bytes.is_none()
                && io_weight.is_none()
                && pids_max.is_none()
                && cpuset_cpus.is_none()
            {
                anyhow::bail!(
                    "no fields to update; pass at least one of --cpu-quota-percent, \
                     --memory-max-bytes, --io-weight, --pids-max, --cpuset-cpus"
                );
            }
            let cpuset_cpus = cpuset_cpus.map(|s| parse_cpuset_spec(&s)).transpose()?;
            m.set_resources(
                id,
                ResourcePatch {
                    cpu_quota_percent,
                    memory_max_bytes,
                    io_weight,
                    pids_max,
                    cpuset_cpus,
                },
            )
            .await?;
            println!("{{\"ok\":true}}");
        }
        Command::Cpuset { id } => {
            let cpus = m.get_cpuset(id).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"cpus": cpus}))?
            );
        }
        Command::Stats { id } => {
            println!("{}", serde_json::to_string_pretty(&m.metrics(id).await?)?);
        }
        Command::Pressure { id } => {
            println!("{}", serde_json::to_string_pretty(&m.pressure(id).await?)?);
        }
        Command::Vz { command } => {
            let out = match command {
                VzCommand::Host => fluxvm_scheduler::vz_devices::apple_host_capabilities().await?,
                VzCommand::Ipsw { download } => m.macos_ipsw(download).await?,
                VzCommand::SecureBoot { id } => m.vz_secure_boot_status(id).await?,
                VzCommand::CustomVirtio { id, reset: true } => {
                    m.vz_custom_virtio_reset(id).await?;
                    serde_json::json!({"ok": true})
                }
                VzCommand::CustomVirtio { id, reset: false } => {
                    m.vz_custom_virtio_status(id).await?
                }
                VzCommand::Usb {
                    id,
                    physical: true,
                    attach: Some(registry_id),
                } => {
                    serde_json::json!({"uuid": m.vz_usb_physical_attach(id, registry_id).await?})
                }
                VzCommand::Usb {
                    id, physical: true, ..
                } => serde_json::json!({"items": m.vz_usb_physical_list(id).await?}),
                VzCommand::Usb { id, .. } => serde_json::json!({"items": m.vz_usb_list(id).await?}),
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::Balloon { id, set_mib } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.balloon_control(id, set_mib).await?)?
            );
        }
        Command::Memory { id } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.vm_memory_report(id).await?)?
            );
        }
        Command::Screenshot {
            id,
            output,
            max_width,
        } => {
            let shot = m.vm_screenshot(id, max_width).await?;
            std::fs::write(&output, &shot.png)
                .with_context(|| format!("writing {}", output.display()))?;
            println!("{}", output.display());
        }
        Command::Signin { command } => {
            let v = match command {
                SigninCommand::Set { id, username } => {
                    let password = read_secret("password: ")?;
                    serde_json::to_value(m.set_vm_signin(id, username, password).await?)?
                }
                SigninCommand::Status { id } => {
                    serde_json::to_value(m.vm_signin_status(id).await?)?
                }
                SigninCommand::Clear { id } => {
                    m.get(id).await?;
                    serde_json::json!({"deleted": m.delete_vm_signin(id).await?})
                }
                SigninCommand::Type {
                    id,
                    mode,
                    no_submit,
                } => {
                    let mode: fluxvm_scheduler::vz_screen::SigninMode =
                        serde_json::from_value(serde_json::Value::String(mode))
                            .context("--mode must be password, username or username_tab")?;
                    m.vm_signin(id, mode, !no_submit).await?;
                    serde_json::json!({"ok": true})
                }
            };
            println!("{}", serde_json::to_string_pretty(&v)?);
        }
        Command::Input { id, actions, text } => {
            let actions: Vec<fluxvm_scheduler::vz_screen::InputAction> =
                serde_json::from_value(serde_json::Value::Array(input_actions(&actions, text)?))
                    .context("invalid input action")?;
            let n = m.vm_input(id, &actions).await?;
            println!("{}", serde_json::json!({"ok": true, "actions": n}));
        }
        Command::Hotplug { command } => match command {
            HotplugCommand::Cpu { id, add_vcpus } => {
                let vcpus = m.hotplug_cpu(id, add_vcpus).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({"vcpus": vcpus}))?
                );
            }
            HotplugCommand::Memory { id, add_memory_mib } => {
                let memory_mib = m.hotplug_memory(id, add_memory_mib).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({"memory_mib": memory_mib}))?
                );
            }
            HotplugCommand::Nic {
                id,
                bridge,
                mac,
                outer,
                netns_path,
                mode,
                guest_ip,
            } => {
                match (bridge.as_deref(), outer.as_deref()) {
                    (None, None) => {
                        anyhow::bail!("hotplug nic needs either --bridge or --outer")
                    }
                    (Some(_), Some(_)) => {
                        anyhow::bail!("--bridge and --outer are mutually exclusive")
                    }
                    (Some(bridge), None) => {
                        if netns_path.is_some() || !guest_ip.is_empty() || mode != "peer-veth" {
                            anyhow::bail!("--netns-path/--guest-ip/--mode apply only with --outer");
                        }
                        m.hotplug_nic(id, bridge.to_string(), mac).await?;
                    }
                    (None, Some(outer)) => {
                        let mode = match mode.as_str() {
                            "peer-veth" => DirectMode::PeerVeth,
                            "l2-uplink" => DirectMode::L2Uplink,
                            other => anyhow::bail!(
                                "unsupported direct mode {other:?}; use peer-veth or l2-uplink"
                            ),
                        };
                        let direct = DirectSpec {
                            outer: outer.to_string(),
                            netns_path,
                            mode,
                            guest_ips: guest_ip,
                        };
                        direct
                            .validate()
                            .map_err(|e| anyhow::anyhow!("invalid direct nic: {e}"))?;
                        m.hotplug_direct_nic(id, direct, mac).await?;
                    }
                }
                println!("{{\"ok\":true}}");
            }
            HotplugCommand::NicUnplug { id, mac, tap } => {
                let req = fluxvm_core::model::UnplugNicRequest { mac, tap };
                req.validate().map_err(|e| anyhow::anyhow!(e))?;
                m.unplug_nic(id, &req).await?;
                println!("{{\"ok\":true}}");
            }
            HotplugCommand::Share {
                id,
                host_path,
                read_only,
            } => {
                if !host_path.is_absolute() {
                    anyhow::bail!("--host-path must be absolute");
                }
                let tag = m.hotplug_share(id, host_path, read_only).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({"tag": tag}))?
                );
            }
        },
        Command::Snapshot { id, tag } => {
            m.create_vm_snapshot(id, &tag).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"ok": true, "tag": tag}))?
            );
        }
        Command::StartFromSnapshot { id, tag } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.start_from_snapshot(id, &tag).await?)?
            );
        }
        Command::Console {
            id,
            cols,
            rows,
            command,
        } => {
            if !command.is_empty() {
                let response = m.exec(id, command.join(" "), None).await?;
                println!("{}", serde_json::to_string_pretty(&response)?);
            } else {
                run_console_session(&m, id, cols, rows).await?;
            }
        }
        Command::Up { file, services, .. } => {
            let (f, dir) = load_stack_file(&file)?;
            let only = (!services.is_empty()).then_some(services.as_slice());
            stack::up(&run::Local(&m), &f, &dir, only).await?;
        }
        Command::Down {
            file,
            stack: name,
            keep,
            ..
        } => {
            let f = stack_for(&file, name.as_deref())?;
            let name =
                name.unwrap_or_else(|| f.as_ref().map(|f| f.name.clone()).unwrap_or_default());
            stack::down(&run::Local(&m), &name, f.as_ref(), keep).await?;
        }
        Command::Ps {
            file, stack: name, ..
        } => {
            let f = stack_for(&file, name.as_deref())?;
            let name =
                name.unwrap_or_else(|| f.as_ref().map(|f| f.name.clone()).unwrap_or_default());
            for [svc, vm, status, ip] in stack::ps(&run::Local(&m), &name).await? {
                println!("{svc:<16} {vm:<28} {status:<10} {ip}");
            }
        }
        Command::Run {
            image,
            name,
            cpus,
            memory_mib,
            ports,
            volumes,
            user,
            keep,
            no_warm,
            command,
        } => {
            let code = run::run(
                &run::Local(&m),
                run::RunOptions {
                    image,
                    name,
                    cpus,
                    memory_mib,
                    ports,
                    volumes,
                    user,
                    keep,
                    no_warm,
                    command,
                },
            )
            .await?;
            std::process::exit(code);
        }
        Command::Ssh {
            id,
            user,
            port,
            ssh_args,
        } => {
            let vm = m.get(id).await?;
            let ip = vm.guest_ip.as_deref().context(
                "VM has no guest_ip yet — wait for DHCP/lease, or use `console`/`login` over vsock",
            )?;
            let user = user
                .or_else(|| vm.request.cloud_init.as_ref().and_then(|c| c.user.clone()))
                .unwrap_or_else(|| "root".into());
            run::ssh_to(ip, &user, port, vm.backend == BackendKind::Vz, &ssh_args).await?;
        }
        Command::Show { id } => {
            println!("{}", serde_json::to_string_pretty(&m.get(id).await?)?);
        }
        Command::Poweroff { id } => {
            m.agent_poweroff(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::Reboot { id } => {
            m.agent_reboot(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::Kill { id } => {
            println!("{}", serde_json::to_string_pretty(&m.kill(id).await?)?);
        }
        Command::Bind {
            id,
            host_path,
            read_only,
        } => {
            if !host_path.is_absolute() {
                anyhow::bail!("host_path must be absolute");
            }
            let tag = m.hotplug_share(id, host_path, read_only).await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"tag": tag}))?
            );
        }
        Command::Enable { id } => {
            m.enable(id).await?;
            println!("{{\"ok\":true,\"enabled\":true}}");
        }
        Command::Disable { id } => {
            m.disable(id).await?;
            println!("{{\"ok\":true,\"enabled\":false}}");
        }
        Command::Logs { id, lines, follow } => {
            let vm = m.get(id).await?;
            tail_vm_log(&vm.log_path, lines.max(1), follow).await?;
        }
        Command::Exec {
            id,
            timeout_seconds,
            policy,
            command,
        } => {
            let policy = match policy {
                Some(path) => {
                    let text = std::fs::read_to_string(&path)
                        .with_context(|| format!("reading policy {}", path.display()))?;
                    Some(
                        fluxvm_scheduler::guest_exec::parse_exec_policy(&text)
                            .with_context(|| format!("parsing policy {}", path.display()))?,
                    )
                }
                None => None,
            };
            let response = m
                .exec_with_policy(id, command.join(" "), timeout_seconds, policy)
                .await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::Ping { id } => {
            m.agent_ping(id).await?;
            println!("{{\"ok\":true}}");
        }
        Command::CopyTo {
            id,
            local,
            remote,
            mode,
        } => {
            let bytes = read_local_file_for_copy_to(&local)?;
            let response = m.put_file(id, remote, B64.encode(&bytes), mode).await?;
            println!("{}", serde_json::to_string_pretty(&response)?);
        }
        Command::CopyFrom { id, remote, local } => match m.get_file(id, remote).await? {
            AgentResponse::FileContent {
                content_base64,
                mode,
            } => {
                let n = write_copy_from_response(&local, &content_base64, mode)?;
                println!("{{\"ok\":true,\"bytes\":{n}}}");
            }
            AgentResponse::Error { message } => anyhow::bail!("guest agent error: {message}"),
            other => anyhow::bail!("unexpected response to get-file: {other:?}"),
        },
        Command::Migrate { command } => match command {
            MigrateCommand::Start {
                id,
                destination,
                mode,
                bandwidth_mbps,
                max_downtime_ms,
                multifd_channels,
            } => {
                let request = MigrationStartRequest {
                    destination,
                    mode: parse_migration_mode(&mode)?,
                    bandwidth_mbps,
                    max_downtime_ms,
                    multifd_channels,
                    tls: None,
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.start_migration(id, &request).await?)?
                );
            }
            MigrateCommand::Status { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.migration_status(id).await?)?
                );
            }
            MigrateCommand::Cancel { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.cancel_migration(id).await?)?
                );
            }
            MigrateCommand::Receiver { command } => match command {
                MigrateReceiverCommand::Create {
                    disk,
                    disk_format,
                    vcpus,
                    memory_mib,
                    cpu_model,
                    machine,
                    listen_host,
                    advertise_host,
                    listen_port,
                    expires_in_seconds,
                } => {
                    let request = MigrationReceiverRequest {
                        vcpus,
                        memory_mib,
                        cpu_model,
                        machine,
                        disk,
                        disk_format,
                        listen_host,
                        advertise_host,
                        listen_port,
                        expires_in_seconds,
                        tls: None,
                        record: None,
                    };
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&m.create_migration_receiver(request).await?)?
                    );
                }
                MigrateReceiverCommand::Activate { id, token } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &m.activate_migration_receiver(id, &token).await?
                        )?
                    );
                }
                MigrateReceiverCommand::Delete { id } => {
                    m.delete_migration_receiver(id).await?;
                    println!("{{\"ok\":true}}");
                }
            },
        },
        Command::Sandbox { command } => match command {
            SandboxCommand::Create { spec } => {
                let req: SandboxCreateRequest = serde_json::from_slice(&std::fs::read(spec)?)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.create_sandbox(req, None, None).await?)?
                );
            }
            SandboxCommand::List => {
                let items: Vec<_> = m
                    .list()
                    .await
                    .into_iter()
                    .filter(|v| {
                        v.backend == BackendKind::FluxVm
                            || v.workspace.join("sandbox-proxy.json").exists()
                    })
                    .collect();
                output::print_list(format, &items, output::VM_COLUMNS)?;
            }
            SandboxCommand::Run(args) => {
                let code = sandbox_run::run(sandbox_run::Target::Local(&m), &args).await?;
                std::process::exit(code);
            }
            SandboxCommand::Logs { id, lines } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.sandbox_logs(id, lines).await?)?
                );
            }
            SandboxCommand::Warm { .. } => {
                anyhow::bail!(
                    "sandbox warm fills the pool in the daemon's background: use --server"
                )
            }
            SandboxCommand::Density => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.sandbox_density().await)?
                );
            }
            SandboxCommand::Snapshot { id, path } => {
                m.snapshot_sandbox(id, &path).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "ok": true,
                        "path": path,
                    }))?
                );
            }
            SandboxCommand::FsRead { id, path } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.get_file(id, path).await?)?
                );
            }
            SandboxCommand::FsWrite {
                id,
                path,
                local,
                mode,
            } => {
                let bytes = std::fs::read(&local)
                    .with_context(|| format!("reading {}", local.display()))?;
                let response = m.put_file(id, path, B64.encode(&bytes), mode).await?;
                println!("{}", serde_json::to_string_pretty(&response)?);
            }
            SandboxCommand::Process {
                id,
                timeout_seconds,
                command,
            } => {
                let cmd = command.join(" ");
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.exec(id, cmd, timeout_seconds).await?)?
                );
            }
            SandboxCommand::Speculate {
                id,
                timeout_seconds,
                paths,
                ttl_seconds,
                command,
            } => {
                let paths = (!paths.is_empty()).then_some(paths);
                let cs = m
                    .speculate(id, command.join(" "), timeout_seconds, paths, ttl_seconds)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&cs)?);
            }
            SandboxCommand::Changesets { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.changeset_list(id).await?)?
                );
            }
            SandboxCommand::Changeset { id, cs } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.changeset_get(id, cs).await?)?
                );
            }
            SandboxCommand::Approve { id, cs } => {
                let out = m
                    .changeset_decide(
                        id,
                        cs,
                        fluxvm_scheduler::speculate::ChangesetState::Approved,
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            SandboxCommand::Reject { id, cs } => {
                let out = m
                    .changeset_decide(
                        id,
                        cs,
                        fluxvm_scheduler::speculate::ChangesetState::Rejected,
                    )
                    .await?;
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            SandboxCommand::Apply { id, cs } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.changeset_apply(id, cs).await?)?
                );
            }
        },
        Command::Qga { command } => match command {
            QgaCommand::Ping { id } => {
                m.qga_ping(id).await?;
                println!("{{\"ok\":true}}");
            }
            QgaCommand::Powershell {
                id,
                timeout_seconds,
                command,
            } => {
                let result = m
                    .qga_powershell(id, command.join(" "), timeout_seconds)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            QgaCommand::Exec {
                id,
                path,
                timeout_seconds,
                args,
            } => {
                let result = m.qga_exec(id, path, args, timeout_seconds).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            QgaCommand::FirewallOpen {
                id,
                name,
                port,
                protocol,
                timeout_seconds,
            } => {
                let result = m
                    .qga_firewall_open(id, name, port, protocol, timeout_seconds)
                    .await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
            QgaCommand::FirewallClose {
                id,
                name,
                timeout_seconds,
            } => {
                let result = m.qga_firewall_close(id, name, timeout_seconds).await?;
                println!("{}", serde_json::to_string_pretty(&result)?);
            }
        },
        Command::Delete { target } => run_bulk(&m, target, BulkOp::Delete).await?,
        Command::Terminate { id } => m.delete(id).await?,
        Command::ImportImage {
            source,
            name,
            no_repair,
            remove_vmware_tools,
        } => {
            let req = image::import::ImportRequest {
                source,
                name,
                repair: !no_repair,
                remove_vmware_tools,
            };
            println!(
                "{}",
                serde_json::to_string_pretty(&image::import::import_image(&cfg, &req).await?)?
            );
        }
        Command::BuildImage { spec } => {
            let req: BuildImageRequest = serde_json::from_slice(&std::fs::read(spec)?)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&image::build_image(&cfg, &req).await?)?
            );
        }
        Command::Pool { command } => match command {
            PoolCommand::Create { spec } => {
                let spec: fluxvm_core::model::PoolSpec =
                    serde_json::from_slice(&std::fs::read(spec)?)?;
                let name = spec.name.clone();
                m.create_pool(spec).await?;
                // This CLI process exits right after printing — wait for a
                // real backfill here rather than relying on the background
                // task create_pool() also fires off, which would otherwise
                // get killed mid-flight along with this process (see
                // VmManager::backfill_pool_sync's doc comment).
                m.backfill_pool_sync(&name).await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_core::model::PoolView::from(
                        m.get_pool(&name).await?
                    ))?
                );
            }
            PoolCommand::List => {
                let items: Vec<_> = m
                    .list_pools()
                    .await
                    .into_iter()
                    .map(fluxvm_core::model::PoolView::from)
                    .collect();
                println!("{}", serde_json::to_string_pretty(&items)?)
            }
            PoolCommand::Get { name } => println!(
                "{}",
                serde_json::to_string_pretty(&fluxvm_core::model::PoolView::from(
                    m.get_pool(&name).await?
                ))?
            ),
            PoolCommand::Claim {
                name,
                vm_name,
                ttl_seconds,
            } => {
                let overrides = ClaimOverrides {
                    name: vm_name,
                    ttl_seconds,
                    pod_uid: None,
                };
                println!(
                    "{}",
                    // No token/tenant concept for this local CLI -- same
                    // untenanted-admin posture every other m.<mutate>()
                    // call in this file already has.
                    serde_json::to_string_pretty(
                        &m.claim_from_pool(&name, overrides, None).await?
                    )?
                );
            }
            PoolCommand::Resize { name, size } => {
                let before = m.get_pool(&name).await?.size;
                m.resize_pool(&name, size).await?;
                if size > before {
                    // Same reasoning as `pool create`'s own call: this
                    // process exits right after printing, which would
                    // otherwise take resize_pool's own background backfill
                    // down with it before the pool actually reaches its
                    // new (larger) size.
                    m.backfill_pool_sync(&name).await?;
                }
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_core::model::PoolView::from(
                        m.get_pool(&name).await?
                    ))?
                );
            }
            PoolCommand::Delete { name } => m.delete_pool(&name).await?,
        },
        Command::Cnp { command } => match command {
            CnpCommand::List => {
                println!("{}", serde_json::to_string_pretty(&m.list_cnp().await?)?);
            }
            CnpCommand::Get { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.get_cnp(&name).await?)?
                );
            }
            CnpCommand::Apply { spec } => {
                let raw = std::fs::read_to_string(&spec)?;
                let policy: fluxvm_network::cnp::CiliumNetworkPolicy = serde_json::from_str(&raw)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.apply_cnp(policy).await?)?
                );
            }
            CnpCommand::Delete { name } => {
                m.delete_cnp(&name).await?;
                println!("{{\"deleted\":\"ok\"}}");
            }
        },
        Command::Hubble { command } => match command {
            HubbleCommand::Observe {
                output,
                detailed,
                limit,
                verdict,
                protocol,
            } => {
                print_hubble_observe(&m, &output, detailed, limit, &verdict, &protocol).await?;
            }
            HubbleCommand::Flow {
                output,
                limit,
                verdict,
                protocol,
            } => {
                print_hubble_observe(&m, &output, true, limit, &verdict, &protocol).await?;
            }
            HubbleCommand::Endpoints => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_endpoints().await?)?
                );
            }
        },
        Command::Observe => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.network_observe().await?)?
            );
        }
        Command::Dataplane { command } => match command {
            DataplaneCommand::Health => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_health().await?)?
                );
            }
            DataplaneCommand::Ipcache => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_ipcache().await?)?
                );
            }
            DataplaneCommand::IpamStatus => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_ipam_status().await?)?
                );
            }
            DataplaneCommand::RefreshDns => {
                let n = m.refresh_fqdn_policies().await?;
                println!("{{\"refreshed\":{n}}}");
            }
            DataplaneCommand::MigrationState { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_network::migration_state::status(
                        &m.cfg, id
                    )?)?
                );
            }
            DataplaneCommand::MigrationQuiesce { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_network::migration_state::quiesce(
                        &m.cfg, id
                    )?)?
                );
            }
            DataplaneCommand::MigrationExport { id, output } => {
                let snapshot = fluxvm_network::migration_state::export_snapshot(&m.cfg, id)?;
                let encoded = serde_json::to_vec_pretty(&snapshot)?;
                if let Some(path) = output {
                    std::fs::write(path, &encoded)?;
                } else {
                    println!("{}", String::from_utf8(encoded)?);
                }
            }
            DataplaneCommand::MigrationRestore { id, input } => {
                let snapshot: fluxvm_network::migration_state::VmNetworkStateSnapshot =
                    serde_json::from_slice(&std::fs::read(input)?)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &fluxvm_network::migration_state::restore_snapshot(&m.cfg, id, &snapshot)?
                    )?
                );
            }
            DataplaneCommand::MigrationResume { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&fluxvm_network::migration_state::resume(
                        &m.cfg, id
                    )?)?
                );
            }
        },
        Command::Identity { command } => match command {
            IdentityCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.list_identities().await?)?
                );
            }
        },
        Command::Network { command } => match command {
            NetworkCommand::Policy { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_policy(id).await?)?
                );
            }
            NetworkCommand::SetPolicy { id, spec } => {
                let policy: fluxvm_network::dataplane::VmNetworkPolicy =
                    serde_json::from_slice(&std::fs::read(spec)?)?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.set_network_policy(id, policy).await?)?
                );
            }
            NetworkCommand::Effective { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_effective(id).await?)?
                );
            }
            NetworkCommand::Status { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_status(id).await?)?
                );
            }
            NetworkCommand::Stats { id } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.network_stats(id).await?)?
                );
            }
            NetworkCommand::Flows { id, limit } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "items": m.network_flows(id, limit).await?
                    }))?
                );
            }
        },
        Command::Group { command } => match command {
            GroupCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.list_network_groups().await?)?
                );
            }
            GroupCommand::Get { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.get_network_group(&name).await?)?
                );
            }
            GroupCommand::Set {
                name,
                label,
                allow_cidr,
                deny_cidr,
                allow_port,
                default_allow,
                allow_icmp,
                priority,
                description,
                max_egress_mbps,
                max_egress_pps,
            } => {
                let group = fluxvm_network::groups::SecurityGroup {
                    name,
                    labels: label,
                    policy: fluxvm_network::dataplane::VmNetworkPolicy {
                        default_allow: default_allow.unwrap_or(true),
                        allow_cidrs: allow_cidr,
                        deny_cidrs: deny_cidr,
                        allow_ports: allow_port,
                        allow_icmp,
                        max_egress_mbps,
                        max_egress_pps,
                        ..Default::default()
                    },
                    identity: 0,
                    priority: priority.unwrap_or(100),
                    description: description.unwrap_or_default(),
                };
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.upsert_network_group(group).await?)?
                );
            }
            GroupCommand::Delete { name } => {
                m.delete_network_group(&name).await?;
                println!("{{\"deleted\":\"ok\"}}");
            }
        },
        Command::Vznet {
            command: VznetCommand::Ls { json },
        } => print_vznets(&serde_json::to_value(m.vznets(None).await)?, json)?,
        Command::Oci { command } => {
            let out = match command {
                OciCommand::Pull { image, platform } => {
                    serde_json::to_value(m.oci_pull(&image, platform.as_deref()).await?)?
                }
                OciCommand::Ls => serde_json::to_value(m.oci_list()?)?,
                OciCommand::Rm { image } => serde_json::json!({"removed": m.oci_remove(&image)?}),
                OciCommand::Prune => serde_json::to_value(m.oci_prune().await?)?,
            };
            println!("{}", serde_json::to_string_pretty(&out)?);
        }
        Command::Catalog { command } => match command {
            CatalogCommand::Keygen => {
                let (private_b64, public_b64) = image::catalog::generate_keypair();
                println!(
                    "private key (keep secret, use with `catalog sign --key`):\n  {private_b64}"
                );
                println!(
                    "public key -- add as [[catalog.trusted_signers]] with a name:\n  [[catalog.trusted_signers]]\n  name = \"CHANGE_ME\"\n  public_key = \"{public_b64}\""
                );
            }
            CatalogCommand::Sign {
                key,
                name,
                source,
                sha256,
                format,
                distro,
                version,
                arch,
                build_pipeline,
                build_run_id,
                build_commit,
                catalog_file,
            } => {
                let entry = image::catalog::sign_entry(
                    &key,
                    name,
                    source,
                    sha256,
                    format,
                    distro,
                    version,
                    arch,
                    build_pipeline,
                    build_run_id,
                    build_commit,
                )?;
                match catalog_file {
                    Some(path) => {
                        let mut entries: Vec<image::catalog::CatalogEntry> = if path.exists() {
                            serde_json::from_slice(&std::fs::read(&path)?)?
                        } else {
                            Vec::new()
                        };
                        entries.retain(|e| e.name != entry.name);
                        entries.push(entry);
                        std::fs::write(&path, serde_json::to_vec_pretty(&entries)?)?;
                        println!("{}", serde_json::to_string_pretty(&entries)?);
                    }
                    None => println!("{}", serde_json::to_string_pretty(&entry)?),
                }
            }
            CatalogCommand::List => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&image::catalog::list_with_verification(&cfg)?)?
                );
            }
            CatalogCommand::Add {
                name,
                source,
                format,
            } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &m.add_catalog_entry(name, source, format).await?
                    )?
                );
            }
            CatalogCommand::Remove { name } => {
                m.remove_catalog_entry(&name).await?;
                println!("{}", serde_json::json!({"removed": name}));
            }
            CatalogCommand::Rename { name, new_name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.rename_catalog_entry(&name, &new_name).await?)?
                );
            }
            CatalogCommand::Clone { name, target_name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &m.clone_catalog_entry(&name, &target_name).await?
                    )?
                );
            }
            CatalogCommand::Export { name, dest } => {
                m.export_catalog_entry(&name, &dest).await?;
                println!("{}", serde_json::json!({"exported": dest}));
            }
            CatalogCommand::Lock { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.set_catalog_read_only(&name, true).await?)?
                );
            }
            CatalogCommand::Unlock { name } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&m.set_catalog_read_only(&name, false).await?)?
                );
            }
            CatalogCommand::Clean => {
                let removed = m.clean_catalog_downloads().await?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({"removed": removed}))?
                );
            }
        },
        Command::ListImages => {
            output::print_list(
                format,
                &image::catalog::list_with_verification(&cfg)?,
                output::IMAGE_COLUMNS,
            )?;
        }
        Command::ImageStatus { name } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.get_catalog_entry(&name).await?)?
            );
        }
        Command::Clone { name, new_name } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.clone_catalog_entry(&name, &new_name).await?)?
            );
        }
        Command::Rename { name, new_name } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.rename_catalog_entry(&name, &new_name).await?)?
            );
        }
        Command::ReadOnly { name, off } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.set_catalog_read_only(&name, !off).await?)?
            );
        }
        Command::Remove { name } => {
            m.remove_catalog_entry(&name).await?;
            println!("{{\"ok\":true}}");
        }
        Command::Clean => {
            let removed = m.clean_catalog_downloads().await?;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::json!({"removed": removed}))?
            );
        }
        Command::PullRaw {
            name,
            source,
            format,
        }
        | Command::ImportRaw {
            name,
            source,
            format,
        } => {
            println!(
                "{}",
                serde_json::to_string_pretty(&m.add_catalog_entry(name, source, format).await?)?
            );
        }
        Command::ExportRaw { name, dest } => {
            m.export_catalog_entry(&name, &dest).await?;
            println!("{}", serde_json::json!({"exported": dest}));
        }
        Command::PullTar { .. }
        | Command::ImportTar { .. }
        | Command::ImportFs { .. }
        | Command::ExportTar { .. } => {
            anyhow::bail!(
                "tar/fs image transport is not supported; use pull-raw / import-raw / export-raw \
                 (qcow2 or raw disk images)"
            );
        }
        Command::ListTransfers => {
            println!("{{\"items\":[]}}");
        }
        Command::CancelTransfer { .. } => {
            anyhow::bail!(
                "no async image transfers to cancel (catalog pulls/imports are synchronous)"
            );
        }
        Command::Edit { .. } => {
            anyhow::bail!(
                "edit is not applicable; use `resources`/`set-limit` for cgroup limits, \
                 or recreate from an updated JSON spec"
            );
        }
        Command::Fleet {
            central,
            token,
            command,
        } => {
            let token = token.as_deref();
            match command {
                FleetCommand::Nodes => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::list_nodes(&central, token).await?
                        )?
                    );
                }
                FleetCommand::Node { name } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::get_node(&central, token, &name).await?
                        )?
                    );
                }
                FleetCommand::Cordon { name } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::cordon(&central, token, &name).await?
                        )?
                    );
                }
                FleetCommand::Uncordon { name } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::uncordon(&central, token, &name).await?
                        )?
                    );
                }
                FleetCommand::Deregister { name } => {
                    fleet_client::deregister(&central, token, &name).await?;
                    println!("{{\"ok\":true}}");
                }
                FleetCommand::Capacity => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::capacity(&central, token).await?
                        )?
                    );
                }
                FleetCommand::Create {
                    spec,
                    node,
                    node_selector,
                } => {
                    let body: serde_json::Value = serde_json::from_slice(&std::fs::read(&spec)?)
                        .with_context(|| format!("parsing {}", spec.display()))?;
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::create_vm(
                                &central,
                                token,
                                body,
                                node,
                                node_selector.into_iter().collect(),
                            )
                            .await?
                        )?
                    );
                }
                FleetCommand::Vms => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::list_vms(&central, token).await?
                        )?
                    );
                }
                FleetCommand::NodeVms { name } => {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(
                            &fleet_client::node_vms(&central, token, &name).await?
                        )?
                    );
                }
                FleetCommand::Delete { node, id } => {
                    fleet_client::delete_vm(&central, token, &node, id).await?;
                    println!("{{\"ok\":true}}");
                }
            }
        }
    }
    Ok(())
}

async fn build_mtls_config(
    cert: &Path,
    key: &Path,
    client_ca: &Path,
) -> Result<axum_server::tls_rustls::RustlsConfig> {
    use rustls::pki_types::CertificateDer;
    use rustls::server::WebPkiClientVerifier;
    use rustls::{RootCertStore, ServerConfig};
    use std::fs::File;
    use std::io::BufReader;
    use std::sync::Arc;

    let mut cert_reader = BufReader::new(File::open(cert).context("open TLS cert")?);
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("parse TLS cert PEM")?;
    let mut key_reader = BufReader::new(File::open(key).context("open TLS key")?);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .context("parse TLS key PEM")?
        .ok_or_else(|| anyhow::anyhow!("TLS key PEM contained no private key"))?;

    let mut roots = RootCertStore::empty();
    let mut ca_reader = BufReader::new(File::open(client_ca).context("open client CA")?);
    for cert in rustls_pemfile::certs(&mut ca_reader) {
        roots
            .add(cert.context("parse client CA cert")?)
            .context("add client CA to trust store")?;
    }
    let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .context("build client cert verifier")?;

    let mut config = ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .context("build rustls ServerConfig")?;
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(axum_server::tls_rustls::RustlsConfig::from_config(
        Arc::new(config),
    ))
}

async fn print_hubble_observe(
    m: &VmManager,
    output: &str,
    detailed: bool,
    limit: usize,
    verdict: &str,
    protocol: &str,
) -> Result<()> {
    use fluxvm_network::packetflow::{FlowOutput, filter_views, render_flows};
    let mut views = m.hubble_observe_views(limit).await?;
    views = filter_views(views, Some(verdict), Some(protocol));
    let mode = if std::env::var("NO_COLOR")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
        && output.eq_ignore_ascii_case("color")
    {
        FlowOutput::Plain
    } else {
        FlowOutput::parse(output)
    };
    print!("{}", render_flows(&views, mode, detailed));
    Ok(())
}

#[cfg(test)]
mod catalog_cli_tests {
    use super::*;

    /// Every `fluxvm catalog <verb>` subcommand this file added parses into
    /// the field values it's documented to take, and rejects a required
    /// flag/positional being left off — clap wiring bugs (a typo'd `long`
    /// name, a flag that silently became optional) would otherwise only
    /// surface the first time someone actually ran the command by hand.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn catalog_list_takes_no_arguments() {
        assert!(matches!(
            parse(&["catalog", "list"]),
            Command::Catalog {
                command: CatalogCommand::List
            }
        ));
    }

    #[test]
    fn catalog_add_parses_name_positional_and_source_format_flags() {
        let Command::Catalog {
            command:
                CatalogCommand::Add {
                    name,
                    source,
                    format,
                },
        } = parse(&[
            "catalog",
            "add",
            "ubuntu-24.04",
            "--source",
            "/var/lib/fluxvm/images/ubuntu.qcow2",
        ])
        else {
            panic!("expected CatalogCommand::Add");
        };
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(source, "/var/lib/fluxvm/images/ubuntu.qcow2");
        assert_eq!(format, "qcow2", "format must default to qcow2");
    }

    #[test]
    fn catalog_add_requires_source() {
        assert!(Cli::try_parse_from(["fluxvm", "catalog", "add", "ubuntu-24.04"]).is_err());
    }

    #[test]
    fn catalog_sign_parses_optional_build_provenance_flags() {
        let Command::Catalog {
            command:
                CatalogCommand::Sign {
                    key,
                    name,
                    source,
                    sha256,
                    format,
                    distro,
                    version,
                    arch,
                    build_pipeline,
                    build_run_id,
                    build_commit,
                    catalog_file,
                },
        } = parse(&[
            "catalog",
            "sign",
            "--key",
            "base64key",
            "--name",
            "ubuntu-24.04",
            "--source",
            "/var/lib/fluxvm/images/ubuntu.qcow2",
            "--sha256",
            "abc123",
            "--build-pipeline",
            "github-actions/build-images.yml",
            "--build-run-id",
            "42",
            "--build-commit",
            "deadbeef",
        ])
        else {
            panic!("expected CatalogCommand::Sign");
        };
        assert_eq!(key, "base64key");
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(source, "/var/lib/fluxvm/images/ubuntu.qcow2");
        assert_eq!(sha256, "abc123");
        assert_eq!(format, "qcow2", "format must default to qcow2");
        assert_eq!(distro, None);
        assert_eq!(version, None);
        assert_eq!(arch, None);
        assert_eq!(
            build_pipeline.as_deref(),
            Some("github-actions/build-images.yml")
        );
        assert_eq!(build_run_id.as_deref(), Some("42"));
        assert_eq!(build_commit.as_deref(), Some("deadbeef"));
        assert_eq!(
            catalog_file, None,
            "build provenance flags must stay optional and independent of --catalog-file"
        );
    }

    #[test]
    fn catalog_sign_leaves_build_provenance_unset_when_omitted() {
        let Command::Catalog {
            command:
                CatalogCommand::Sign {
                    build_pipeline,
                    build_run_id,
                    build_commit,
                    ..
                },
        } = parse(&[
            "catalog",
            "sign",
            "--key",
            "base64key",
            "--name",
            "n",
            "--source",
            "s",
            "--sha256",
            "h",
        ])
        else {
            panic!("expected CatalogCommand::Sign");
        };
        assert_eq!(build_pipeline, None);
        assert_eq!(build_run_id, None);
        assert_eq!(build_commit, None);
    }

    #[test]
    fn catalog_remove_parses_name() {
        let Command::Catalog {
            command: CatalogCommand::Remove { name },
        } = parse(&["catalog", "remove", "ubuntu-24.04-qa"])
        else {
            panic!("expected CatalogCommand::Remove");
        };
        assert_eq!(name, "ubuntu-24.04-qa");
    }

    #[test]
    fn catalog_rename_parses_both_positionals() {
        let Command::Catalog {
            command: CatalogCommand::Rename { name, new_name },
        } = parse(&["catalog", "rename", "old-name", "new-name"])
        else {
            panic!("expected CatalogCommand::Rename");
        };
        assert_eq!(name, "old-name");
        assert_eq!(new_name, "new-name");
    }

    #[test]
    fn catalog_clone_parses_both_positionals() {
        let Command::Catalog {
            command: CatalogCommand::Clone { name, target_name },
        } = parse(&["catalog", "clone", "ubuntu-24.04", "ubuntu-24.04-staging"])
        else {
            panic!("expected CatalogCommand::Clone");
        };
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(target_name, "ubuntu-24.04-staging");
    }

    #[test]
    fn catalog_export_parses_name_and_dest_path() {
        let Command::Catalog {
            command: CatalogCommand::Export { name, dest },
        } = parse(&[
            "catalog",
            "export",
            "ubuntu-24.04",
            "/var/lib/fluxvm/exports/ubuntu-24.04.qcow2",
        ])
        else {
            panic!("expected CatalogCommand::Export");
        };
        assert_eq!(name, "ubuntu-24.04");
        assert_eq!(
            dest,
            PathBuf::from("/var/lib/fluxvm/exports/ubuntu-24.04.qcow2")
        );
    }

    #[test]
    fn catalog_lock_and_unlock_parse_name() {
        let Command::Catalog {
            command: CatalogCommand::Lock { name },
        } = parse(&["catalog", "lock", "ubuntu-24.04"])
        else {
            panic!("expected CatalogCommand::Lock");
        };
        assert_eq!(name, "ubuntu-24.04");

        let Command::Catalog {
            command: CatalogCommand::Unlock { name },
        } = parse(&["catalog", "unlock", "ubuntu-24.04"])
        else {
            panic!("expected CatalogCommand::Unlock");
        };
        assert_eq!(name, "ubuntu-24.04");
    }

    #[test]
    fn catalog_clean_takes_no_arguments() {
        assert!(matches!(
            parse(&["catalog", "clean"]),
            Command::Catalog {
                command: CatalogCommand::Clean
            }
        ));
    }
}

#[cfg(test)]
mod agent_cli_tests {
    use super::*;

    /// `ping`/`copy-to`/`copy-from` parse into the field values documented
    /// above, `mode` stays optional on `copy-to`, and the required
    /// positionals can't be left off — the same clap-wiring-bug class the
    /// sibling `catalog_cli_tests` module guards against for `catalog`.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn ping_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Ping { id: parsed } = parse(&["ping", &id.to_string()]) else {
            panic!("expected Command::Ping");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn ping_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "ping"]).is_err());
    }

    #[test]
    fn copy_to_parses_positionals_and_defaults_mode_to_none() {
        let id = Uuid::nil();
        let Command::CopyTo {
            id: parsed_id,
            local,
            remote,
            mode,
        } = parse(&[
            "copy-to",
            &id.to_string(),
            "/tmp/local-file.txt",
            "/etc/app/config.yaml",
        ])
        else {
            panic!("expected Command::CopyTo");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(local, PathBuf::from("/tmp/local-file.txt"));
        assert_eq!(remote, "/etc/app/config.yaml");
        assert_eq!(
            mode, None,
            "mode must default to None (guest agent's own 0o644 default)"
        );
    }

    #[test]
    fn copy_to_parses_explicit_mode() {
        let id = Uuid::nil();
        let Command::CopyTo { mode, .. } = parse(&[
            "copy-to",
            &id.to_string(),
            "/tmp/key",
            "/etc/app/key",
            "--mode",
            "384", // 0o600
        ]) else {
            panic!("expected Command::CopyTo");
        };
        assert_eq!(mode, Some(384));
    }

    #[test]
    fn copy_to_requires_both_local_and_remote_paths() {
        let id = Uuid::nil().to_string();
        assert!(Cli::try_parse_from(["fluxvm", "copy-to", &id, "/tmp/local-file.txt"]).is_err());
    }

    #[test]
    fn copy_from_parses_positionals_in_remote_then_local_order() {
        let id = Uuid::nil();
        let Command::CopyFrom {
            id: parsed_id,
            remote,
            local,
        } = parse(&[
            "copy-from",
            &id.to_string(),
            "/etc/app/config.yaml",
            "/tmp/local-file.txt",
        ])
        else {
            panic!("expected Command::CopyFrom");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(remote, "/etc/app/config.yaml");
        assert_eq!(local, PathBuf::from("/tmp/local-file.txt"));
    }

    #[test]
    fn copy_from_requires_both_remote_and_local_paths() {
        let id = Uuid::nil().to_string();
        assert!(Cli::try_parse_from(["fluxvm", "copy-from", &id, "/etc/app/config.yaml"]).is_err());
    }

    /// `read_local_file_for_copy_to` is what stands between a caller and a
    /// wasted base64-encode + vsock round trip for content the guest
    /// agent's own `put_file` would reject anyway — proves the cap is
    /// actually enforced client-side, not just documented.
    #[test]
    fn read_local_file_for_copy_to_rejects_oversized_files() {
        let dir = std::env::temp_dir().join(format!(
            "fluxctl-copy-to-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("oversized.bin");
        // One byte past the limit is enough to prove the boundary check —
        // no need to actually write 64MB+1 to disk to exercise it.
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut f = std::fs::File::create(&path).unwrap();
            f.seek(SeekFrom::Start(
                fluxvm_guest_protocol::MAX_FILE_TRANSFER_BYTES as u64,
            ))
            .unwrap();
            f.write_all(b"x").unwrap();
        }

        let err = read_local_file_for_copy_to(&path).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "unexpected error: {err}"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_local_file_for_copy_to_accepts_files_within_the_limit() {
        let dir = std::env::temp_dir().join(format!(
            "fluxctl-copy-to-test-ok-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("small.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let bytes = read_local_file_for_copy_to(&path).unwrap();
        assert_eq!(bytes, b"hello world");

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// `write_copy_from_response` round-trips base64 content back to real
    /// bytes on disk and restores the guest-reported Unix mode — the two
    /// things `get_file`'s REST/CLI callers actually rely on, not just that
    /// the base64 decodes.
    #[cfg(unix)]
    #[test]
    fn write_copy_from_response_restores_content_and_mode() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!(
            "fluxctl-copy-from-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("restored.txt");

        let n = write_copy_from_response(&path, &B64.encode(b"secret content"), 0o600).unwrap();
        assert_eq!(n, "secret content".len());
        assert_eq!(std::fs::read(&path).unwrap(), b"secret content");
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_copy_from_response_rejects_invalid_base64() {
        let dir = std::env::temp_dir().join(format!(
            "fluxctl-copy-from-test-bad-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("never-written.txt");

        assert!(write_copy_from_response(&path, "not-valid-base64!!!", 0o644).is_err());
        assert!(!path.exists());

        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod freeze_cli_tests {
    use super::*;

    /// `freeze`/`thaw`/`frozen` all take a single VM-id positional and
    /// nothing else — proves the clap wiring actually produces the three
    /// distinct variants (not, say, all three silently parsing into the
    /// same one) and that the id can't be left off, the same clap-wiring-bug
    /// class `catalog_cli_tests`/`agent_cli_tests` guard against elsewhere
    /// in this file.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn freeze_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Freeze { id: parsed } = parse(&["freeze", &id.to_string()]) else {
            panic!("expected Command::Freeze");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn freeze_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "freeze"]).is_err());
    }

    #[test]
    fn thaw_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Thaw { id: parsed } = parse(&["thaw", &id.to_string()]) else {
            panic!("expected Command::Thaw");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn thaw_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "thaw"]).is_err());
    }

    #[test]
    fn frozen_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Frozen { id: parsed } = parse(&["frozen", &id.to_string()]) else {
            panic!("expected Command::Frozen");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn frozen_requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "frozen"]).is_err());
    }

    /// `freeze`/`thaw`/`frozen` are three distinct commands, not aliases of
    /// each other or of `pause`/`resume` — a copy-paste bug wiring `thaw`'s
    /// arm to call `m.freeze()` (both take just an id, so the type checker
    /// wouldn't catch it) would otherwise only surface at runtime.
    #[test]
    fn freeze_thaw_frozen_are_distinct_from_each_other_and_from_pause_resume() {
        let id = Uuid::nil().to_string();
        assert!(matches!(parse(&["freeze", &id]), Command::Freeze { .. }));
        assert!(matches!(parse(&["thaw", &id]), Command::Thaw { .. }));
        assert!(matches!(parse(&["frozen", &id]), Command::Frozen { .. }));
        assert!(matches!(parse(&["pause", &id]), Command::Pause { .. }));
        assert!(matches!(parse(&["resume", &id]), Command::Resume { .. }));
    }
}

#[cfg(test)]
mod resources_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn parses_a_single_flag() {
        let id = Uuid::nil();
        let Command::Resources {
            id: parsed_id,
            cpu_quota_percent,
            memory_max_bytes,
            io_weight,
            pids_max,
            cpuset_cpus,
        } = parse(&["resources", &id.to_string(), "--cpu-quota-percent", "150"])
        else {
            panic!("expected Command::Resources");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(cpu_quota_percent, Some(150));
        assert_eq!(memory_max_bytes, None);
        assert_eq!(io_weight, None);
        assert_eq!(pids_max, None);
        assert_eq!(cpuset_cpus, None);
    }

    #[test]
    fn parses_every_flag_together() {
        let id = Uuid::nil();
        let Command::Resources {
            id: parsed_id,
            cpu_quota_percent,
            memory_max_bytes,
            io_weight,
            pids_max,
            cpuset_cpus,
        } = parse(&[
            "resources",
            &id.to_string(),
            "--cpu-quota-percent",
            "150",
            "--memory-max-bytes",
            "536870912",
            "--io-weight",
            "250",
            "--pids-max",
            "64",
            "--cpuset-cpus",
            "0-1,4",
        ])
        else {
            panic!("expected Command::Resources");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(cpu_quota_percent, Some(150));
        assert_eq!(memory_max_bytes, Some(536_870_912));
        assert_eq!(io_weight, Some(250));
        assert_eq!(pids_max, Some(64));
        assert_eq!(cpuset_cpus.as_deref(), Some("0-1,4"));
    }

    #[test]
    fn requires_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "resources"]).is_err());
    }

    #[test]
    fn all_flags_are_optional_at_the_clap_layer() {
        // clap itself allows zero flags -- the "at least one field" rule is
        // enforced at runtime in main()'s match arm, not by clap, since
        // ResourcePatch's own all-Option shape gives clap no way to express
        // "at least one of these".
        let id = Uuid::nil();
        assert!(matches!(
            parse(&["resources", &id.to_string()]),
            Command::Resources { .. }
        ));
    }

    #[test]
    fn is_distinct_from_freeze_and_pause() {
        let id = Uuid::nil().to_string();
        assert!(matches!(
            parse(&["resources", &id, "--pids-max", "8"]),
            Command::Resources { .. }
        ));
        assert!(matches!(parse(&["freeze", &id]), Command::Freeze { .. }));
        assert!(matches!(parse(&["pause", &id]), Command::Pause { .. }));
    }

    // --- parse_cpuset_spec ---

    #[test]
    fn cpuset_spec_parses_a_single_range() {
        assert_eq!(parse_cpuset_spec("0-3").unwrap(), vec![0, 1, 2, 3]);
    }

    #[test]
    fn cpuset_spec_parses_a_comma_list() {
        assert_eq!(parse_cpuset_spec("0,2,4").unwrap(), vec![0, 2, 4]);
    }

    #[test]
    fn cpuset_spec_parses_mixed_ranges_and_singletons() {
        assert_eq!(parse_cpuset_spec("0-1,4,6-7").unwrap(), vec![0, 1, 4, 6, 7]);
    }

    #[test]
    fn cpuset_spec_sorts_and_dedups() {
        assert_eq!(parse_cpuset_spec("4,0-1,1,0").unwrap(), vec![0, 1, 4]);
    }

    #[test]
    fn cpuset_spec_tolerates_surrounding_whitespace() {
        assert_eq!(parse_cpuset_spec(" 0-1, 4 ").unwrap(), vec![0, 1, 4]);
    }

    #[test]
    fn cpuset_spec_rejects_empty_string() {
        let err = parse_cpuset_spec("").unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn cpuset_spec_rejects_an_empty_entry_between_commas() {
        assert!(parse_cpuset_spec("0,,1").is_err());
    }

    #[test]
    fn cpuset_spec_rejects_non_numeric_input() {
        assert!(parse_cpuset_spec("abc").is_err());
    }

    #[test]
    fn cpuset_spec_rejects_a_reversed_range_instead_of_silently_returning_empty() {
        // Plain `start..=end` with start > end is a silently-empty Rust
        // range -- without this check a typo like "5-2" would apply an
        // empty cpuset instead of erroring.
        let err = parse_cpuset_spec("5-2").unwrap_err();
        assert!(err.to_string().contains("start > end"));
    }
}

#[cfg(test)]
mod migrate_cli_tests {
    use super::*;

    /// `migrate start/status/cancel` parse into the field values documented
    /// above -- the same clap-wiring-bug class `agent_cli_tests` and
    /// `catalog_cli_tests` guard against for their own subcommands.
    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn migrate_start_parses_destination_and_defaults_mode_to_pre_copy() {
        let id = Uuid::nil();
        let Command::Migrate {
            command:
                MigrateCommand::Start {
                    id: parsed_id,
                    destination,
                    mode,
                    bandwidth_mbps,
                    max_downtime_ms,
                    multifd_channels,
                },
        } = parse(&[
            "migrate",
            "start",
            &id.to_string(),
            "--destination",
            "tcp:10.0.0.9:49152",
        ])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Start");
        };
        assert_eq!(parsed_id, id);
        assert_eq!(destination, "tcp:10.0.0.9:49152");
        assert_eq!(mode, "pre-copy", "mode must default to pre-copy");
        assert_eq!(bandwidth_mbps, None);
        assert_eq!(max_downtime_ms, None);
        assert_eq!(multifd_channels, None);
    }

    #[test]
    fn migrate_start_parses_all_optional_tuning_flags() {
        let id = Uuid::nil();
        let Command::Migrate {
            command:
                MigrateCommand::Start {
                    mode,
                    bandwidth_mbps,
                    max_downtime_ms,
                    multifd_channels,
                    ..
                },
        } = parse(&[
            "migrate",
            "start",
            &id.to_string(),
            "--destination",
            "unix:/run/fluxvm/migrate.sock",
            "--mode",
            "post-copy",
            "--bandwidth-mbps",
            "500",
            "--max-downtime-ms",
            "300",
            "--multifd-channels",
            "4",
        ])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Start");
        };
        assert_eq!(mode, "post-copy");
        assert_eq!(bandwidth_mbps, Some(500));
        assert_eq!(max_downtime_ms, Some(300));
        assert_eq!(multifd_channels, Some(4));
    }

    #[test]
    fn migrate_start_requires_a_destination() {
        let id = Uuid::nil().to_string();
        assert!(Cli::try_parse_from(["fluxvm", "migrate", "start", &id]).is_err());
    }

    #[test]
    fn migrate_status_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Migrate {
            command: MigrateCommand::Status { id: parsed },
        } = parse(&["migrate", "status", &id.to_string()])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Status");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn migrate_cancel_takes_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Migrate {
            command: MigrateCommand::Cancel { id: parsed },
        } = parse(&["migrate", "cancel", &id.to_string()])
        else {
            panic!("expected Command::Migrate/MigrateCommand::Cancel");
        };
        assert_eq!(parsed, id);
    }

    /// `parse_migration_mode` matches `MigrationMode`'s own kebab-case wire
    /// spelling exactly and rejects anything else with a clear error,
    /// rather than silently falling back to a default the caller didn't ask
    /// for.
    #[test]
    fn parse_migration_mode_accepts_the_two_wire_values() {
        assert_eq!(
            parse_migration_mode("pre-copy").unwrap(),
            MigrationMode::PreCopy
        );
        assert_eq!(
            parse_migration_mode("post-copy").unwrap(),
            MigrationMode::PostCopy
        );
    }

    #[test]
    fn parse_migration_mode_rejects_unknown_values() {
        let err = parse_migration_mode("precopy").unwrap_err();
        assert!(
            err.to_string().contains("unknown migration mode"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn migrate_receiver_create_parses_required_flags() {
        let Command::Migrate {
            command:
                MigrateCommand::Receiver {
                    command:
                        MigrateReceiverCommand::Create {
                            disk,
                            disk_format,
                            vcpus,
                            memory_mib,
                            listen_port,
                            ..
                        },
                },
        } = parse(&[
            "migrate",
            "receiver",
            "create",
            "--disk",
            "/var/lib/fluxvm/shared.raw",
            "--vcpus",
            "2",
            "--memory-mib",
            "2048",
            "--listen-port",
            "4444",
        ])
        else {
            panic!("expected MigrateReceiverCommand::Create");
        };
        assert_eq!(disk, PathBuf::from("/var/lib/fluxvm/shared.raw"));
        assert_eq!(disk_format, "raw");
        assert_eq!(vcpus, 2);
        assert_eq!(memory_mib, 2048);
        assert_eq!(listen_port, 4444);
    }

    #[test]
    fn migrate_receiver_activate_and_delete_parse() {
        let id = Uuid::nil();
        let Command::Migrate {
            command:
                MigrateCommand::Receiver {
                    command: MigrateReceiverCommand::Activate { id: parsed, token },
                },
        } = parse(&[
            "migrate",
            "receiver",
            "activate",
            &id.to_string(),
            "--token",
            "secret",
        ])
        else {
            panic!("expected MigrateReceiverCommand::Activate");
        };
        assert_eq!(parsed, id);
        assert_eq!(token, "secret");

        let Command::Migrate {
            command:
                MigrateCommand::Receiver {
                    command: MigrateReceiverCommand::Delete { id: parsed },
                },
        } = parse(&["migrate", "receiver", "delete", &id.to_string()])
        else {
            panic!("expected MigrateReceiverCommand::Delete");
        };
        assert_eq!(parsed, id);
    }
}

#[cfg(test)]
mod stats_pressure_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn stats_and_pressure_take_only_the_vm_id() {
        let id = Uuid::nil();
        let Command::Stats { id: parsed } = parse(&["stats", &id.to_string()]) else {
            panic!("expected Command::Stats");
        };
        assert_eq!(parsed, id);
        let Command::Pressure { id: parsed } = parse(&["pressure", &id.to_string()]) else {
            panic!("expected Command::Pressure");
        };
        assert_eq!(parsed, id);
    }

    #[test]
    fn stats_and_pressure_require_an_id() {
        assert!(Cli::try_parse_from(["fluxvm", "stats"]).is_err());
        assert!(Cli::try_parse_from(["fluxvm", "pressure"]).is_err());
    }
}

#[cfg(test)]
mod hotplug_snapshot_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn hotplug_cpu_memory_share_parse() {
        let id = Uuid::nil();
        let Command::Hotplug {
            command:
                HotplugCommand::Cpu {
                    id: parsed,
                    add_vcpus,
                },
        } = parse(&["hotplug", "cpu", &id.to_string(), "--add-vcpus", "2"])
        else {
            panic!("expected HotplugCommand::Cpu");
        };
        assert_eq!(parsed, id);
        assert_eq!(add_vcpus, 2);

        let Command::Hotplug {
            command:
                HotplugCommand::Memory {
                    id: parsed,
                    add_memory_mib,
                },
        } = parse(&[
            "hotplug",
            "memory",
            &id.to_string(),
            "--add-memory-mib",
            "512",
        ])
        else {
            panic!("expected HotplugCommand::Memory");
        };
        assert_eq!(parsed, id);
        assert_eq!(add_memory_mib, 512);

        let Command::Hotplug {
            command:
                HotplugCommand::Share {
                    id: parsed,
                    host_path,
                    read_only,
                },
        } = parse(&[
            "hotplug",
            "share",
            &id.to_string(),
            "--host-path",
            "/mnt/data",
            "--read-only",
        ])
        else {
            panic!("expected HotplugCommand::Share");
        };
        assert_eq!(parsed, id);
        assert_eq!(host_path, PathBuf::from("/mnt/data"));
        assert!(read_only);
    }

    #[test]
    fn hotplug_nic_unplug_parse() {
        let id = Uuid::nil().to_string();
        let Command::Hotplug {
            command: HotplugCommand::NicUnplug { mac, tap, .. },
        } = parse(&["hotplug", "nic-unplug", &id, "--mac", "02:00:00:00:00:01"])
        else {
            panic!("expected HotplugCommand::NicUnplug");
        };
        assert_eq!(mac.as_deref(), Some("02:00:00:00:00:01"));
        assert!(tap.is_none());
        let fails = |a: &[&str]| Cli::try_parse_from([&["fluxvm"], a].concat()).is_err();
        assert!(fails(&["hotplug", "nic-unplug", &id]));
        assert!(fails(&[
            "hotplug",
            "nic-unplug",
            &id,
            "--mac",
            "m",
            "--tap",
            "t"
        ]));
    }

    #[test]
    fn hotplug_nic_bridge_and_direct_parse() {
        let id = Uuid::nil();
        let Command::Hotplug {
            command: HotplugCommand::Nic {
                bridge, outer, mac, ..
            },
        } = parse(&[
            "hotplug",
            "nic",
            &id.to_string(),
            "--bridge",
            "br0",
            "--mac",
            "52:54:00:12:34:56",
        ])
        else {
            panic!("expected HotplugCommand::Nic");
        };
        assert_eq!(bridge.as_deref(), Some("br0"));
        assert!(outer.is_none());
        assert_eq!(mac.as_deref(), Some("52:54:00:12:34:56"));

        let Command::Hotplug {
            command:
                HotplugCommand::Nic {
                    outer,
                    mode,
                    guest_ip,
                    ..
                },
        } = parse(&[
            "hotplug",
            "nic",
            &id.to_string(),
            "--outer",
            "eth0",
            "--mode",
            "l2-uplink",
            "--guest-ip",
            "10.0.0.5",
        ])
        else {
            panic!("expected HotplugCommand::Nic direct");
        };
        assert_eq!(outer.as_deref(), Some("eth0"));
        assert_eq!(mode, "l2-uplink");
        assert_eq!(guest_ip, vec!["10.0.0.5".to_string()]);
    }

    #[test]
    fn snapshot_and_start_from_snapshot_parse() {
        let id = Uuid::nil();
        let Command::Snapshot { id: parsed, tag } =
            parse(&["snapshot", &id.to_string(), "--tag", "boot"])
        else {
            panic!("expected Command::Snapshot");
        };
        assert_eq!(parsed, id);
        assert_eq!(tag, "boot");

        let Command::StartFromSnapshot { id: parsed, tag } =
            parse(&["start-from-snapshot", &id.to_string(), "--tag", "boot"])
        else {
            panic!("expected Command::StartFromSnapshot");
        };
        assert_eq!(parsed, id);
        assert_eq!(tag, "boot");
    }
}

#[cfg(test)]
mod sandbox_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn sandbox_run_and_logs_parse() {
        let Command::Sandbox {
            command: SandboxCommand::Run(args),
        } = parse(&[
            "sandbox",
            "run",
            "alpine:3.22",
            "--rm",
            "--offline",
            "-e",
            "A=1",
            "--",
            "sh",
            "-c",
            "exit 3",
        ])
        else {
            panic!("expected SandboxCommand::Run");
        };
        assert_eq!(args.image, "alpine:3.22");
        assert!(args.rm && args.offline);
        assert_eq!(args.env, ["A=1"]);
        assert_eq!(args.command, ["sh", "-c", "exit 3"]);

        let id = Uuid::nil();
        let Command::Sandbox {
            command: SandboxCommand::Logs { id: parsed, lines },
        } = parse(&["sandbox", "logs", &id.to_string(), "--lines", "5"])
        else {
            panic!("expected SandboxCommand::Logs");
        };
        assert_eq!((parsed, lines), (id, 5));
    }

    #[test]
    fn sandbox_create_list_snapshot_parse() {
        let Command::Sandbox {
            command: SandboxCommand::Create { spec },
        } = parse(&["sandbox", "create", "--spec", "/tmp/sandbox.json"])
        else {
            panic!("expected SandboxCommand::Create");
        };
        assert_eq!(spec, PathBuf::from("/tmp/sandbox.json"));

        assert!(matches!(
            parse(&["sandbox", "list"]),
            Command::Sandbox {
                command: SandboxCommand::List
            }
        ));

        let id = Uuid::nil();
        let Command::Sandbox {
            command: SandboxCommand::Snapshot { id: parsed, path },
        } = parse(&[
            "sandbox",
            "snapshot",
            &id.to_string(),
            "--path",
            "/tmp/snap.qcow2",
        ])
        else {
            panic!("expected SandboxCommand::Snapshot");
        };
        assert_eq!(parsed, id);
        assert_eq!(path, PathBuf::from("/tmp/snap.qcow2"));
    }

    #[test]
    fn sandbox_fs_and_process_parse() {
        let id = Uuid::nil();
        let Command::Sandbox {
            command: SandboxCommand::FsRead { id: parsed, path },
        } = parse(&[
            "sandbox",
            "fs-read",
            &id.to_string(),
            "--path",
            "/etc/os-release",
        ])
        else {
            panic!("expected SandboxCommand::FsRead");
        };
        assert_eq!(parsed, id);
        assert_eq!(path, "/etc/os-release");

        let Command::Sandbox {
            command:
                SandboxCommand::FsWrite {
                    id: parsed,
                    path,
                    local,
                    mode,
                },
        } = parse(&[
            "sandbox",
            "fs-write",
            &id.to_string(),
            "--path",
            "/tmp/out",
            "--local",
            "/tmp/in",
            "--mode",
            "600",
        ])
        else {
            panic!("expected SandboxCommand::FsWrite");
        };
        assert_eq!(parsed, id);
        assert_eq!(path, "/tmp/out");
        assert_eq!(local, PathBuf::from("/tmp/in"));
        assert_eq!(mode, Some(600));

        let Command::Sandbox {
            command:
                SandboxCommand::Process {
                    id: parsed,
                    timeout_seconds,
                    command,
                },
        } = parse(&[
            "sandbox",
            "process",
            &id.to_string(),
            "--timeout-seconds",
            "30",
            "echo",
            "hi",
        ])
        else {
            panic!("expected SandboxCommand::Process");
        };
        assert_eq!(parsed, id);
        assert_eq!(timeout_seconds, Some(30));
        assert_eq!(command, vec!["echo".to_string(), "hi".to_string()]);
    }
}

#[cfg(test)]
mod cpuset_network_logs_health_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn cpuset_logs_and_probes_parse() {
        let id = Uuid::nil();
        let Command::Cpuset { id: parsed } = parse(&["cpuset", &id.to_string()]) else {
            panic!("expected Command::Cpuset");
        };
        assert_eq!(parsed, id);

        let Command::Logs {
            id: parsed,
            lines,
            follow,
        } = parse(&["logs", &id.to_string(), "--lines", "50", "--follow"])
        else {
            panic!("expected Command::Logs");
        };
        assert_eq!(parsed, id);
        assert_eq!(lines, 50);
        assert!(follow);

        assert!(matches!(parse(&["healthz"]), Command::Healthz));
        assert!(matches!(parse(&["readyz"]), Command::Readyz));
        let Command::Metrics { token } = parse(&["metrics", "--token", "t"]) else {
            panic!("expected Command::Metrics");
        };
        assert_eq!(token.as_deref(), Some("t"));
    }

    #[test]
    fn network_subcommands_parse() {
        let id = Uuid::nil();
        assert!(matches!(
            parse(&["network", "policy", &id.to_string()]),
            Command::Network {
                command: NetworkCommand::Policy { .. }
            }
        ));
        assert!(matches!(
            parse(&["network", "effective", &id.to_string()]),
            Command::Network {
                command: NetworkCommand::Effective { .. }
            }
        ));
        assert!(matches!(
            parse(&["network", "status", &id.to_string()]),
            Command::Network {
                command: NetworkCommand::Status { .. }
            }
        ));
        assert!(matches!(
            parse(&["network", "stats", &id.to_string()]),
            Command::Network {
                command: NetworkCommand::Stats { .. }
            }
        ));
        let Command::Network {
            command: NetworkCommand::Flows { id: parsed, limit },
        } = parse(&["network", "flows", &id.to_string(), "--limit", "20"])
        else {
            panic!("expected NetworkCommand::Flows");
        };
        assert_eq!(parsed, id);
        assert_eq!(limit, 20);

        let Command::Network {
            command: NetworkCommand::SetPolicy { id: parsed, spec },
        } = parse(&[
            "network",
            "set-policy",
            &id.to_string(),
            "--spec",
            "/tmp/pol.json",
        ])
        else {
            panic!("expected NetworkCommand::SetPolicy");
        };
        assert_eq!(parsed, id);
        assert_eq!(spec, PathBuf::from("/tmp/pol.json"));
    }
}

#[cfg(test)]
mod machinectl_parity_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn login_and_shell_alias_console() {
        let id = Uuid::nil();
        assert!(matches!(
            parse(&["login", &id.to_string()]),
            Command::Console { command, .. } if command.is_empty()
        ));
        assert!(matches!(
            parse(&["shell", &id.to_string()]),
            Command::Console { command, .. } if command.is_empty()
        ));
        let Command::Console { command, .. } = parse(&["shell", &id.to_string(), "uname", "-a"])
        else {
            panic!("expected Console with command");
        };
        assert_eq!(command, vec!["uname".to_string(), "-a".to_string()]);
    }

    #[test]
    fn ssh_poweroff_reboot_kill_show_bind_parse() {
        let id = Uuid::nil();
        let Command::Ssh {
            id: parsed,
            user,
            port,
            ssh_args,
        } = parse(&[
            "ssh",
            &id.to_string(),
            "-l",
            "ubuntu",
            "-p",
            "2222",
            "uptime",
        ])
        else {
            panic!("expected Command::Ssh");
        };
        assert_eq!(parsed, id);
        assert_eq!(user.as_deref(), Some("ubuntu"));
        assert_eq!(port, 2222);
        assert_eq!(ssh_args, vec!["uptime".to_string()]);

        // No -l: the user is decided later, from the VM's own cloud-init.
        assert!(matches!(
            parse(&["ssh", &id.to_string()]),
            Command::Ssh {
                user: None,
                port: 22,
                ..
            }
        ));
        assert!(matches!(
            parse(&["show", &id.to_string()]),
            Command::Show { .. }
        ));
        assert!(matches!(
            parse(&["poweroff", &id.to_string()]),
            Command::Poweroff { .. }
        ));
        assert!(matches!(
            parse(&["reboot", &id.to_string()]),
            Command::Reboot { .. }
        ));
        assert!(matches!(
            parse(&["kill", &id.to_string()]),
            Command::Kill { .. }
        ));
        let Command::Bind {
            host_path,
            read_only,
            ..
        } = parse(&["bind", &id.to_string(), "/var/data", "--read-only"])
        else {
            panic!("expected Command::Bind");
        };
        assert_eq!(host_path, PathBuf::from("/var/data"));
        assert!(read_only);
    }

    #[test]
    fn terminate_aliases_delete() {
        let id = Uuid::nil();
        assert!(matches!(
            parse(&["terminate", &id.to_string()]),
            Command::Terminate { .. }
        ));
    }

    #[test]
    fn enable_disable_and_image_verbs_parse() {
        let id = Uuid::nil();
        assert!(matches!(
            parse(&["enable", &id.to_string()]),
            Command::Enable { .. }
        ));
        assert!(matches!(
            parse(&["disable", &id.to_string()]),
            Command::Disable { .. }
        ));
        assert!(matches!(parse(&["list-images"]), Command::ListImages));
        assert!(matches!(
            parse(&["image-status", "ubuntu"]),
            Command::ImageStatus { .. }
        ));
        assert!(matches!(
            parse(&["show-image", "ubuntu"]),
            Command::ImageStatus { .. }
        ));
        assert!(matches!(parse(&["clone", "a", "b"]), Command::Clone { .. }));
        assert!(matches!(
            parse(&["pull-raw", "img", "--source", "https://example/x.qcow2"]),
            Command::PullRaw { .. }
        ));
        assert!(matches!(
            parse(&["set-limit", &id.to_string(), "--pids-max", "64"]),
            Command::Resources { .. }
        ));
        assert!(matches!(parse(&["list-transfers"]), Command::ListTransfers));
        assert!(matches!(parse(&["clean"]), Command::Clean));
    }

    #[test]
    fn status_with_id_is_vm_status() {
        let id = Uuid::nil();
        let Command::Status {
            id: Some(parsed),
            verbose: false,
        } = parse(&["status", &id.to_string()])
        else {
            panic!("expected Status with id");
        };
        assert_eq!(parsed, id);
    }
}

#[cfg(test)]
mod backlog_tier1_cli_tests {
    use super::*;

    fn cli(args: &[&str]) -> Cli {
        let mut full = vec!["fluxctl"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap()
    }

    #[test]
    fn restart_rename_label_parse() {
        let id = Uuid::nil();
        assert!(matches!(
            cli(&["restart", &id.to_string()]).command,
            Command::Restart { target: Target { id: Some(p), selector: None, .. } } if p == id
        ));
        let Command::RenameVm { new_name, .. } =
            cli(&["rename-vm", &id.to_string(), "web-2"]).command
        else {
            panic!("expected RenameVm");
        };
        assert_eq!(new_name, "web-2");
        let Command::Label { labels, .. } =
            cli(&["label", &id.to_string(), "env=prod", "team-"]).command
        else {
            panic!("expected Label");
        };
        assert_eq!(
            labels,
            vec![
                ("env".to_string(), Some("prod".to_string())),
                ("team".to_string(), None)
            ]
        );
        assert!(Cli::try_parse_from(["fluxctl", "label", &id.to_string(), "bad"]).is_err());
    }

    #[test]
    fn every_subcommand_has_consistent_arguments() {
        Cli::command().debug_assert();
        assert!(matches!(
            cli(&["import-compose", "c.yml", "--out", "f.toml"]).command,
            Command::ImportCompose {
                output: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn snapshot_list_delete_wait_events_quota_completions_parse() {
        let id = Uuid::nil();
        assert!(matches!(
            cli(&["snapshot-list", &id.to_string()]).command,
            Command::SnapshotList { .. }
        ));
        assert!(matches!(
            cli(&["snapshot-delete", &id.to_string(), "--tag", "t1"]).command,
            Command::SnapshotDelete { tag, .. } if tag == "t1"
        ));
        assert!(matches!(
            cli(&["wait", &id.to_string(), "--for", "agent", "--timeout", "5"]).command,
            Command::Wait { for_state, timeout: 5, .. } if for_state == "agent"
        ));
        assert!(
            Cli::try_parse_from(["fluxctl", "wait", &id.to_string(), "--for", "bogus"]).is_err()
        );
        assert!(matches!(
            cli(&["events", "--follow", "--event", "vm."]).command,
            Command::Events { follow: true, .. }
        ));
        assert!(matches!(cli(&["quota"]).command, Command::Quota { .. }));
        assert!(matches!(
            cli(&["completions", "zsh"]).command,
            Command::Completions { .. }
        ));
    }

    #[test]
    fn output_format_is_global_and_does_not_clash_with_subcommand_output() {
        assert_eq!(cli(&["list"]).output, output::OutputFormat::Json);
        assert_eq!(
            cli(&["-o", "table", "list"]).output,
            output::OutputFormat::Table
        );
        assert_eq!(
            cli(&["list", "-o", "wide"]).output,
            output::OutputFormat::Wide
        );
        let parsed = cli(&[
            "-o",
            "table",
            "trace",
            &Uuid::nil().to_string(),
            "--output",
            "jsonl",
        ]);
        assert_eq!(parsed.output, output::OutputFormat::Table);
        assert!(matches!(parsed.command, Command::Trace { output, .. } if output == "jsonl"));
    }

    #[test]
    fn label_edit_parser() {
        assert_eq!(
            parse_label_edit("a=b=c").unwrap(),
            ("a".into(), Some("b=c".into()))
        );
        assert_eq!(parse_label_edit("gone-").unwrap(), ("gone".into(), None));
        assert!(parse_label_edit("=x").is_err());
        assert!(parse_label_edit("-").is_err());
    }
}

#[cfg(test)]
mod tier2_cli_tests {
    use super::*;

    fn cli(args: &[&str]) -> Result<Cli, clap::Error> {
        let mut full = vec!["fluxctl"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full)
    }

    #[test]
    fn bulk_selector_or_id_but_not_both() {
        let id = Uuid::nil().to_string();
        assert!(matches!(
            cli(&["stop", "-l", "env=dev"]).unwrap().command,
            Command::Stop { target: Target { id: None, selector: Some(s), .. } } if s == "env=dev"
        ));
        assert!(matches!(
            cli(&["delete", "-l", "env=dev", "--yes"]).unwrap().command,
            Command::Delete {
                target: Target { yes: true, .. }
            }
        ));
        assert!(cli(&["start", &id]).is_ok());
        assert!(cli(&["start"]).is_err());
        assert!(cli(&["restart", &id, "-l", "env=dev"]).is_err());
        assert!(matches!(
            cli(&["list", "-l", "team"]).unwrap().command,
            Command::List {
                selector: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn clone_disk_serial_backup_parse() {
        let id = Uuid::nil().to_string();
        assert!(matches!(
            cli(&["clone-vm", &id, "web-2"]).unwrap().command,
            Command::CloneVm { new_name, .. } if new_name == "web-2"
        ));
        assert!(matches!(
            cli(&["disk", "attach", &id, "data", "--size-gib", "10"])
                .unwrap()
                .command,
            Command::Disk {
                command: DiskCommand::Attach {
                    size_gib: Some(10),
                    ..
                }
            }
        ));
        assert!(matches!(
            cli(&["disk", "attach", &id, "pvc", "--path", "/dev/rbd0"])
                .unwrap()
                .command,
            Command::Disk {
                command: DiskCommand::Attach {
                    size_gib: None,
                    path: Some(_),
                    ..
                }
            }
        ));
        assert!(
            cli(&[
                "disk",
                "attach",
                &id,
                "x",
                "--size-gib",
                "1",
                "--path",
                "/a"
            ])
            .is_err()
        );
        assert!(matches!(
            cli(&["disk", "resize", &id, "root", "--size-gib", "20"])
                .unwrap()
                .command,
            Command::Disk {
                command: DiskCommand::Resize { size_gib: 20, .. }
            }
        ));
        assert!(cli(&["disk", "attach", &id, "data"]).is_err());
        assert!(matches!(
            cli(&["disk", "list", &id]).unwrap().command,
            Command::Disk {
                command: DiskCommand::List { .. }
            }
        ));
        assert!(matches!(
            cli(&["serial", &id]).unwrap().command,
            Command::Serial { .. }
        ));
        assert!(matches!(
            cli(&["screenshot", &id, "--out", "s.png", "--max-width", "1280"])
                .unwrap()
                .command,
            Command::Screenshot {
                max_width: Some(1280),
                ..
            }
        ));
        assert!(matches!(
            cli(&["input", &id, r#"{"action":"key","key":"enter"}"#, "--text", "ls"]).unwrap().command,
            Command::Input { actions, text: Some(_), .. } if actions.len() == 1
        ));
        assert!(matches!(
            cli(&["port-connect", &id, "agent"]).unwrap().command,
            Command::PortConnect { name, .. } if name == "agent"
        ));
        assert!(matches!(
            cli(&["backup", &id, "--compress"]).unwrap().command,
            Command::Backup {
                compress: true,
                dest: None,
                quiesce: fluxvm_core::model::BackupQuiesce::Auto,
                ..
            }
        ));
        assert!(matches!(
            cli(&["backup", &id, "--quiesce", "required"])
                .unwrap()
                .command,
            Command::Backup {
                quiesce: fluxvm_core::model::BackupQuiesce::Required,
                ..
            }
        ));
        assert!(cli(&["backup", &id, "--quiesce", "maybe"]).is_err());
        assert!(matches!(
            cli(&["backup", &id, "--name", "db-1"]).unwrap().command,
            Command::Backup { name: Some(n), .. } if n == "db-1"
        ));
        assert!(cli(&["backup", &id, "--name", "a", "--dest", "/tmp/a"]).is_err());
        assert!(matches!(
            cli(&["restore-backup", &id, "db-1"]).unwrap().command,
            Command::RestoreBackup { name, .. } if name == "db-1"
        ));
    }

    #[test]
    fn server_flag_is_global() {
        let c = cli(&["list", "--server", "http://h:7788", "--server-token", "t"]).unwrap();
        assert_eq!(c.server.as_deref(), Some("http://h:7788"));
        assert_eq!(c.server_token.as_deref(), Some("t"));
        let c = cli(&["--server=h:7788", "stop", "-l", "env=dev"]).unwrap();
        assert_eq!(c.server.as_deref(), Some("h:7788"));
        let c = cli(&["--context", "lab", "list"]).unwrap();
        assert_eq!(c.context.as_deref(), Some("lab"));
    }

    #[test]
    fn template_subcommands_parse() {
        let id = Uuid::nil().to_string();
        assert!(matches!(
            cli(&["vm-template", "save", "small", "--from-vm", &id])
                .unwrap()
                .command,
            Command::VmTemplate {
                command: TemplateCommand::Save {
                    from_vm: Some(_),
                    spec: None,
                    ..
                }
            }
        ));
        assert!(cli(&["vm-template", "save", "small"]).is_err());
        assert!(
            cli(&[
                "vm-template",
                "save",
                "s",
                "--spec",
                "a.json",
                "--from-vm",
                &id
            ])
            .is_err()
        );
        assert!(matches!(
            cli(&["vm-template", "create", "small", "web-1", "--label", "env=dev", "--label", "t=x"])
                .unwrap()
                .command,
            Command::VmTemplate { command: TemplateCommand::Create { labels, .. } } if labels.len() == 2
        ));
        assert!(
            cli(&[
                "vm-template",
                "create",
                "small",
                "web-1",
                "--label",
                "novalue"
            ])
            .is_err()
        );
    }

    #[test]
    fn context_subcommands_parse() {
        assert!(matches!(
            cli(&["context", "add", "lab", "--server", "http://h:7788"])
                .unwrap()
                .command,
            Command::Context {
                command: ContextCommand::Add { token: None, .. }
            }
        ));
        assert!(cli(&["context", "add", "lab"]).is_err());
        for sub in ["list", "current", "unset"] {
            assert!(cli(&["context", sub]).is_ok(), "{sub}");
        }
        assert!(matches!(
            cli(&["context", "use", "lab"]).unwrap().command,
            Command::Context { command: ContextCommand::Use { name } } if name == "lab"
        ));
    }
}

#[cfg(test)]
mod speculate_density_cli_tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        let mut full = vec!["fluxvm"];
        full.extend_from_slice(args);
        Cli::try_parse_from(full).unwrap().command
    }

    #[test]
    fn sandbox_speculate_and_changeset_commands_parse() {
        let id = Uuid::nil();
        let cs = Uuid::new_v4();
        let Command::Sandbox {
            command:
                SandboxCommand::Speculate {
                    id: parsed,
                    paths,
                    ttl_seconds,
                    command,
                    ..
                },
        } = parse(&[
            "sandbox",
            "speculate",
            &id.to_string(),
            "--path",
            "/work",
            "--ttl-seconds",
            "120",
            "make",
            "build",
        ])
        else {
            panic!("expected SandboxCommand::Speculate");
        };
        assert_eq!(parsed, id);
        assert_eq!(paths, vec!["/work".to_string()]);
        assert_eq!(ttl_seconds, Some(120));
        assert_eq!(command, vec!["make".to_string(), "build".to_string()]);

        let Command::Sandbox {
            command: SandboxCommand::Apply { id: parsed, cs: c },
        } = parse(&["sandbox", "apply", &id.to_string(), &cs.to_string()])
        else {
            panic!("expected SandboxCommand::Apply");
        };
        assert_eq!((parsed, c), (id, cs));
    }

    #[test]
    fn balloon_and_memory_parse() {
        let id = Uuid::nil();
        let Command::Balloon {
            id: parsed,
            set_mib,
        } = parse(&["balloon", &id.to_string(), "--set-mib", "256"])
        else {
            panic!("expected Command::Balloon");
        };
        assert_eq!((parsed, set_mib), (id, Some(256)));
        let Command::Memory { id: parsed } = parse(&["memory", &id.to_string()]) else {
            panic!("expected Command::Memory");
        };
        assert_eq!(parsed, id);
    }
}
