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

mod contexts;
mod fleet_client;
mod output;
mod remote;
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

#[derive(Subcommand)]
enum Command {
    #[command(next_help_heading = "Basic Commands")]
    /// Start the FluxVM control-plane daemon (REST API).
    Serve,
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
    /// Create a VM from a JSON spec file.
    Create {
        #[arg(long)]
        spec: PathBuf,
    },
    /// List VMs. `-l env=dev,team!=x,gpu` filters by label selector.
    List {
        #[arg(short = 'l', long = "selector")]
        selector: Option<String>,
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
        #[arg(long, default_value_t = false)]
        compress: bool,
        /// Also back up data disks: `dest` becomes a directory of
        /// `root.qcow2` + `<disk>.qcow2`, consistent with each other.
        #[arg(long, default_value_t = false)]
        all_disks: bool,
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
    /// SSH into the guest at its `guest_ip` via the host OpenSSH client.
    /// Needs a reachable address and `sshd` in the guest — distinct from
    /// `console`/`login` (vsock agent PTY).
    Ssh {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        #[arg(long, short = 'l', default_value = "root")]
        user: String,
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
        #[arg(long)]
        token: Option<String>,
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

#[derive(Subcommand)]
enum DiskCommand {
    /// Root disk plus every data disk.
    List {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
    },
    /// Create a qcow2 data disk; hot-added when the VM is running.
    Attach {
        #[arg(value_parser = output::parse_vm_ref)]
        id: Uuid,
        name: String,
        #[arg(long)]
        size_gib: u64,
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
            if let Some(size) = terminal_size() {
                if size != last {
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let stream = m.open_serial(id).await?;
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprintln!("Connected to {id} serial console. Escape: Ctrl-]\r");
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
    use futures_util::{SinkExt, StreamExt};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_tungstenite::tungstenite::Message;
    let ws = r.websocket(&format!("/v1/vms/{id}/serial")).await?;
    let interactive = std::io::stdin().is_terminal();
    if interactive {
        eprintln!("Connected to {id} serial console. Escape: Ctrl-]\r");
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
        } => {
            if name == remote::LOCAL_CONTEXT {
                anyhow::bail!("'{name}' is reserved for local mode");
            }
            c.add(&name, contexts::Endpoint { server, token })?
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
        Command::List { selector } => output::print_list(
            format,
            &r.list_vms(selector.as_deref()).await?,
            output::VM_COLUMNS,
        )?,
        Command::Get { id } | Command::Status { id: Some(id), .. } => {
            pretty(&r.call(Method::GET, &format!("/v1/vms/{id}"), None).await?)?
        }
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
            compress,
            all_disks,
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
                    Some(json!({"compress": compress, "all_disks": all_disks})),
                )
                .await?,
            )?
        }
        Command::Disk { command } => match command {
            DiskCommand::List { id } => {
                let v = r
                    .call(Method::GET, &format!("/v1/vms/{id}/disks"), None)
                    .await?;
                output::print_list(format, &v["items"], output::DISK_COLUMNS)?
            }
            DiskCommand::Attach { id, name, size_gib } => pretty(
                &r.call(
                    Method::POST,
                    &format!("/v1/vms/{id}/disks"),
                    Some(json!({"name": name, "size_gib": size_gib})),
                )
                .await?,
            )?,
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
        Command::Create { spec } => {
            let body: serde_json::Value = serde_json::from_slice(&std::fs::read(spec)?)?;
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
        _ => anyhow::bail!(
            "this command is not available with --server; supported: create, vm-template, list, get, \
             status <vm>, start, stop, restart, delete, pause, resume, label, rename-vm, clone-vm, snapshot, \
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
    let format = cli.output;
    if let Command::Context { command } = cli.command {
        return run_context(command, format);
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
            compress,
            all_disks,
        } => println!(
            "{}",
            serde_json::to_string_pretty(&m.backup_vm(id, dest, compress, all_disks).await?)?
        ),
        Command::Disk { command } => match command {
            DiskCommand::List { id } => {
                output::print_list(format, &m.list_vm_disks(id).await?, output::DISK_COLUMNS)?;
            }
            DiskCommand::Attach { id, name, size_gib } => println!(
                "{}",
                serde_json::to_string_pretty(&m.attach_vm_disk(id, &name, size_gib).await?)?
            ),
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
        Command::Create { spec } => {
            let req: CreateVmRequest = serde_json::from_slice(&std::fs::read(spec)?)?;
            println!("{}", serde_json::to_string_pretty(&m.create(req).await?)?);
        }
        Command::List { selector } => {
            let mut items = m.list().await;
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
            let status = tokio::process::Command::new("ssh")
                .arg("-tt")
                .arg("-p")
                .arg(port.to_string())
                .arg(format!("{user}@{ip}"))
                .args(&ssh_args)
                .status()
                .await
                .context("running ssh (is OpenSSH client installed?)")?;
            if !status.success() {
                anyhow::bail!("ssh exited with {status}");
            }
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
            command,
        } => {
            let response = m.exec(id, command.join(" "), timeout_seconds).await?;
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
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
        .with_single_cert(certs, PrivateKeyDer::from(key))
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
        assert_eq!(user, "ubuntu");
        assert_eq!(port, 2222);
        assert_eq!(ssh_args, vec!["uptime".to_string()]);

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
            Command::List { selector: Some(_) }
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
                command: DiskCommand::Attach { size_gib: 10, .. }
            }
        ));
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
            cli(&["backup", &id, "--compress"]).unwrap().command,
            Command::Backup {
                compress: true,
                dest: None,
                ..
            }
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
