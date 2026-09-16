# Day-2 operations

Host setup, remote deploy, end-to-end verification, the Firecracker jailer, backend
auto-selection, admission policy, pause/resume/exec, cgroup v2 resource control, warm
VM pools, the image catalog, alternative storage backends, the distributed node-agent,
and on-disk state layout. See also [api.md](api.md) for the REST API and
[PRODUCTION.md](PRODUCTION.md) for the whole-project production checklist.

## Host requirements

Linux x86_64 with virtualization enabled and `/dev/kvm` available.

Typical packages/tools:

```bash
qemu-system-x86_64
qemu-img
cloud-localds
ip
cp
nft                 # netns NAT + legacy sandbox dataplane
# Optional native eBPF dataplane (sandbox.dataplane.mode = ebpf|cilium):
clang llvm libbpf-dev bpftool   # build + load bpf/fluxvm_tc.bpf.c (+ optional fluxvm_xdp.bpf.c)
tc                              # iproute2 TC attach
```

Neither Cloud Hypervisor nor Firecracker is packaged by `apt`/`dnf`, so this repo ships installer
scripts that fetch the upstream release binary for your CPU architecture (x86_64 or aarch64) and
verify it against the SHA-256 digest GitHub records for that release asset before installing it.

For Firecracker, provide a compatible uncompressed guest kernel (`vmlinux`) and a Linux rootfs. For Cloud Hypervisor, use either direct kernel boot or firmware boot. The project's Rust Hypervisor Firmware (`hypervisor-fw`) is passed through the request's `kernel` field, matching the Cloud Hypervisor quick-start; `firmware` is reserved for firmware loaded through the VMM's `--firmware` option.

### Installing (or updating) a single VMM

```bash
./scripts/install-cloud-hypervisor.sh            # latest release, both cloud-hypervisor + hypervisor-fw
./scripts/install-cloud-hypervisor.sh v53.0       # pin a version
./scripts/install-cloud-hypervisor.sh --no-firmware

./scripts/install-firecracker.sh                  # latest release, firecracker + jailer
./scripts/install-firecracker.sh v1.16.1          # pin a version
```

Both scripts resolve the requested (or latest) GitHub release, download the arch-appropriate
binary, verify its SHA-256 digest, and `install` it to `/usr/local/bin` (override with
`INSTALL_DIR=...`). They are safe to re-run — an already-installed matching version is a no-op.

## Deploy to a remote host

**Easiest (Fabric + FluxVM stack):** from this repo with sibling `../fabric`:

```bash
./scripts/ship sus@HOST           # quick redeploy + readiness
./scripts/ship sus@HOST --full    # first install
```

FluxVM-only remote deploy:

`scripts/deploy-remote.sh` does the above end-to-end over SSH: rsync the source, install system
packages + Cloud Hypervisor/Firecracker, install a Rust toolchain if needed, build, and install the
binary, config, and systemd unit.

```bash
./scripts/deploy-remote.sh 10.0.0.5 deploy --key   # full deploy, SSH key auth
./scripts/deploy-remote.sh deploy@10.0.0.5 --quick  # rsync + build only, skip dep install
./scripts/deploy-remote.sh 10.0.0.5 deploy --verify-only
./scripts/deploy-remote.sh --help
```

## Testing networking and lifecycle end-to-end

`scripts/test-networking.sh` boots real VMs over each supported network mode and proves they're
actually reachable over SSH — not just that the process launched:

- **QEMU user-mode NAT** + host port forward (no host network changes required).
- **TAP + Linux bridge + DHCP** (against an existing bridge with a DHCP server on it, e.g.
  libvirt's `virbr0` or a bridge set up by `bootstrap-host.sh`). Skipped with a warning if the
  bridge doesn't exist.
- **macvtap**, against a throwaway `dummy0` parent by default so the test never touches a real
  physical NIC/switch (pass `--macvtap-parent eth0` to test against a real uplink instead). Since
  macvtap's `bridge` mode can't reach the parent/host directly, the test creates a second, host-side
  macvtap sibling on the same parent to reach the guest's statically-assigned IP.

All three also assert cleanup: the QEMU process and (for TAP/macvtap) the interface must actually be
gone after `fluxvm delete` — this is what caught a TAP-interface leak during development (fixed
by making VM shutdown wait for the process to actually exit before releasing its network resources).

```bash
sudo ./scripts/test-networking.sh                          # bridge defaults to vmbr0, macvtap uses dummy0
sudo ./scripts/test-networking.sh --bridge virbr0           # test TAP against libvirt's default network
sudo ./scripts/test-networking.sh --macvtap-parent eth0     # test macvtap against a real uplink
sudo ./scripts/test-networking.sh --image /path/to/base.qcow2   # skip auto-downloading a test image
```

It downloads an Ubuntu 24.04 cloud image on first run (cached under `<state_dir>/images/`) unless
`--image` is given, generates a throwaway SSH keypair, and prints a pass/fail/warn summary.

`scripts/test-lifecycle.sh` covers the rest of the VM lifecycle the same way: boots a QEMU VM with
the guest agent enabled and `network.mode=none`, proves `exec` round-trips real output over vsock
(no network path exists at all), forces a CPU-bound loop into the guest so pausing has something to
verify (an idle guest's VMM process shows ~flat CPU time whether it's paused or just idle — this
avoids that false signal), confirms the VMM's own CPU-time counter actually freezes while paused,
confirms `exec` works again after resume, confirms `stop` exits the VMM process, and confirms two
concurrently-created VMs get distinct vsock CIDs. QEMU only — Cloud Hypervisor and Firecracker were
validated manually (see [Pause, resume, and exec](#pause-resume-and-exec) below) since they need a
Firecracker-compatible uncompressed `vmlinux` / extracted whole-disk rootfs respectively, more setup
than belongs in an unattended script.

```bash
sudo ./scripts/test-lifecycle.sh
sudo ./scripts/test-lifecycle.sh --image /path/to/base.qcow2
```

## Firecracker jailer (chroot, uid/gid isolation, cgroups)

Opt-in, off by default, config-only (no per-VM flag) — every Firecracker VM either goes through
`jailer` or none do:

```toml
[jailer]
enabled = true
jailer_binary = "jailer"          # resolved via $PATH unless you give an absolute path
uid = 123                         # must be non-root; unique per tenant for a real isolation boundary
gid = 100
chroot_base_dir = "/srv/jailer"   # should be on the same filesystem as state_dir (see below)
```

`firecracker_binary` must be an absolute path when jailer is enabled — `jailer`'s `--exec-file` needs
a real path, not a bare command resolved via `$PATH`.

FluxVM hardlinks the kernel and rootfs into `jailer`'s chroot (`<chroot_base_dir>/<firecracker
basename>/<vm-id>/root/`) before invoking it — falling back to a real copy if `chroot_base_dir` is on
a different filesystem than the source files, which is why same-filesystem placement matters (a
multi-GB rootfs copy per VM otherwise). Every subsequent control-plane operation (pause/resume/stop,
vsock exec) is routed through the VM's *actual* recorded socket paths rather than a path reconstructed
from its workspace directory — necessary because jailing relocates both the Firecracker API socket and
the vsock proxy socket into the chroot, a genuinely different location than the non-jailed case.

Verified on real hardware (`scripts/test-firecracker-jailer.sh`): the resulting Firecracker process
really runs as the configured unprivileged uid/gid (confirmed via `ps`, not just "the command didn't
error"); the guest boots and answers `exec` over vsock through the relocated proxy socket;
pause/resume/stop all work against the relocated API socket; `delete` cleans up both the normal
workspace and the separate jail chroot tree, leaving no orphaned files or process.

## Auto backend selection

Set `"backend": "auto"` and the manager picks a concrete backend for you, resolved once at the very
start of `create` (the resolved value — never `"auto"` — is what's persisted and returned):

1. **Firecracker** if the request has a `kernel`, or `firecracker_kernel` is set in the config — the
   fastest microVM start when a direct-boot kernel is available.
2. otherwise **Cloud Hypervisor** if the request has a `kernel`/`firmware`, or
   `cloud_hypervisor_firmware` is set in the config.
3. otherwise **QEMU** — the only one of the three that boots from just a disk image, via its own
   BIOS/UEFI, with no kernel or firmware required.

`"backend": "flux-vm"` is never chosen by `auto` — set it explicitly for the agent-sandbox track.

```json
{ "name": "auto-example", "backend": "auto", "image": "/var/lib/fluxvm/images/ubuntu.qcow2", "...": "..." }
```

Verified on real hardware (`scripts/test-auto-backend.sh`): all three resolution paths actually boot
the chosen backend and answer over vsock, not just that `resolve_backend` returns the right enum
value in isolation.

## Policy (admission limits)

`[policy]` in the config file (see `config.example.toml`) lets an operator cap what a `create`
request is allowed to ask for. Every field is optional and defaults to unrestricted — an absent or
empty `[policy]` table behaves exactly like no policy at all:

```toml
[policy]
max_vcpus = 8
max_memory_mib = 16384
max_disk_gib = 100
max_ttl_seconds = 86400          # every request must set ttl_seconds <= this; unbounded VMs are rejected
allowed_backends = ["qemu", "firecracker"]
allowed_image_dirs = ["/var/lib/fluxvm/images"]
```

Checked once, right after `"auto"` resolves to a concrete backend and before any disk/network work
starts, so a rejected request fails fast with a specific reason (`request vcpus (4) exceeds policy
max_vcpus (2)`, `policy requires ttl_seconds to be set...`, `backend Firecracker is not permitted by
policy allowed_backends [Qemu]`, etc.) rather than a generic 400. `allowed_image_dirs` is a plain
path-prefix check — good enough to stop a tenant pointing `image` at an arbitrary host path, not a
symlink-resistant sandboxing boundary. Verified against a real config on real hardware: all five
cases (four rejections, one compliant create that actually boots) behave as documented.

### Per-tenant aggregate quotas

Everything above is a **per-request** check — it validates the one incoming `CreateVmRequest` in
isolation, never looking at what else already exists. `[[policy.tenants]]` is different: an
**aggregate** cap, summed across every existing VM a tenant already owns plus the incoming request,
matched against `CreateVmRequest.tenant` (itself resolved authoritatively by `fluxvm-api` from
`[[auth.tokens]]`'s own `tenant` field or an OIDC claim before `fluxvm-scheduler` ever sees the
request — see `SECURITY.md`'s "per-token / OIDC `tenant` is authoritative" note):

```toml
[[policy.tenants]]
tenant = "acme"
max_vcpus_total = 32
max_memory_mib_total = 131072
max_vms_total = 20
```

A tenant with no matching entry is unrestricted by this mechanism (still subject to every
per-request `[policy]` field above, unchanged). Checked right after the per-request `[policy]`
check, only when the request actually has a `tenant` set and at least one `[[policy.tenants]]`
entry exists at all — a full `Store::list()` scan is skipped entirely otherwise, so hosts that
don't use per-tenant quotas pay nothing extra per create. This is the aggregate, fleet-wide
counterpart to Kairon's own `MachineQuota` CRD (a sibling project in the same family) — deliberately
config-file-based here rather than a separate CRD/API object, matching how every other admission
control in this project is already shaped (`[policy]`, `[[auth.tokens]]`).

### REST API rate limiting

`[policy]`/`[[policy.tenants]]` above cap what a request may *ask for*; neither caps how *often* one
caller can ask. Before this existed, `fluxvm-api` had no request-volume limiting at all — a single
misbehaving script holding one valid token (or hitting an unauthenticated loopback deployment) could
issue an unbounded number of requests, no different in effect from an external DoS, with nothing in
the REST layer itself to push back. `auth.rate_limit_rps`/`auth.rate_limit_burst` (both opt-in, must
be set together) close that gap with a small hand-rolled per-caller token bucket
(`fluxvm-api::rate_limit`, no new dependency):

```toml
[auth]
rate_limit_rps = 20
rate_limit_burst = 40
```

Keyed by the same actor identity the audit log already attributes a request to — a static token's
`name`, an OIDC subject, an mTLS client-cert CN, or `"anonymous-admin"` on an unauthenticated
loopback deployment with no credentials configured at all — so a caller's bucket tracks the identity
already established by `auth_middleware`, not raw connection volume; two callers sharing one token
share one bucket by design, the same way the audit log already attributes them as one actor. Runs
after auth (so every request it sees already carries that identity) and before the per-tenant scope
guard, with its own explicit bypass for `GET /healthz`/`GET /readyz` (auth only skips resolving an
identity for those two, it doesn't stop them reaching the layers below it), so a liveness/readiness
probe can never be starved by a caller's own throttling. A throttled request gets
`429 Too Many Requests` with `Retry-After` set. Absent by default (both fields unset): no rate
limiting at all, byte-for-byte the behavior before this existed. The admission-side checks above stay
separate and unaffected either way — this only bounds request frequency, never what a single request
is allowed to contain.

## Pause, resume, and exec

```bash
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml pause <id>
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml resume <id>
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml exec <id> -- echo hello
```

`exec` requires `agent.enabled: true` in the VM spec (see [the JSON contract](api.md#vm-json-contract))
and the guest image to have `fluxvm-guest-agent` installed and running — build it with `cargo build
--release -p fluxvm-guest-agent` and bake it into an image via `build-image`'s
`copy_in`/`enable_services` (see [Build an image](build-image-tutorials.md) and
`systemd/fluxvm-guest-agent.service`).

**Guest-agent auth:** every agent-enabled VM gets a random shared-secret token (or the one you set in
`agent.token`) burned into that VM's own disk — never the shared base image — before it boots, at
`/etc/fluxvm-guest-agent.token`. The agent checks it on every request; `eph exec`/the REST `/agent`
route supply it automatically from the VM's own record, so callers never handle it directly. This
stops a process on the host *other than fluxvm* from opening a raw vsock socket to the VM's CID and
running commands as root — it does not replace REST-layer auth (see [api.md](api.md#auth--rbac)),
which answers a different question ("can this caller reach fluxvm's API at all"). A VM created before
this existed, or with no token file baked into its image for another reason, still runs the agent
unauthenticated — check the agent's own startup log line to be sure. Verified on real hardware
(`scripts/test-guest-agent-auth.sh`): a raw, tokenless (or wrong-token) vsock request is rejected,
the correct token succeeds, and `eph exec` keeps working unmodified.

`stop` always tries a graceful VMM-level shutdown first (QMP `system_powerdown` for QEMU, `ch-remote
shutdown` for Cloud Hypervisor, `SendCtrlAltDel` for Firecracker — x86_64 only, no ARM equivalent in
Firecracker's API today) and only force-kills the process if it doesn't exit within a grace period.

**Firecracker-specific note:** pause/resume were verified correct and fast against Firecracker's own
authoritative `GET /` state (not CPU-time heuristics — an idle guest and a paused one both show flat
CPU time, which is a false "it's paused" signal either way). `exec` over vsock works before a VM is
ever paused, but did not survive a pause/resume cycle in testing on this Firecracker version — a
Cloud Hypervisor VM's vsock connection *did* survive the identical pause/resume/exec sequence using
the same client code, so this looks like a Firecracker vsock characteristic rather than an fluxvm
bug, but it's not something this project has a fix for.

**Interactive console:** `GET /v1/vms/{id}/console?cols=&rows=` upgrades to a WebSocket relayed
end-to-end to a real PTY-backed `/bin/sh` in the guest over the same vsock agent connection as
`exec` (see `fluxvm_vsock_client::open_shell`) — real keystrokes, real job control, verified live
against a real QEMU VM (connect, `echo` a marker string, see it echoed back through the PTY).

**Fixed — process isolation, not a kernel-level root cause.** For a while, roughly 1-in-3 console
sessions left the guest agent's vsock listener unable to accept any further connections afterward
(`exec`/console/file-copy calls to the same VM would then fail with a raw `Connection reset by peer`),
with process/thread tracing showing the listener's `accept()` thread permanently parked in the
kernel's `vsock_accept`. Extensive live isolation ruled out every userspace trigger tried — whether
and from which thread `child.kill()`/`.wait()`/`.try_wait()` was called on the spawned shell made no
measurable difference, and a from-scratch reproducer mirroring the real PTY/fork/setsid/relay-thread
structure could not trigger it at all across 40+ trials while the real binary kept failing — pointing
at something below userspace, in the exact `AF_VSOCK`/`vhost_vsock` accept path, that was never
pinned down to a specific kernel commit or mechanism.

The actual fix doesn't require knowing that mechanism: `OpenShell` sessions are no longer handled in a
thread of the guest agent's own process at all. `spawn_open_shell_session()` double-forks — the
grandchild does the PTY/`setsid()`/shell/relay work fully detached from the agent's process tree (never
sharing a process, even via a thread, with the vsock listener), while the agent's original process
only reaps the fast-exiting intermediate child and returns straight to `accept()`. This is exactly how
OpenSSH's `sshd` and systemd isolate PTY/session-leader work from their own long-lived listeners — see
their `session.c`/`systemd-executor` fork-per-session model — for the same underlying reason: signal
disposition and `waitpid()` are process-wide, so a session leader's lifecycle can affect an unrelated
listener sharing its process in ways a separate process boundary cannot. Verified live: 20/20 console
sessions back-to-back left `exec` working afterward every time (statistically conclusive against the
prior ~1-in-3 failure rate), including through the real WebSocket console path end-to-end, not just a
raw vsock handshake. `zyvor-fabric`'s FluxVM driver can now safely request `agent.enabled: true` by
default — see its own `docs/guides/vm-drivers/fluxvm.md`.

## Resource control (cgroup v2)

Every VM (all three backends) is migrated into its own `fluxvm.slice/{id}.scope` cgroup right after
launch, giving real, kernel-enforced control independent of anything a VMM's own API exposes:

```bash
curl -sS -X POST http://127.0.0.1:7788/v1/vms/<uuid>/resources \
  -H 'content-type: application/json' \
  -d '{"cpu_quota_percent": 150, "memory_max_bytes": 536870912, "pids_max": 64}' | jq

curl -sS -X POST http://127.0.0.1:7788/v1/vms/<uuid>/freeze   # cgroup-level freeze — works even if the VMM's own API doesn't respond
curl -sS -X POST http://127.0.0.1:7788/v1/vms/<uuid>/thaw
curl -sS http://127.0.0.1:7788/v1/vms/<uuid>/frozen            # {"frozen": true|false}
curl -sS http://127.0.0.1:7788/v1/vms/<uuid>/stats              # CPU%, memory, disk I/O, read from the cgroup
curl -sS http://127.0.0.1:7788/v1/vms/<uuid>/pressure           # PSI: cpu/memory/io some+full, avg10/60/300 + total
```

`resources` (`ResourcePatch`) is a partial patch — only the fields you set are touched: `cpu_quota_percent`
(percentage of one core, e.g. `150` = 1.5 cores), `memory_max_bytes`, `io_weight` (1-10000), `pids_max`,
`cpuset_cpus` (pin to specific host cores). `freeze`/`thaw` act on the cgroup directly via
`cgroup.freeze`, independent of the VMM's own pause/resume API (see "Pause, resume, and exec" above) —
useful as a control path that still works if a VMM's control socket is unresponsive. Delegation
(`cgroup.subtree_control`) is set up once at `VmManager` startup; if that fails (e.g. no cgroup v2, or
insufficient privilege), resource control/metrics are unavailable for that run but VM creation/lifecycle
are otherwise unaffected — a warning is logged, not a hard failure.

Verified on real hardware (`scripts/test-cgroup-resources.sh`, all through the REST API against a
running `fluxvm serve`): a launched VM really lands in its own cgroup (confirmed by reading
`cgroup.procs` directly, not just trusting the recorded path); a memory limit set via `resources` is
really written to `memory.max` and reads back correctly; `freeze` really stops the VMM process (CPU
time frozen with a forced busy-loop running in the guest, same technique used to verify QMP-level
pause) and `thaw` really resumes it; `stats`/`pressure` return real nonzero, cgroup-derived numbers;
`delete` removes the VM's cgroup directory.

## Warm VM pools

A pool keeps `size` VMs booted from a template sitting `Paused`, ready to be handed out on `claim` in
a fraction of a full `create`'s time instead of a full boot:

```bash
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml pool create --spec examples/pool.json
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml pool list
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml pool get my-pool
```

Pool spec (`template` is a normal `CreateVmRequest` — its `name`/`ttl_seconds` are ignored for pool
members, which must never expire on their own while sitting idle):

```json
{
  "name": "my-pool",
  "size": 4,
  "template": {
    "name": "ignored",
    "backend": "qemu",
    "image": "/var/lib/fluxvm/images/ubuntu-agent.qcow2",
    "vcpus": 2,
    "memory_mib": 2048,
    "network": {"mode": "none"},
    "agent": {"enabled": true, "port": 17777}
  }
}
```

Claim one through REST against a running `fluxvm serve` daemon — the recommended way, since a
claim's own backfill-the-pool-back-up work runs as a background task inside that long-lived process:

```bash
curl -sS -X POST http://127.0.0.1:7788/v1/pools/my-pool/claim \
  -H 'content-type: application/json' \
  -d '{"name": "job-123", "ttl_seconds": 900}' | jq
```

`fluxvm pool claim <name>` also exists on the CLI, but as a **one-shot process** it exits right
after printing the claimed VM — which can take its own backfill-replenishment task down with it
mid-flight before the process exits. `fluxvm pool create` avoids this by blocking until the pool is
genuinely full before its own process exits; `pool claim` deliberately doesn't, to keep a claim fast.
A separately-running `fluxvm serve` daemon's reaper independently tops up every pool on its own
schedule regardless of which process's claim under-filled it, so pool health converges either way —
but for a claim's *own* immediate replenishment to be reliable, use REST against a running daemon.

Resize a pool after the fact instead of deleting and recreating it from the same spec just to change
one number:

```bash
curl -sS -X POST http://127.0.0.1:7788/v1/pools/my-pool/resize \
  -H 'content-type: application/json' \
  -d '{"size": 8}' | jq
```

Growing behaves exactly like `pool create`'s own initial fill — the target size is updated
immediately and a background backfill (same code path, same reaper backstop) brings membership up
to it. Shrinking is synchronous: excess ready members are popped and deleted right away, not left
for the reaper. `fluxvm pool resize <name> --size N` exists on the CLI too, and — like `pool
create` but unlike `pool claim` — blocks on `backfill_pool_sync` when growing, so this one-shot
process doesn't take its own background backfill down with it before the pool actually reaches the
requested size.

`pool list`/`pool get` (and the equivalent REST responses) report computed occupancy alongside the
stored fields, so you don't have to derive it yourself:

```bash
sudo /usr/local/bin/fluxvm --config /etc/fluxvm.toml pool get my-pool
```

```json
{
  "name": "my-pool",
  "size": 8,
  "members": ["...", "..."],
  "claimed_total": 41,
  "ready": 6,
  "pending": 2
}
```

`ready` is `members.len()` under a clearer name; `pending` is how many more members are still
needed to reach `size` (0 once backfill has caught up); `claimed_total` is a lifetime count of
every member this pool has ever successfully handed out via `pool claim` — useful for telling
"this pool is sized about right" apart from "this pool has never actually been claimed from" or
"this pool is running dry constantly and should be bigger," none of which the bare `size`/`members`
pair said on their own.

**Real limits today**: resizing has unit and router-level tests (`fluxvm-scheduler`,
`fluxvm-api`) but, unlike the rest of this section, has not been exercised against real hardware —
`scripts/test-warm-pool.sh` doesn't cover it yet. A shrink that fails to delete one excess member
(logged, not fatal) leaves the pool's target size reduced but membership not fully caught up; the
reaper never shrinks a pool on its own, so an under-trimmed pool stays exactly that size until
resized again, rather than silently drifting back up. The `ready`/`pending`/`claimed_total` fields
are pure read-side computation over state `pool create`/`claim`/`resize` already maintain and
already exercise on real hardware above — nothing new to independently verify against a live guest,
but also not separately re-run against real hardware under this name.

Every pool member is verified genuinely ready — not just "a process exists" — before being paused: a
real bug found on real hardware pausing a member immediately after `create()` returns (before the
guest had even finished booting, let alone started its guest-agent) meant a "warm" member was actually
frozen mid-boot, so resuming it on claim still had to finish booting before `exec` worked at all,
defeating the point. Backfill now waits for the guest agent to answer a ping before pausing.

Verified on real hardware (`scripts/test-warm-pool.sh`): a pool backfills to size on its own, a REST
claim is dramatically faster than a plain create (real numbers observed: ~0.2–0.5s vs. ~4–17s), the
claimed VM works immediately (`exec` succeeds right away), the pool tops itself back up unasked after
each claim, two claims in a row hand out two different VMs, and `pool delete` cleans up every member
it still owns with no leftover VMs or processes.

## Image catalog & signing

Reference a named, checksummed image instead of a raw path or URL — resolved transparently by
`create` before policy/existence checks, so `allowed_image_dirs` still governs the real resolved file:

```json
{"name": "job-1", "backend": "qemu", "image": "ubuntu-24.04", "...": "..."}
```

Enable it with `[catalog]` in the config:

```toml
[catalog]
path = "/etc/fluxvm/catalog.json"
# Empty = signatures not required; non-empty = every entry MUST verify against one of these.
# Named (unlike a bare list of keys) so `signed_by` below can report real signer identity,
# not just pass/fail -- the same [[auth.tokens]]-shaped "array of tables with a name" this
# project uses everywhere else it needs a labeled list of credentials.
[[catalog.trusted_signers]]
name = "release-ci"
public_key = "BASE64_ED25519_PUBLIC_KEY"
```

An image reference that doesn't match any catalog entry's `name` is treated as a literal path/URL,
exactly like before this existed — the catalog is purely additive.

Signing is a self-contained Ed25519 scheme (not cosign/Sigstore, which need either a local `cosign`
binary or a live Fulcio/Rekor round trip — neither of which this project can verify end-to-end without
external network-dependent test infrastructure):

```bash
fluxvm catalog keygen
#   private key (keep secret, use with `catalog sign --key`): ...
#   public key -- add as [[catalog.trusted_signers]] with a name: ...

fluxvm catalog sign \
  --key <private-key> --name ubuntu-24.04 \
  --source https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img \
  --sha256 <sha256> --distro ubuntu --version 24.04 --arch x86_64 \
  --build-pipeline github-actions/build-images.yml --build-run-id 987654321 --build-commit <commit-sha> \
  --catalog-file /etc/fluxvm/catalog.json   # appends/updates in place; omit to just print the entry
```

`sign` also stamps a `signed_at` (Unix seconds, right when signing runs) onto the entry, **covered by
the signature itself** — the signed payload now spans `name`/`source`/`sha256`/`format`/
`distro`/`version`/`arch`/`signed_at`/`build_pipeline`/`build_run_id`/`build_commit`, not just the
first four. Previously `distro`/`version`/`arch` were present on an entry but excluded from what was
actually signed, so they could be edited in `catalog.json` after the fact (e.g. relabeling `arch` to
mislead a platform-matching consumer) without invalidating the signature — closed now. `read_only`
stays deliberately unsigned, since it's a mutable operational flag toggled via its own REST route
(below), not provenance data — signing it would mean every legitimate toggle silently breaks the
signature.

**Build lineage** (`--build-pipeline`/`--build-run-id`/`--build-commit`, all optional) records which
CI pipeline, which run within it, and which source commit produced the image's bytes — the real gap
this closes: previously signing only ever vouched for the catalog entry's own fields (name, source,
checksum, ...), with no way to record *who built it* at all. Read this claim honestly, though: it's
asserted by whoever ran `catalog sign`, the same posture as `signed_by` below — there is no
cryptographic attestation chain proving the named CI system actually produced these bytes (that would
need something like Sigstore/in-toto, which this project's signing scheme deliberately avoids for the
same reason it avoids cosign — see above). What signing *does* give it: once set, `build_pipeline`/
`build_run_id`/`build_commit` are tamper-evident exactly like `distro`/`version`/`arch` — relabeling
any of them in `catalog.json` after the fact invalidates the signature.

**Breaking change for existing signed catalogs**: an entry signed before this existed will fail
verification against the new, wider payload — there's no dual-format fallback. Re-run `fluxvm catalog
sign` for every entry after upgrading if `trusted_signers` is configured.

With `trusted_signers` set, an unsigned (or wrongly-signed) catalog entry is rejected at `create` time
— fails closed, no silent fallback to "unsigned is fine." `GET /v1/images/catalog` lists every entry
with a computed `signature_valid`, and — new — `signed_by`: the *name* of whichever configured
`trusted_signers` entry's key actually verified the signature (`null` when unsigned, wrongly signed, or
signatures aren't required at all). This is derived fresh on every call from which key matched, not
something the entry itself claims about its own signer — an entry can't assert its own identity, only a
real key can prove it. Signing itself stays a CLI/offline operation; private keys never touch the API
surface.

**Catalog CRUD over REST** — add/remove/rename/clone/export entries without hand-editing
`catalog.json` or going through the CLI's offline sign flow (this is what zyvor-fabric's
`FluxVMDriver::ImageDriver` uses to replace machinectl's image-management verbs):

```bash
# Register a new entry — source can be a local path or an http(s) URL; sha256 is computed
# fresh from what actually lands on disk, not trusted from the caller.
curl -sS -X POST http://127.0.0.1:7788/v1/images/catalog \
  -H 'content-type: application/json' \
  -d '{"name": "ubuntu-24.04", "source": "/var/lib/fluxvm/images/ubuntu.qcow2", "format": "qcow2"}' | jq

curl -sS -X POST http://127.0.0.1:7788/v1/images/catalog/ubuntu-24.04/clone \
  -d '{"target_name": "ubuntu-24.04-staging"}' | jq
curl -sS -X POST http://127.0.0.1:7788/v1/images/catalog/ubuntu-24.04-staging/rename \
  -d '{"new_name": "ubuntu-24.04-qa"}' | jq
curl -sS -X POST http://127.0.0.1:7788/v1/images/catalog/ubuntu-24.04/export \
  -d '{"path": "/var/lib/fluxvm/exports/ubuntu-24.04.qcow2"}' | jq
curl -sS -X DELETE http://127.0.0.1:7788/v1/images/catalog/ubuntu-24.04-qa
```

A clone or rename drops any existing signature and `signed_at` (a signature covers the entry's `name`,
so it no longer vouches for the new one — the old `signed_at` timestamp would also be misleading once
detached from a valid signature). All five mutating operations are serialized against each other and
against a fresh `catalog.json` read on every call — no in-memory cache to go stale.

**The same CRUD lives on `fluxvm catalog`, too** — `keygen`/`sign` were the only catalog subcommands
this project's CLI had for a while (offline-signing needs to stay CLI/offline; private keys never touch
the API surface), leaving list/add/remove/rename/clone/export/lock unlock/clean reachable only over
REST even though the underlying `fluxvm_image::catalog` functions backing all of it (`add_entry`,
`remove_entry`, ...) always covered them. That meant a one-shot admin task against a `catalog.json` no
`fluxvm serve` was currently serving — seeding a fresh host's catalog before the daemon is even up, or a
script that would rather shell out than depend on a running HTTP endpoint — had no CLI path at all. Each
subcommand below is a thin wrapper: it operates on `catalog.path` from `--config`/`FLUXVM_CONFIG`
directly (same one-shot-process model as `fluxvm pool claim`, see its own doc comment), so it works
identically whether or not `fluxvm serve` happens to be running against the same `state_dir`:

```bash
fluxvm catalog list
#   [{"name": "ubuntu-24.04", "source": "...", "sha256": "...", "signature_valid": null, ...}, ...]

fluxvm catalog add ubuntu-24.04 --source /var/lib/fluxvm/images/ubuntu.qcow2
fluxvm catalog clone ubuntu-24.04 ubuntu-24.04-staging
fluxvm catalog rename ubuntu-24.04-staging ubuntu-24.04-qa
fluxvm catalog export ubuntu-24.04 /var/lib/fluxvm/exports/ubuntu-24.04.qcow2
fluxvm catalog lock ubuntu-24.04     # refuse remove/rename until unlocked
fluxvm catalog unlock ubuntu-24.04
fluxvm catalog remove ubuntu-24.04-qa
fluxvm catalog clean                 # prune downloads/ orphans no entry's source references any more
```

`lock`/`unlock` are new: the REST route (`POST .../read-only`) took a `{"read_only": bool}` body, which
the CLI now exposes as two verbs instead of a boolean flag — clearer on a command line than
`--read-only true`, and it keeps `fluxvm catalog --help` self-explanatory without reading the REST docs
first. Every other subcommand mirrors its REST counterpart's semantics exactly (same refuse-on-read-only,
same signature/`signed_at` clearing on `clone`/`rename`), since both ultimately call the identical
`fluxvm_image::catalog` functions.

Verified on real hardware (`scripts/test-image-catalog.sh`, 10/10): `keygen`/`sign` produce a real
verifiable entry; creating a VM by catalog name actually resolves and boots the underlying image; with
`trusted_signers` configured, an unsigned entry is rejected while a validly signed one is accepted (both
confirmed by actually trying to boot); a plain literal path still works unchanged; `GET
/v1/images/catalog` correctly reports `signature_valid: true`/`false` for the two cases. The CRUD
endpoints above were verified live against a real deployed instance: full add → list → clone →
rename → export (byte-identical file at the destination) → delete round trip, plus the duplicate-name
and not-found error paths.

## Storage backends

By default a VM's disk is provisioned the same way it always has been: a
qcow2 copy-on-write overlay for QEMU, a reflinked-or-copied raw file for
Cloud Hypervisor/Firecracker. Setting `storage` on a create request switches
to one of three alternative provisioning backends instead —
`fluxvm_core::model::StorageBackend`, implemented in `fluxvm_image::storage`:

- **`lvm-thin`** — `image` must be a `/dev/<vg>/<lv>` path to an existing
  LVM thin logical volume (in a thin pool). A fresh thin *snapshot* LV is
  created per VM (`lvcreate --snapshot`) and handed to the VMM directly as a
  raw block device — real copy-on-write at the block layer, and near-instant
  regardless of image size. Verified end to end on real hardware: create →
  a genuinely new `/dev/<vg>/eph-<id>` snapshot LV appears → the guest boots
  off it and answers `exec` → `delete` removes the snapshot LV, `stop` alone
  leaves it in place (same as the disk file is left in place for every other
  backend). Not supported under the Firecracker jailer, since its
  chroot/hardlink resource-placement model doesn't extend to a shared block
  device — use direct (non-jailed) Firecracker, QEMU, or Cloud Hypervisor.
  **Real bug found and fixed while testing this**: LVM sets a persistent
  "activation skip" flag on every new thin snapshot by default; without
  `--setactivationskip n` on the `lvcreate`, the following `lvchange -ay`
  exits 0 but silently activates nothing, and the VM fails to boot with a
  "device does not exist" error. There's also a real (if narrow) udev race —
  `lvchange -ay` returns as soon as the kernel dm target is live, before
  udev has necessarily finished creating the `/dev/<vg>/<lv>` symlink — so
  provisioning polls for that symlink for up to 5s rather than trusting the
  command's exit status alone.
- **`nbd`** — QEMU only (QEMU has a native `nbd:` block client; Cloud
  Hypervisor and Firecracker don't). The disk is the same disposable qcow2
  overlay as the default backend, but it's exported over NBD via a
  `qemu-nbd` subprocess this VM owns (over a UNIX socket, not a TCP port)
  instead of being opened directly as a local file — the same client/server
  split real remote/shared NBD storage uses, without needing a separate
  storage host to prove the mechanism end to end. Verified on real hardware:
  the exporting `qemu-nbd` process is a real, findable pid; the guest boots
  over the NBD attachment and answers `exec`; `delete` kills the export
  (`stop` alone leaves it running, so a later `start` can reattach). **Real
  bug found and fixed while testing this**: injecting the guest-agent token
  into the disk (via `guestkit`, which does its own independent qemu-nbd
  mount) after this VM's own `qemu-nbd --persistent` export was already
  running raced its write lock and failed with "Failed to get 'write' lock".
  Fixed by injecting the token before the export starts, not after.
- **`ceph-rbd`** — `rbd clone <pool>/<image>@fluxvm-base ...` and QEMU's
  native `rbd:` block driver (QEMU only; Cloud Hypervisor/Firecracker have
  no built-in Ceph client). Verified end to end against a real, live Rook
  Ceph cluster (the Atlas storage-control-plane project's lab: Rook v1.20.2
  + Ceph Squid v19.2.3, `rbd-nvme-prod` pool): imported a raw image as
  `rbd-nvme-prod/fluxvm-base`, protected an `fluxvm-base` snapshot on
  it, created a VM with `storage=ceph-rbd` — `rbd clone` produced a real
  `eph-<id>` clone, QEMU booted a real guest straight off
  `rbd:rbd-nvme-prod/eph-<id>:id=admin:conf=...` all the way to a login
  prompt, and `delete` reaped the clone (confirmed gone via `rbd ls`, no
  leak). Doesn't support automatic guest-agent token injection (`guestkit`
  needs a local file or block device to mount, not an arbitrary `rbd:`
  URI) — that combination fails fast with a clear error rather than
  attempting it.

`storage` defaults to unset (`Default`) on every create request — nothing
above changes any existing behavior unless a caller opts in.

See `scripts/test-storage-backends.sh` for the repeatable real-hardware
regression test covering `lvm-thin` and `nbd` (it also sets up a
loopback-backed thin pool from scratch if you don't already have one — see
the script's own `--help`). `ceph-rbd` isn't in that script — it was
verified manually against the specific external Rook Ceph lab above, which
this repo has no automated way to stand up or tear down; the recipe was:
`rbd import` a raw image into a pool, `rbd snap create` + `rbd snap
protect` an `fluxvm-base` snapshot on it, then create a VM with
`"storage":"ceph-rbd","image":"<pool>/<image>"`.

## Distributed node-agent

`fluxvm-agent` is the non-Kubernetes multi-host story — a caller talks to one central endpoint
instead of knowing which host a VM is on, distinct from `fluxvm-kube`'s per-node reconciliation
against a *local* fluxvm. One binary, two modes:

```bash
# Central fleet registry + create/list/delete proxy — one instance for the whole fleet.
fluxvm-agent central --listen 0.0.0.0:7799

# Per-host heartbeat client — one instance per hypervisor host, alongside a local `fluxvm serve`.
fluxvm-agent node --name worker-1 \
    --central http://fleet-registry:7799 \
    --fluxvm-url http://127.0.0.1:7788 \
    --advertise-url http://worker-1.internal:7788
```

Every `--interval-secs` (default 10), each node agent reports its name, real capacity (vCPUs off
`available_parallelism()`, RAM off `/proc/meminfo`), and current VM count (via its own local
`GET /v1/vms`) to the central registry. `POST /fleet/vms` with no `"node"` field picks the healthy
node with the fewest VMs and proxies the create there; with an explicit `"node"` it targets that node
directly. `GET /fleet/vms` aggregates every healthy node's VMs, tagged with which node each came from,
and names any node it couldn't account for in a separate `"unreachable_nodes"` field (see below) rather
than silently omitting it.
`GET /fleet/nodes/{name}/vms` narrows that same query to exactly one node, queried directly rather
than filtered out of the aggregate. `DELETE /fleet/vms/{node}/{id}` proxies to that exact node.

Verified end to end across two real, physically separate hosts (`scripts/test-fleet-agent.sh`, 11/11
passing): both hosts register with real capacity; an unaddressed create picks the least-loaded host
and produces a real QEMU process confirmed on that exact physical host (and confirmed absent on the
other); a second create lands on the *other* host once the first host's load is known — real
load-aware placement, not round-robin; the fleet-wide list correctly aggregates and tags VMs from
both hosts; a fleet-proxied delete reaps the right VM on the right host and leaves the other alone.

**Real bugs found and fixed while testing this across two actual hosts** (bugs that are invisible
running everything on one machine, which is exactly why this got tested on two real, separate hosts
instead of just trusting the code): a node's heartbeat originally reported its own `--fluxvm-url`
(almost always a loopback address) straight to central — central's proxy calls for a *remote* node
would then silently hit whatever was listening on *central's own* localhost instead, with no error at
all. Fixed by splitting `--fluxvm-url` (what this agent uses to reach its own local fluxvm) from
`--advertise-url` (what a remote central should use to reach this same fluxvm — must be a real,
externally routable address). Separately, this test script's own cleanup function first tried
`sudo pkill -f "target/release/fluxvm --config ..."` over SSH — which matched **its own** command
line (the pattern string is a substring of the `pkill` invocation's own argv) and SIGTERMed itself
before it ever reached the real target process, leaving the actual `fluxvm serve` running every
time with no error surfaced. Fixed with the standard `[t]arget/...` bracket-escape idiom that keeps
`pgrep`/`pkill -f` from matching their own invocation.

**Auth / TLS / persistence / placement**: set `--token` / `FLUXVM_AGENT_TOKEN` on both
`central` and `node` (Bearer on all `/fleet/*` except `/healthz`). Optional
`--tls-cert`/`--tls-key` on central. Registry persists to
`--state-dir/fleet-nodes.json` (survives central restart until heartbeats refresh
`last_seen`). Unaddressed creates use residual CPU/memory capacity scoring (not
only fewest-VMs).

**Cordon a node for planned maintenance** without deregistering it, waiting out
`HEALTHY_WINDOW_SECS` for a heartbeat timeout, or draining/evicting anything
already running on it:

```bash
curl -X POST http://fleet-registry:7799/fleet/nodes/worker-1/cordon
curl -X POST http://fleet-registry:7799/fleet/nodes/worker-1/uncordon
```

(add `-H "Authorization: Bearer $FLUXVM_AGENT_TOKEN"` when the registry has a
token configured, same as every other `/fleet/*` route). A cordoned node keeps
heartbeating, keeps reporting real capacity in `GET /fleet/nodes` (now with a
`"cordoned"` field alongside `"healthy"`), and any VM already on it keeps
running and keeps showing up in `GET /fleet/vms` — cordon only removes the
node from automatic placement's candidate set in a subsequent unaddressed
`POST /fleet/vms`, the same "stop scheduling here, don't touch what's already
there" semantics as `kubectl cordon`. It does *not* block an explicit
`POST /fleet/vms {"node": "worker-1", ...}` naming that exact node — matching
the same precedent: a Kubernetes Pod with `spec.nodeName` set bypasses the
scheduler and can still land on a cordoned node, because cordoning was never a
per-node admission check, only a placement-candidate filter. Cordoned state is
per-node-name in the registry, not carried in the node agent's heartbeat body
at all (the node agent has no idea cordoning exists), so it survives every
subsequent heartbeat and a central restart (it's in `fleet-nodes.json`)
without a node operator having to do anything to keep it in effect, and
without a node agent's own heartbeat ever silently clearing it back off. 9 new
unit tests in `fluxvm-agent::central` (cordoned-node placement exclusion, the
only-node-cordoned case, uncordon restoring eligibility, cordoning an unknown
node reporting not-found rather than silently succeeding, heartbeat
preserving an existing cordon vs. a brand-new node registering uncordoned,
and both directions of the explicit-`"node"`-bypasses-cordon behavior).

**See what's actually running on a node** before deciding to cordon it (or
after, to confirm nothing changed):

```bash
curl http://fleet-registry:7799/fleet/nodes/worker-1/vms
```

This is deliberately a different route from the fleet-wide `GET /fleet/vms`,
not a documented query-param filter on it: answering "what's on *one* node"
by filtering the fleet-wide list client-side would still require every
*other* node in the fleet to also be up and reachable just to answer a
question about one of them. `GET /fleet/nodes/{name}/vms` proxies straight
to that one node's own `GET /v1/vms` — it works regardless of the node's
`cordoned`/`healthy` state, tags each VM with `"node"` the same way the
fleet-wide list does, and turns that node being unreachable or erroring
into a real `502` naming the node instead of an empty, unexplained list.
Unknown node name is a `400`, same as every other `/fleet/*` route that
takes a `{name}` path segment. 5 new tests in `fluxvm-agent::central`
against a real (not mocked) minimal HTTP server standing in for the node —
happy path with correct tagging, unknown node, an unreachable node, a node
whose own `/v1/vms` itself errors, and a node with zero VMs.

**Know when the fleet-wide list is incomplete.** `GET /fleet/vms` originally
dropped any node it couldn't account for — one excluded up front for a stale
heartbeat, or one whose `GET /v1/vms` call failed partway through — with
nothing but a server-side `tracing::warn!` the caller never saw; a fleet
member being down looked identical to it simply having no VMs. The response
now carries a second field naming exactly which nodes that happened to and
why:

```bash
curl http://fleet-registry:7799/fleet/vms
# {
#   "items": [ ... VMs from every node that did answer, "node"-tagged ... ],
#   "unreachable_nodes": [
#     { "node": "worker-2", "reason": "unhealthy (stale heartbeat)" },
#     { "node": "worker-5", "reason": "unreachable: error sending request..." }
#   ]
# }
```

`"unreachable_nodes"` is `[]` on the ordinary all-healthy path — existing
callers that only ever read `"items"` see no behavior change. A caller that
does care whether the list it just got is the *whole* fleet's now has a
direct way to check, instead of having to cross-reference `GET /fleet/nodes`
or grep server logs to rule out a silent gap. Each reason distinguishes a
node excluded before it was even queried (stale heartbeat) from one that
was queried and failed (connection error, a non-2xx from its own
`GET /v1/vms`, or an unparseable body), matching the same three failure
modes `GET /fleet/nodes/{name}/vms` already turns into a `502` for the
single-node case — this just extends that surface-don't-hide behavior to
the aggregate instead of requiring a per-node loop to get it. 4 new tests in
`fluxvm-agent::central`: all-healthy-and-reachable reports an empty
`unreachable_nodes`; an unreachable node is named without losing the other
node's real VMs; a stale-heartbeat node is named without ever being
contacted; a node that rejects the call with a non-2xx is named with its
own error message included in the reason.

## State layout

```text
/var/lib/fluxvm/
  vms.json
  vms.lock
  network-policy/             (per-VM dataplane policy JSON)
  network-groups/             (security groups, CNP store, ipcache.json)
  downloads/
  images/
  kernels/
  templates/                 ([sandbox].templates_dir; OCI→template export)
  instances/
    <uuid>/
      root.qcow2 | root.raw
      seed.img
      user-data
      meta-data
      console.log
      qmp.sock | ch-api.sock | firecracker.sock | fluxvm.sock
      vsock.sock              (CH / Firecracker / FluxVm, when agent.enabled)
      firecracker.json
      snapshot/               (FluxVm memory+disk snapshots)
      nbd.sock | nbd.pid      (storage=nbd only — see "Storage backends" above)
```

`storage=lvm-thin` and `storage=ceph-rbd` disks live outside this tree entirely — a thin
snapshot LV (`/dev/<vg>/eph-<id>`) and an RBD clone (`rbd:<pool>/eph-<id>:...`) respectively,
both torn down by `delete` via `VmRecord.lvm_lv`/parsing the `rbd:` URI, not by deleting
anything under `instances/<uuid>/`.

`vms.lock` coordinates `vms.json` reads/writes across concurrent `fluxvm` processes (each CLI
invocation is a separate process, not just a separate task inside `serve`) via an OS-level `flock` —
without it, two VMs created at the same moment could silently lose one's record, or both get
assigned the same vsock CID.
