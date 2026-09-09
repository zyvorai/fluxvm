# FluxVM Secure Containers — Set 5

Set 5 adds production-oriented stdio transport and TTY/PTY behavior on top of
Set 4 volumes + guest security hardening.

## VSOCK stdio transport

Lifecycle RPC remains on VSOCK port **17778**. Long-lived process I/O uses a
separate authenticated stream endpoint on VSOCK port **17779**.

For each process, the shim opens only the streams containerd requested:

- stdin: containerd FIFO -> VSOCK -> guest pipe/PTY
- stdout: guest pipe/PTY -> VSOCK -> containerd FIFO
- stderr: guest pipe -> VSOCK -> containerd FIFO

The attach handshake carries the VM's existing guest-agent token plus container
ID, optional exec ID, and stream kind. After the JSON acknowledgement, the
connection becomes a raw byte stream. This keeps lifecycle messages small and
avoids framing overhead on stdout/stderr payloads.

`FLUXVM_CONTAINER_STREAMING_STDIO=1` is the default. Set it to `0` to retain the
Set 3/4 regular-file virtiofs relay for non-TTY debugging. TTY requires VSOCK
streaming.

## Guest PTY

When OCI/containerd requests `terminal=true`, the guest agent creates a real
pseudo-terminal pair. The child becomes a session leader, owns the PTY slave as
its controlling terminal, and receives the slave on stdin/stdout/stderr.

The agent keeps the PTY master for:

- stdin and combined terminal output streaming
- `ResizePty` (`TIOCSWINSZ`)
- best-effort `CloseIO` EOF delivery

Non-TTY processes use independent guest pipes for stdin/stdout/stderr.

## Interactive exec

`ExecProcessRequest` now accepts terminal processes. Execs use the same stream
attach model as init processes, keyed by container ID + exec ID. containerd task
Create/Start/Exit/Delete event behavior from Set 3 remains unchanged.

## Exit/drain semantics

The shim tracks outstanding VSOCK output relays by process. Before publishing
TaskExit / returning Wait or Delete, it gives stdout/stderr relay tasks a bounded
chance to reach EOF and flush the containerd destination. The old virtiofs
size-stabilization drain remains available only for legacy stdio mode.

## Remaining gates

- namespace creation parity (PID/mount/IPC/UTS/user) inside the Pod VM
- device-cgroup enforcement and broader OCI conformance
- seccomp argument comparators / notify
- allowlisted arbitrary hostPath broker/hotplug
- IPv6 + multi-interface CNI conformance
- Cloud Hypervisor / Firecracker shared-rootfs parity
- real KVM/containerd/Kubernetes churn and terminal-resize CI on self-hosted nodes

## Test on a real KVM/containerd node

```bash
sudo ./scripts/e2e-secure-containers-ctr.sh
sudo ./scripts/e2e-secure-containers-tty.sh
```

The TTY test checks both an init TTY and a TTY exec, including terminal-size
propagation through containerd's `ResizePty` call.
