## Secure Containers Set 5 — VSOCK stdio + TTY/PTY

### What changed

- keep lifecycle JSON RPC on VSOCK 17778
- add authenticated long-lived stdio streams on VSOCK 17779
- use guest pipes for non-TTY stdin/stdout/stderr
- use a real guest PTY for terminal init/exec processes
- forward containerd ResizePty to TIOCSWINSZ
- forward CloseIO and close/EOF guest stdin
- track output relay drain before TaskExit / Wait / Delete
- retain legacy virtiofs regular-file stdio behind an environment fallback
- add TTY + exec smoke coverage for self-hosted KVM/containerd nodes

### Why

Set 3/4 regular-file stdio solved virtiofs FIFO visibility but still required
polling and could not implement terminal semantics. A dedicated VSOCK stream
keeps payload I/O off the shared filesystem and lets the guest own a real PTY.

### Compatibility

- default: `FLUXVM_CONTAINER_STREAMING_STDIO=1`
- fallback: set it to `0` for legacy non-TTY regular-file stdio
- TTY requires streaming mode
- QEMU remains the production target for Secure Containers because the shared
  rootfs/volume path is still QEMU/virtiofs-based

### Validation

See `TEST_REPORT.md`. Static validation and patch apply-check pass in the
artifact environment. Rust compilation and live KVM/containerd tests require a
real build/lab node.
