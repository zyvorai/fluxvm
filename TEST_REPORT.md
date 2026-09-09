# Test report — FluxVM Secure Containers Set 5

## Reviewed base

Set 5 is a delta on top of the Set 4 handoff. Public `zyvorai/fluxvm` main was
rechecked while building this set at:

`33be3ffb56c958253bc0a449a62d4ff6f871c5e7`

Set 5 is transport-focused: lifecycle RPC remains on VSOCK 17778 and dedicated
long-lived stdin/stdout/stderr streams use VSOCK 17779.

## Checks executed in this artifact environment

PASS:

- `bash -n` for every shell script in the bundle
- TOML parse for every `.toml` file in the bundle
- YAML parse for deployment/workflow manifests
- Rust lexical delimiter balance for all Set 5 Rust sources
- source review of pipe/PTY file-descriptor ownership across `fork()`
- source review of stream authentication and one-shot stream attachment
- source review of output drain and process cleanup paths
- containerd stdio endpoint existence validation before guest stream consumption
- `git diff --check` for the Set 5 repository delta
- `git apply --check` for `patches/0005-secure-containers-vsock-tty.patch`
- ZIP integrity test and SHA-256 manifest generation

## Important execution limitation

This artifact environment does **not** provide `cargo`, `rustc`, `rustfmt`,
`/dev/kvm`, QEMU, a running containerd, kubelet, or a secure-container guest
image. Therefore this report does not claim:

- Rust compilation / rustfmt / clippy success
- VSOCK AF_VSOCK execution against a live guest
- PTY execution or `TIOCSWINSZ` behavior in a FluxVM guest
- `ctr run --tty` or `ctr task exec --tty` E2E success
- KVM/containerd/Kubernetes runtime validation

## Required merge gate

Run repository CI, then on a Linux KVM node verify at least:

1. non-TTY `ctr run` stdout/stderr over VSOCK 17779
2. stdin forwarding and CloseIO/EOF behavior
3. `ctr run --tty` with `test -t 0` / `test -t 1`
4. terminal window resize propagation through `ResizePty`
5. non-TTY init + `ctr task exec --tty` interactive exec
6. simultaneous stdout/stderr for non-TTY processes
7. process exit while output is still draining
8. kill/delete during active stdin and output streams
9. repeated exec churn with no leaked stream threads/file descriptors
10. Set 4 PVC + CNI behavior together with Set 5 streaming stdio
11. legacy fallback with `FLUXVM_CONTAINER_STREAMING_STDIO=0`

`scripts/e2e-secure-containers-tty.sh` provides the init-TTY + exec-TTY +
resize smoke on a suitable KVM/containerd node.
