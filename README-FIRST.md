# FluxVM Secure Containers — Set 5 handoff

## Base

This is a **Set 5 delta on top of Set 4**. Current public `zyvorai/fluxvm` main
was rechecked at `33be3ffb56c958253bc0a449a62d4ff6f871c5e7`; Set 4 itself was built
from the earlier Set 3 runtime line. Apply Set 4 first if it is not already in
your branch, then apply `patches/0005-secure-containers-vsock-tty.patch`.

## Set 5 adds

1. Dedicated authenticated VSOCK stdio endpoint on port 17779.
2. Raw stdin/stdout/stderr streaming without virtiofs polling files.
3. Real guest PTY for `terminal=true` containers and execs.
4. containerd `ResizePty` -> guest `TIOCSWINSZ`.
5. `CloseIO` forwarding and stdin EOF handling.
6. Per-process VSOCK output drain before exit publication/Wait/Delete.
7. TTY + interactive-exec KVM smoke script.
8. Legacy regular-file stdio fallback via `FLUXVM_CONTAINER_STREAMING_STDIO=0`.

## Apply

```bash
git checkout <branch-with-set4>
git apply --check patches/0005-secure-containers-vsock-tty.patch
git apply patches/0005-secure-containers-vsock-tty.patch
```

The ZIP also carries complete replacement files for manual review.

## Validation status

Static/source checks, `git diff --check`, and patch apply-check are recorded in
`TEST_REPORT.md`. This artifact environment has no Rust toolchain (including
`rustfmt`), `/dev/kvm`, QEMU, or running containerd, so it does **not** claim
cargo compilation, formatting/clippy execution, or KVM E2E execution.
