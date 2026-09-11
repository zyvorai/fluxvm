# Patched `containerd-shim` 0.11.0 (FluxVM)

Vendored from crates.io `containerd-shim` **0.11.0** with FluxVM-local
fixes for containerd **≥ 2.3** / k3s 1.36+.

## Problems addressed

1. **BootstrapParams stdin** — containerd 2.3+ always writes `BootstrapParams`
   on shim `start` stdin. Stock 0.11 parses stdin as legacy `Any(Options)`
   inside `set_cgroup_and_oom_score`, dying with `IncorrectTag(46)` (ASCII
   `.` from namespace `k8s.io`). Same failure: [smolvm#889](https://github.com/smol-machines/smolvm/issues/889).
2. **Missing `TTRPC_ADDRESS`** — BootstrapParams path may omit the env var;
   derive `{address}.ttrpc` from `-address`.
3. **`-info` / `-version`** — handled before requiring TTRPC / task socket.

## FluxVM delta

- `src/cgroup.rs`: on unparseable stdin, warn and skip `shim_cgroup`.
- `src/asynchronous/mod.rs`: TTRPC fallback; early `-info`/`-version`;
  tolerant `run_info` Options parse.

Remove this patch once crates.io ships equivalent fixes.
