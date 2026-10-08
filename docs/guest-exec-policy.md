# Guest exec policy

Confine a single command inside a VM. The request carries a policy; the guest agent applies it with
Landlock and seccomp (through `fluxvm-procbox`) before the command runs, and reports what it actually
enforced.

## Roadmap and status

| Item | Implemented and type-checked | Verified on hardware |
|---|---|---|
| `policy` on `POST /v1/vms/{uuid}/agent` and `POST /v1/sandboxes/{id}/process` | yes (unit tests pass) | not yet |
| `ExecPolicy` wire type, procbox-compatible JSON | yes (parse and conversion tests) | not yet |
| Landlock and seccomp enforcement in the guest agent | yes | not yet |
| Fail-closed on unenforceable policy | yes | not yet |
| `ExecEnforcement` in the exec response | yes | not yet |
| `fluxctl exec --policy FILE` | yes | not yet |
| Agent refuses requests without a token | yes | not yet |

Nothing in this batch has been run end-to-end on real VMs. The enforcement code is procbox's, which is
covered by its own tests (see [procbox.md](procbox.md)); the new part is the plumbing through the agent.

## Policy JSON

The shape is the `fluxvm-procbox` policy JSON, so a policy written for procbox can be passed through
unchanged. Unknown fields are ignored (for example `max_abi`); missing fields take the safe defaults.
`{}` is a valid policy: no filesystem access, no network, IPC scoping on, seccomp errno.

```json
{
  "read": ["/bin", "/usr", "/lib", "/lib64", "/etc/ssl"],
  "write": ["/tmp/work"],
  "tcp_connect": {"ports": [443]},
  "tcp_bind": "deny",
  "scope_ipc": true,
  "seccomp": "errno",
  "allow_namespaces": false,
  "max_memory": 268435456,
  "max_processes": 200,
  "cpu_seconds": 30,
  "timeout_secs": 30,
  "clean_env": true,
  "env": [["FOO", "bar"]],
  "cwd": "/tmp/work",
  "best_effort": false,
  "max_output_bytes": 1048576,
  "run_as": {"uid": 1000, "gid": 1000},
  "isolation": "off",
  "allow_unix": false,
  "allow_udp": false
}
```

| Field | Type | Default | Meaning |
|---|---|---|---|
| `read`, `write` | paths | `[]` | Filesystem paths the command may read or write |
| `tcp_connect`, `tcp_bind` | `"any"`, `"deny"` or `{"ports": [n, ...]}` | `"deny"` | Landlock TCP rules |
| `scope_ipc` | bool | `true` | Scope abstract unix sockets and signals |
| `seccomp` | `"errno"`, `"kill"` or `null` | `"errno"` | Denylist action; `null` turns the filter off |
| `allow_namespaces` | bool | `false` | Permit creating namespaces |
| `max_memory`, `max_processes`, `cpu_seconds` | number | none | `RLIMIT_AS`, `RLIMIT_NPROC`, `RLIMIT_CPU` |
| `timeout_secs` | number | none | Wall-clock timeout. Capped by the request's `timeout_seconds`: a policy can only shorten it |
| `clean_env`, `env`, `cwd` | | `false`, `[]`, none | Environment and working directory |
| `best_effort` | bool | `false` | Run with what the kernel can enforce and report the rest |
| `max_output_bytes` | number | procbox default | Output capture cap |
| `run_as` | `{uid, gid}` | none | Drop to this id before confining |
| `isolation` | `"off"`, `"auto"`, `"strict"` | `"off"` | Private namespaces with a root holding only granted paths |
| `allow_unix`, `allow_udp` | bool | `false` | Keep those socket families when the network is restricted |

**Read paths must include `/bin` and `/usr`.** The agent runs the command as `/bin/sh -c <command>`.
Under a policy the command can read only what `read` or `write` lists, so a policy without `/bin` and
`/usr` cannot even start the shell, and shared libraries usually also need `/lib` and `/lib64`. A
minimal working read list is `["/bin", "/usr", "/lib", "/lib64"]`; add `/etc` entries the command
needs (certificates, `resolv.conf`).

## Enforcement and fail-closed behavior

Without `policy`, nothing changes: the command runs unconfined and the response has no `enforcement`
key.

With `policy`:

1. The agent converts the policy and runs it through procbox. Landlock confines the filesystem and
   TCP ports, seccomp denies a syscall denylist, and rlimits, `run_as` and `isolation` apply as set.
2. **Strict by default.** If the guest kernel cannot enforce something the policy asks for, the
   command is **not run**, and the response is an error:
   `policy could not be enforced, command not run: ...`. Strict mode needs Landlock ABI 3 or later,
   and the default `scope_ipc: true` needs ABI 6 (Linux 6.12 or later). On an older guest kernel,
   either upgrade it, set `scope_ipc` to `false`, or set `best_effort` to `true`.
3. With `best_effort: true` the command runs with what the kernel can enforce, and the gaps are listed
   in `enforcement.not_enforced`. Check that list before trusting the run.
4. A command that outlives its timeout is killed and reported as an error. The timeout is the smaller
   of the policy's `timeout_secs` and the request's `timeout_seconds` (default 30 s).
5. Procbox sandboxes are already confined by their own spec, so a per-exec `policy` on one is
   rejected with 400.

## ExecEnforcement result

The exec response gains `enforcement`:

```json
{
  "result": "exec",
  "exit_code": 0,
  "stdout": "...",
  "stderr": "",
  "enforcement": {
    "landlock_abi": 6,
    "filesystem": true,
    "tcp_connect": true,
    "tcp_bind": true,
    "scope_abstract_unix": true,
    "scope_signal": true,
    "seccomp": true,
    "uid_dropped": false,
    "namespaces": false,
    "network_isolated": false,
    "seccomp_sockets": true,
    "not_enforced": []
  }
}
```

`not_enforced` lists everything the policy asked for that this run did not enforce; it is empty in
strict mode. A caller that needs a guarantee should check `not_enforced == []` and the specific booleans
it relies on, rather than only the exit code.

## CLI and REST

```bash
cat > build-policy.json <<'EOF'
{"read": ["/bin", "/usr", "/lib", "/lib64"], "write": ["/tmp/work"], "tcp_connect": "deny"}
EOF
fluxctl exec $VM --policy build-policy.json --timeout-seconds 60 -- 'cd /tmp/work && make'
```

`fluxctl exec --policy FILE` parses the JSON locally (unknown fields ignored, missing ones defaulted)
and prints the response including `enforcement`. It runs through the local manager; `fluxctl exec` is
not available with `--server`, so use REST there:

```bash
curl -sS http://127.0.0.1:7788/v1/vms/$VM/agent \
  -H 'content-type: application/json' \
  -d '{"command":"ls /usr","policy":{"read":["/bin","/usr","/lib","/lib64"]}}'
```

The same `policy` field is accepted by `POST /v1/sandboxes/{id}/process`. See [api.md](api.md).

## Agent token: fail closed

The guest agent authenticates requests with a token provisioned into the guest. This batch also
changes what happens when there is none:

- Token file present: requests must carry it (unchanged).
- Token file missing: the agent **refuses every request** with
  `unauthorized: guest agent has no token provisioned ...` and logs an error at startup.
- `FLUXVM_AGENT_ALLOW_INSECURE=1` (also `true`, `yes`, `on`) in the agent's environment restores the
  old behavior: the agent runs unauthenticated, logs a warning, and any vsock caller can run commands
  as root.

**Compatibility warning for older guest images.**

- An image built with an earlier agent that has no token and relied on running unauthenticated will
  stop working once its agent is upgraded to this version, until you provision the token or set
  `FLUXVM_AGENT_ALLOW_INSECURE=1`. Prefer provisioning the token; the opt-in is for development
  images.
- An older agent does not know the `policy` field. The protocol ignores unknown fields, so it would
  run the command **unconfined** and the response would have no `enforcement` key. When you send a
  policy, treat a response without `enforcement` as "not confined", and rebuild the guest image with
  this agent version before depending on confinement.
