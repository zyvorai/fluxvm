# AI agents over MCP (`fluxctl mcp serve`)

`fluxctl mcp serve` is a [Model Context Protocol](https://modelcontextprotocol.io)
server on stdin/stdout. An MCP client such as
[Hermes Agent](https://github.com/NousResearch/hermes-agent) starts it as a
subprocess and uses it to inspect, and optionally operate, the VMs of one
FluxVM daemon. It talks to the daemon over the REST API, the same way
`fluxctl --server` does; it never opens the state directory.

Kairon has a matching server, `kaironctl mcp serve`, for the cluster view of
Kairon Machines (see Kairon's `docs/guides/hermes-mcp.md`).

## Tools

Read tools are always offered:

| Tool | What it returns | API |
| --- | --- | --- |
| `list_vms` | VMs with id, name, status, backend, guest IP, vCPUs, memory, labels and error; `selector` filters by labels | `GET /v1/vms` |
| `get_vm` | One VM's full record | `GET /v1/vms/{id}` |
| `host_status` | `/readyz` (KVM, dataplane mode and BPF/Cilium health, secure containers) plus a count of VMs by status | `GET /readyz`, `GET /v1/vms` |
| `vm_network` | `kind` = `status`, `effective`, `stats`, `flows`, `drops`, `drop-reasons`, `learned-ip`, `conntrack` or `capture`; `limit` for flows and drops | `GET /v1/vms/{id}/network/{kind}` |
| `vm_logs` | The last `lines` (default 100, max 500) of the serial console log | `GET /v1/vms/{id}/logs` |

Write tools are offered only with `--allow-write`:

| Tool | Effect | API |
| --- | --- | --- |
| `vm_power` | `op` = `start`, `stop`, `pause`, `resume` or `restart` | `POST /v1/vms/{id}/{op}` |
| `vm_capture` | A 1-30 s tcpdump capture (optional `filter`). With `output`, waits and writes the pcap to that path on the machine running fluxctl; otherwise returns the token | `POST` / `GET /v1/vms/{id}/network/capture[/{token}]` |

Create, delete, migrate, exec, and edge or policy changes are not exposed.

`vm` accepts a VM name, a UUID or a unique UUID prefix. Unknown or missing
required arguments are rejected with an error the model can read.

For a VM that Kairon manages, power changes made here are reverted on
Kairon's next reconcile; use Kairon's `set_power_state` instead.

## Configure Hermes

```yaml
mcp_servers:
  fluxvm:
    command: fluxctl
    args: ["mcp", "serve"]          # add "--allow-write" for vm_power and vm_capture
    env:
      FLUXVM_URL: "http://127.0.0.1:7788"
      FLUXVM_TOKEN: "..."           # when auth.require is on
    timeout: 120
```

Then `/reload-mcp` in Hermes. The tools appear as `mcp_fluxvm_list_vms` and
so on.

The daemon is chosen like any remote `fluxctl` command: `--server` or
`FLUXVM_URL`, then `--context` or the current context, and otherwise
`listen` from the config file (`--config` / `FLUXVM_CONFIG`). With
`auth.require` on, a `read-only` token covers the read tools except
`vm_network` with `conntrack` or `capture`, which need `admin`; the write
tools need `admin`.

## Security

- The server has no listener and no identity of its own. It acts with the
  token it is given, so the token's role is the real limit.
- Writes are opt-in per server (`--allow-write`). Hermes can narrow the
  list further with `tools.include` / `tools.exclude`.
- Tool results include data a guest can influence (console log, flows,
  drops). An agent that reads them and also has write tools can be steered;
  keep agents that look at untrusted VMs read-only.
- `vm_capture` with `output` writes a file with the server process's
  permissions.
- Output is capped at 64 KB per call (with a truncation note). Calls time
  out after 30 s; power changes after 120 s; a capture after its length plus
  45 s.

## Testing without Hermes

```bash
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list"}' \
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"host_status","arguments":{}}}' \
  | FLUXVM_URL=http://127.0.0.1:7788 fluxctl mcp serve
```

Logs go to stderr; stdout carries only protocol messages. The server
implements the tools capability only (no MCP resources or prompts) and
accepts protocol versions 2024-11-05, 2025-03-26 and 2025-06-18.
