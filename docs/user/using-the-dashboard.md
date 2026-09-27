# Using the CLI and REST API

FluxVM is primarily a **CLI + REST** control plane (port **7788**). Day-2
orchestration UI lives in [Zyvor Fabric](https://github.com/zyvorai/fabric)
(`:9095`). This page maps common jobs to both surfaces.

## CLI cheat sheet

| Job | Command |
|-----|---------|
| Create | `fluxctl create --spec examples/qemu.json` |
| List | `fluxctl list` |
| Exec (Linux agent) | `fluxctl exec <id> -- cmd` |
| QGA (Windows) | `fluxctl qga ping\|powershell\|firewall-open <id> …` |
| Delete | `fluxctl delete <id>` |
| Restart / rename / label | `fluxctl restart\|rename-vm\|label <vm> …` |
| Bulk by label | `fluxctl list -l env=dev`, `fluxctl stop -l env=dev` (`delete -l` needs `--yes`) |
| Wait for state | `fluxctl wait <vm> --for running --timeout 120` |
| Clone | `fluxctl clone-vm <stopped-vm> <new-name>` |
| Disks | `fluxctl disk list\|attach\|resize\|detach <vm> …` |
| Serial console | `fluxctl serial <vm>` (Ctrl-] quits) |
| Backup | `fluxctl backup <vm> [--compress] [--all-disks] [--dest f.qcow2]` |
| Snapshots | `fluxctl snapshot\|snapshot-list\|snapshot-delete <vm> …` |
| VM templates | `fluxctl vm-template save\|list\|show\|delete\|create …` |
| Events / quota | `fluxctl events -f`, `fluxctl quota` |
| Remote host | `fluxctl --server http://host:7788 list`, or `fluxctl context add\|use …` |
| Output format | `-o json\|table\|wide` on every command |
| Build image | `fluxctl build-image --spec examples/build-image.json` |
| Pool | `fluxctl pool create\|claim\|list …` |
| Serve API | `fluxctl serve` |

Always pass `--config /etc/fluxvm.toml` when not using defaults.

## REST basics

```bash
export API=http://127.0.0.1:7788
export AUTH=(-H "Authorization: Bearer $TOKEN")   # if auth.enabled

curl -sf "$API/readyz" | jq .
curl -sf "${AUTH[@]}" "$API/v1/vms" | jq .
curl -sf "${AUTH[@]}" -H "Content-Type: application/json" \
  -d @examples/qemu.json "$API/v1/vms"
```

Auth-exempt: `/healthz`, `/readyz`, `/v1/openapi.json`. Everything else needs a bearer token when
`[auth] require = true`.

## When to use Fabric instead

| Need | Use |
|------|-----|
| Browser console, fleet UX, DRS, backups UI | Fabric `/app/*` |
| Maglev service CRUD with multi-node leases | Fabric Edge Dataplane → Services |
| Per-VM eBPF policy from a console | Fabric VM → Dataplane tab |
| Single-host lab / CI scripts | FluxVM CLI/REST directly |

Fabric user guides: [fabric docs/user](https://github.com/zyvorai/fabric/tree/main/docs/user).

## Related tutorials

- [Getting started](getting-started.md)
- [Common workflows](workflows.md)
- [Network policy](../tutorials/network-policy/README.md)
- [MicroVM](../tutorials/microvm/README.md)
- [Service Fabric operator](../service-fabric.md)
