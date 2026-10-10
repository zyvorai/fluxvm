# Topology labels for a Mac fleet

For Macs connected by Thunderbolt or 10 GbE, labels on each node let a scheduler keep VMs that talk to each other on the fast fabric
and spread replicas across failure domains.

| Label                         | Example        | Use                                    |
|-------------------------------|----------------|----------------------------------------|
| `kairon.zyvor.dev/topology`   | `tb5-mesh`     | Macs on the same Thunderbolt fabric     |
| `kairon.zyvor.dev/rack`       | `studio-a`     | failure domain                         |
| `kairon.zyvor.dev/net`        | `10gbe`        | management network                     |
| `kairon.zyvor.dev/chip`       | `m4-max`       | Apple silicon generation               |
| `kairon.zyvor.dev/memory-gib` | `64`           | unified memory                         |

Set them when starting the node agent, one `--label` each (see
[examples/topology-labels.yaml](../examples/topology-labels.yaml)):

```bash
args=()
while IFS=': ' read -r k v; do [[ $k == \#* || -z $k ]] || args+=(--label "$k=${v//\"/}"); done < examples/topology-labels.yaml
fluxvm-agent node --name studio-1 --central https://fleet.example:7790 "${args[@]}"
```

The built-in registry uses labels as a hard filter only: `POST /fleet/vms {"nodeSelector": {"kairon.zyvor.dev/topology":
"tb5-mesh"}}` places on a node carrying exactly that label, or fails. Soft preferences ("same fabric if possible") are for Kairon. None
of this is needed for a single Mac.
