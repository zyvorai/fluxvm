# Registering a Mac as a fleet node

On each Mac, run the daemon and the node agent in the logged-in user's session (snapshot restore needs it; see
[launchd-notes.md](launchd-notes.md)):

```bash
fluxctl --config ~/.config/fluxvm/fluxvm.toml serve        # vz backend, with the density settings from examples/fluxvm-density.toml

fluxvm-agent node \
  --name studio-1 \
  --central https://fleet.example:7790 \
  --advertise-url http://studio-1.local:7788 \
  --token "$FLUXVM_AGENT_TOKEN" \
  --label kairon.zyvor.dev/backend.vz=true \
  --label kairon.zyvor.dev/chip=m4-max \
  --label kairon.zyvor.dev/memory-gib=64
```

With Kairon's own `kairon-node` instead of `fluxvm-agent node`, it should read the same `GET /v1/sandboxes/density` from the local
daemon and report it the same way.

Every `fluxvm-agent node` heartbeat carries the host's totals, its VM count, the labels, and the daemon's `GET /v1/sandboxes/density` (memory-pressure
level, available memory, warm slots ready, sandbox counts). Nothing else has to report pressure; `memory_pressure` and `vm_stat` are
read by the daemon.

`fluxctl serve` listens on `127.0.0.1:7788` by default. For a remote central registry, set `listen` to an address the registry can
reach, turn on API auth, and pass that address as `--advertise-url`.

For the `agent-micro` image, register it in the catalog on every Mac (see [docs/agent-micro.md](../docs/agent-micro.md)); a Mac
without it fails creates that ask for it.
