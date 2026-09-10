# FluxVM Set 9 — AF_XDP Fast Path

Set 9 adds an optional two-interface AF_XDP bridge for dedicated VM network paths. It is not a replacement for Cilium, Zyvor Fabric, or the normal FluxVM TC/XDP policy path.

## Safety and ownership

The planner requires explicit `--dedicated` confirmation. The loader queries DRV, SKB and HW XDP ownership on both interfaces and refuses to replace an existing XDP program. This prevents Set 9 from silently stealing a Cilium or other shared-NIC hook. If the worker exits or its XSK disappears, the BPF program's `bpf_redirect_map(..., XDP_PASS)` fallback keeps traffic on the kernel path.

## Data path

One BPF object is attached to both interfaces and owns one shared XSKMAP. Interface slots plus RX queue IDs form unique XSKMAP keys. The worker creates one shared UMEM and one AF_XDP socket per side, then forwards descriptor ownership from an RX ring directly into the peer TX ring. Each unique netdev/queue tuple has its own fill/completion pair, as required by AF_XDP shared-UMEM semantics.

`auto` permits copy fallback. `zerocopy` forces `XDP_ZEROCOPY` and startup fails unless both sides report `XDP_OPTIONS_ZEROCOPY`. `XDP_USE_NEED_WAKEUP` is always enabled. Set 9 v1 intentionally refuses MTU >3500 and drops multi-buffer descriptor chains rather than forwarding a partial jumbo packet.

## Usage

```text
fluxvm-afxdp probe
fluxvm-afxdp plan <uuid> <iface-a> 0 <iface-b> 0 auto --dedicated plan.json
sudo fluxvm-afxdp start plan.json
fluxvm-afxdp status <uuid>
fluxvm-afxdp metrics <uuid>
fluxvm-afxdp events <uuid> 5 128
sudo fluxvm-afxdp stop <uuid>
fluxvm-afxdp serve 127.0.0.1:7795
```

Use one Set-9 worker per queue pair. RSS queue selection remains an explicit topology operation; Set 9 does not rewrite NIC RSS tables or Cilium/Fabric policy.

## Failure behavior

The optional fast path is continuity-safe. Missing/disabled queue gates return `XDP_PASS`; missing XSK entries use `XDP_PASS` as the redirect fallback action. Start failure unloads only the exact XDP program ID that FluxVM pinned. Stop sends TERM to the worker, waits briefly, then unloads only FluxVM-owned attachments.
