# FluxVM Sentinel GA benchmark contract

`sentinel-ga-budgets.json` is the versioned release contract consumed by
`tools/fluxvm-sentinel-certify.py`.  Measurements are intentionally produced by
separate workload-specific harnesses so the certification evaluator does not
hide how a number was obtained.

A measurement file is JSON:

```json
{
  "schema_version": 1,
  "metadata": {"host": "lab-a", "kernel": "6.12.0"},
  "metrics": {
    "vm_boot_p95_ms": 812.4,
    "vm_runnable_p99_ms": 1.7,
    "block_io_p99_ms": 3.1,
    "network_rtt_p99_ms": 0.42,
    "packet_loss_pct": 0.0,
    "throughput_gbps": 12.4,
    "migration_downtime_p95_ms": 74.0,
    "ebpf_ringbuf_loss_pct": 0.0
  }
}
```

Missing metrics are **not silently passed**. The evaluator reports them as
`missing`; use `--require-all-metrics` for a hard failure. This lets a developer
run a partial benchmark while the release gate remains strict.
