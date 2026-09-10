# Sentinel GA release checklist

Use this as a release-engineering checklist, not as an automated claim.

- Record FluxVM commit, kernel release/config, distro, CPU topology, NIC driver/
  firmware, storage backend and microcode/BIOS versions.
- Run the Set 12E static and host recovery gates.
- Load every enabled BPF object through the real kernel verifier on each
  supported kernel line; preserve verifier logs on failure.
- Exercise service crash/restart for Runtime Intelligence, VMM Guard, network
  intelligence, memory profiler, topology intelligence, AF_XDP, QUIC LB and
  sched_ext where enabled. Confirm packet/scheduling fail-safe behavior.
- Fill bounded maps to their documented limits and verify controlled rejection,
  loss counters and recovery rather than silent widening or corruption.
- Upgrade from the prior released pin/map schema, then rollback. Verify stale
  maps/program links are either reused by compatible ABI or rejected/cleaned by
  explicit ownership rules.
- Run boot, runnable latency, block I/O, network, migration and ring-buffer-loss
  benchmarks long enough to include warm and steady-state behavior.
- Repeat performance tests with Sentinel disabled to record overhead, not just
  absolute numbers.
- Verify BPF LSM enforce mode cannot be downgraded by an unprivileged VM/VMM.
- Verify XDP/TCX/AF_XDP code refuses an existing foreign datapath owner.
- Verify sched_ext watchdog/fallback by terminating the userspace scheduler on a
  disposable host.
- Run at least one live-migration test with dataplane state + topology/AF_XDP/
  QUIC affinity teardown/recreation.
- Archive `sentinel-ga-evidence.sh` output, measurement JSON, certification JSON,
  benchmark logs and CI run IDs with the release.
