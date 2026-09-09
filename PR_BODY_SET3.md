## Secure Containers Set 3 — lifecycle events + OCI hardening

### Summary

This change completes the next containerd runtime-v2 lifecycle layer on top of
Secure Containers Set 2. It publishes containerd task events, tracks init and
exec exits independently, makes delete return definitive guest exit metadata,
and strengthens the guest OCI process setup with supplementary groups, umask,
rlimits, noNewPrivileges and Linux capability sets.

### Runtime correctness

- publishes TaskCreate/TaskStart/TaskExecAdded/TaskExecStarted
- publishes TaskPaused/TaskResumed/TaskExit/TaskDelete
- background Wait watcher emits asynchronous TaskExit
- de-duplicates TaskExit against force-delete/explicit Wait races
- keeps per-exec process metadata and stdio staging separate
- preserves current-main virtiofs regular-file stdio behavior
- cleans stale rootfs/mount staging on retry/failure

### OCI hardening

- additionalGids
- umask
- rlimits
- noNewPrivileges
- bounding/effective/inheritable/permitted/ambient capabilities

### Remaining gates

TTY, write-through PVC/CSI, full namespace/seccomp/device parity, additional
VMMs, and real-node KVM/Kubernetes conformance remain follow-ups.
