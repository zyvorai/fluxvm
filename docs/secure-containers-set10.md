# Secure Containers Set 10 — guest security enforcement

Set 10 closes three guest-side policy gaps left open by Set 4/7/9: OCI seccomp
argument comparisons, process LSM labels, and cgroup-v2 device access control.
It is an additive Set 9 delta; the newer namespace/Sentinel work on FluxVM
`main` should be retained when replaying this patch.

## Seccomp argument comparators

`fluxvm-container-agent` now parses and enforces all OCI/libseccomp comparison
operators through `seccomp_rule_add_array`:

- `SCMP_CMP_NE`
- `SCMP_CMP_LT`
- `SCMP_CMP_LE`
- `SCMP_CMP_EQ`
- `SCMP_CMP_GE`
- `SCMP_CMP_GT`
- `SCMP_CMP_MASKED_EQ` (`value` is the mask and `valueTwo` is the value)

Argument indices are restricted to the Linux syscall ABI range 0..=5. Invalid
`valueTwo`, unknown operators, unknown syscall names, unsupported architecture
lists, and unavailable `libseccomp.so.2` all fail closed. `SCMP_ACT_NOTIFY`
remains intentionally unsupported because correct notification semantics need a
long-lived userspace broker and listener-fd lifecycle; Set 10 rejects it rather
than installing a filter that could deadlock the workload.

## AppArmor and SELinux process labels

OCI `process.apparmorProfile` is applied with the kernel AppArmor `exec`
attribute before the container `execve`. If AppArmor is disabled, the profile is
missing, or the exec attribute cannot be written, container start fails closed.

OCI `process.selinuxLabel` is applied through a dynamically loaded
`libselinux.so.1` `setexeccon()` call. A requested label fails closed when
SELinux or the library is unavailable. Exec processes inherit the container
profile/label unless the exec process specifies its own value.

`linux.mountLabel` remains unsupported and is now rejected explicitly instead
of being silently ignored. Mount labeling requires applying and restoring
`setfscreatecon`/mount contexts around every relevant mount operation and is a
separate follow-up.

## cgroup-v2 device BPF

When OCI `linux.resources.devices` contains rules, the guest agent compiles the
ordered policy into a small eBPF program and attaches it directly to the
container cgroup using:

- `BPF_PROG_TYPE_CGROUP_DEVICE`
- expected/attach type `BPF_CGROUP_DEVICE`
- `struct bpf_cgroup_dev_ctx` access/type + major + minor fields

No clang, bpftool, libbpf, or external helper is required in the guest. Rules
support `a`, `b`, and `c` device types; wildcard major/minor; and `r`, `w`, `m`
access combinations. Policies are capped at 128 OCI rules and a conservative
4096 generated-instruction limit.

Before BPF generation, Set 10 emulates the OCI/cgroup-v1 desired rule stream
from a deny-all baseline into a normalized default policy plus exception set,
matching the opencontainers/cgroups device-filter model. A wildcard `a *:* rwm` rule
resets the default exactly as the devices controller does; exact inverse rules
remove exception permission bits, while unsafe attempts to punch holes through
partially matching wildcard exceptions fail closed. Generated exception blocks
require all requested access bits to be present, then return immediately; the
program ends with the emulated default verdict. This follows the same security
shape used by opencontainers/cgroups for cgroup-v2 device filters. The BPF fd
can be closed after attachment; deleting the cgroup removes the attachment with
the cgroup lifecycle.

If the guest kernel lacks cgroup BPF support or the agent lacks the required BPF
privilege, a requested device policy fails container creation instead of
running without the policy.

## Guest prerequisites

For the corresponding OCI controls, the guest image needs:

- cgroup v2 and kernel `CONFIG_CGROUP_BPF` for device rules;
- `libseccomp.so.2` for seccomp;
- AppArmor enabled and the named profile loaded for AppArmor requests;
- `libselinux.so.1` plus enabled SELinux policy for SELinux requests.

A guest does not need all of these features when its OCI spec does not request
them.

## Validation

Host-independent gates in this bundle cover OCI parsing, all seven seccomp
operators, invalid comparator shapes, LSM label parsing, mount-label fail-closed
behavior, device-rule parsing, generated BPF structure, shell syntax, manifest
verification, and patch replay.

The final production gate must still run on the real Secure Containers guest:

1. `RuntimeDefault`/custom seccomp profile starts and reports `Seccomp: 2`.
2. An argument-filter rule blocks only the matching syscall argument.
3. A loaded AppArmor profile appears in `/proc/<pid>/attr/current`.
4. A valid SELinux label appears in `/proc/<pid>/attr/current`/`ps -Z`.
5. Device deny-all + allow-list permits `/dev/null` but denies a non-allowed
   guest device despite filesystem permissions.
6. Existing Set 8/9 raw-block and VFIO workloads still work when their OCI
   device cgroup rules explicitly allow the passed-through guest devices.

This build environment has no Rust toolchain, KVM, bpftool, containerd, or
Kubernetes node, so those live kernel gates are not claimed here.
