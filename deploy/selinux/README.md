# SELinux reference module

`fluxvm.te` is a permissive domain for `fluxctl serve`. AppArmor hosts should
use [`deploy/apparmor`](../apparmor/README.md) and can ignore this directory.

Load it (policy devel packages required):

```bash
sudo make -f /usr/share/selinux/devel/Makefile fluxvm.pp
sudo semodule -i fluxvm.pp
```

The module starts **permissive** (`permissive fluxvm_t`): denials are audited
and then allowed. To enforce, delete the `permissive fluxvm_t;` line, rebuild,
and reinstall the module. Do not flip the whole machine with `setenforce`.
Confirm `ausearch -m avc -ts recent` is quiet for `fluxvm_t` before that edit.

This does not replace the Firecracker jailer or per-VM cgroup.
