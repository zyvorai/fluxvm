# AppArmor / SELinux

FluxVM ships an AppArmor profile at `deploy/apparmor/fluxvm`, installed by
`scripts/bootstrap-host.sh` when AppArmor is present.

On SELinux hosts, load the permissive reference module in
[`deploy/selinux`](../selinux/README.md) (`fluxvm_t`). It stays permissive
until the `permissive` line is removed and the module is rebuilt. Pair the
AppArmor profile with `packaging/systemd/fluxvm.service` (`AppArmorProfile=fluxvm`)
or the drop-in in `packaging/systemd/fluxvm.service.d/apparmor.conf`.
