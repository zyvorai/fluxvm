# Shared vmnet broker

Apple's macOS 26+ design requires VMs on one custom network to share the same
`vmnet_network_ref`. FluxVM runs each VZ VM in a separate process, so the
production design needs one owner process (`fluxvm-vmnetd`) for named networks.

Apple provides the supported cross-process mechanism:
`vmnet_network_copy_serialization` -> XPC -> `vmnet_network_create_with_serialization`.

The broker should own:

- CreateNetwork(name, spec)
- AcquireNetwork(name)
- ReleaseNetwork(name, vm_id)
- InspectNetwork(name)
- DeleteNetwork(name) when refcount == 0

Persist the network specification under `state_dir/apple-networks/*.json`.
Do not attempt to turn the XPC serialization object into JSON/text.

This bundle intentionally implements the per-VM network first and gives the
exact broker contract for the next merge; the XPC transport itself must be
compiled and hardware-tested on macOS 27 before being called production-ready.
