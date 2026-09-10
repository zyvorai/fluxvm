#!/usr/bin/env bash
set -euo pipefail
: "${BDF:?usage: BDF=0000:65:00.0 $0}"
DEV="/sys/bus/pci/devices/$BDF"
test -e "$DEV" || { echo "missing PCI device $BDF" >&2; exit 1; }
DRIVER=$(basename "$(readlink -f "$DEV/driver" 2>/dev/null || echo none)")
GROUP=$(basename "$(readlink -f "$DEV/iommu_group" 2>/dev/null || echo none)")
echo "BDF=$BDF driver=$DRIVER iommu_group=$GROUP"
[[ "$DRIVER" == vfio-pci ]] || { echo "device must already be bound to vfio-pci" >&2; exit 2; }
[[ "$GROUP" != none ]] || { echo "device has no IOMMU group" >&2; exit 3; }
for d in "/sys/kernel/iommu_groups/$GROUP/devices"/*; do
  [[ -e "$d" ]] || continue
  peer=$(basename "$d")
  drv=$(basename "$(readlink -f "$d/driver" 2>/dev/null || echo none)")
  echo "group-peer=$peer driver=$drv"
done
