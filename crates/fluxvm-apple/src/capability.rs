// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0

//! One table of what the Apple backend supports, shared with Kairon's `buildCreateRequest`.

use anyhow::{Result, bail};
use fluxvm_core::model::{CreateVmRequest, NetworkSpec, StorageBackend};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Capability {
    pub feature: &'static str,
    pub supported: bool,
    pub note: &'static str,
}

const fn yes(feature: &'static str, note: &'static str) -> Capability {
    Capability {
        feature,
        supported: true,
        note,
    }
}
const fn no(feature: &'static str, note: &'static str) -> Capability {
    Capability {
        feature,
        supported: false,
        note,
    }
}

pub const CAPABILITIES: &[Capability] = &[
    yes("vcpus", "any count the host allows"),
    yes("memory_mib", "checked against the host"),
    yes(
        "disk (raw image, APFS clone)",
        "qcow2 is converted to raw while cloning (needs qemu-img); named images: debian-13, debian-12, ubuntu-24.04",
    ),
    yes("cloud_init", "NoCloud seed built with hdiutil"),
    yes(
        "network user (NAT)",
        "guest reachable by its address; TCP port forwards relay from 127.0.0.1",
    ),
    yes(
        "bridged networking",
        "VZ bridge to host interface; useful for Mac Studio 10GbE; needs com.apple.vm.networking",
    ),
    yes(
        "shared folders (virtiofs)",
        "Linux: tags fs0, fs1, …; macOS 13+: VZ macOS automount share",
    ),
    yes(
        "Retina / dynamic multi-display",
        "1-8 macOS displays, configurable up to 5K each",
    ),
    yes("Linux clipboard", "SPICE port; guest needs spice-vdagent"),
    yes(
        "vmnet custom network",
        "macOS 26+ shared/host-only network, DHCP reservation, TCP/UDP forwards; named networks are shared across VMs through the fluxvm-vmnetd broker; unverified on hardware",
    ),
    yes(
        "custom Virtio device",
        "macOS 27+ Linux guests; provider/delegate, bounded control queue, guest-memory mapping probe",
    ),
    yes(
        "memory balloon",
        "runtime VZ balloon exposed through FluxVM balloon API",
    ),
    yes("ASIF overlay", "macOS 27+ DiskImageKit sparse write layer"),
    yes("USB mass-storage hotplug", "macOS 15+ XHCI attach/detach"),
    yes(
        "macOS 27 provisioning",
        "first-boot user/autologin/Remote Login",
    ),
    yes(
        "audio output / microphone",
        "Virtio sound; microphone is opt-in",
    ),
    yes(
        "Linux Rosetta",
        "optional VZLinuxRosettaDirectoryShare; host must have Rosetta available",
    ),
    yes(
        "nested virtualization",
        "Linux guests only, when VZGenericPlatformConfiguration reports support",
    ),
    yes(
        "USB controller",
        "XHCI controller configured for VZ USB mass-storage/passthrough hotplug",
    ),
    yes("serial console", "VM log and /v1/vms/{id}/serial"),
    yes("pause / resume", "Virtualization.framework"),
    yes(
        "graceful shutdown / stop",
        "ACPI power button, then force stop",
    ),
    yes(
        "guest agent over vsock",
        "needs the guest agent in the image; proxied like Firecracker",
    ),
    yes(
        "macOS guests",
        "installed from an IPSW through the API (apple.install) or cloned from a prepared template; see docs/macos.md",
    ),
    no(
        "tap / macvtap / netns / eBPF networking",
        "Linux kernel features",
    ),
    no("UDP port forwards", "only TCP is relayed"),
    no(
        "NUMA, hugepages, cpuset, vfio",
        "no such controls on Apple silicon",
    ),
    yes(
        "EFI Secure Boot",
        "macOS 27+ Linux EFI guests: Apple or custom platform key, Microsoft or custom KEK/db/dbx",
    ),
    no(
        "TPM, confidential profiles",
        "not offered by Virtualization.framework",
    ),
    no("hotplug (cpu, memory, disks, nics)", "not supported"),
    no(
        "top-level data_disks and cdroms",
        "use apple.extra_disks (image, block, NBD; virtio, NVMe, USB) or apple.media instead",
    ),
    no(
        "firmware overrides",
        "EFI from the disk, or direct kernel boot for Linux guests",
    ),
    yes(
        "snapshots of running VMs",
        "memory, devices and disk; restore from a stopped VM; needs an unlocked login session",
    ),
    no("live migration", "not implemented"),
    no(
        "GPU passthrough",
        "macOS guests get Metal-accelerated paravirtual graphics; Linux guests a 2D virtio display",
    ),
];

fn parse_v4(what: &str, v: &str) -> Result<std::net::Ipv4Addr> {
    v.parse::<std::net::Ipv4Addr>()
        .map_err(|_| anyhow::anyhow!("apple.vmnet {what} {v:?} is not a valid IPv4 address"))
}

/// Admission checks for a custom vmnet network (addresses only; macOS 26+ is checked by the runner).
fn validate_vmnet(v: &fluxvm_core::model::AppleVmnetSpec) -> Result<()> {
    if let Some(name) = &v.name {
        let valid = !name.is_empty()
            && name.len() <= 64
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'));
        if !valid {
            bail!("apple.vmnet.name must be 1..=64 of a-z/A-Z/0-9/._-");
        }
    }
    let subnet = u32::from(parse_v4("subnet", &v.subnet)?);
    let mask = u32::from(parse_v4("mask", &v.mask)?);
    let host_bits = !mask;
    if mask == 0 || host_bits & host_bits.wrapping_add(1) != 0 {
        bail!("apple.vmnet mask {:?} is not a contiguous netmask", v.mask);
    }
    // A /31 or /32 leaves no room for a host, gateway and guest.
    if host_bits < 3 {
        bail!("apple.vmnet mask {:?} leaves no room for guests", v.mask);
    }
    let in_net = |what: &str, raw: &str| -> Result<u32> {
        let a = u32::from(parse_v4(what, raw)?);
        if a & mask != subnet & mask {
            bail!(
                "apple.vmnet {what} {raw} is outside {}/{}",
                v.subnet,
                v.mask
            );
        }
        Ok(a)
    };
    // The macOS SDK's vmnet network configuration has no DHCP pool setter (only reservations), so a custom
    // range cannot be honoured; refuse it rather than silently ignore it.
    if v.dhcp_start.is_some() || v.dhcp_end.is_some() {
        bail!("apple.vmnet dhcp_start/dhcp_end are not supported by vmnet; use reserved_ip");
    }
    if let Some(ip) = &v.reserved_ip {
        in_net("reserved_ip", ip)?;
    }
    for f in &v.forwards {
        if !matches!(f.protocol.to_ascii_lowercase().as_str(), "tcp" | "udp") {
            bail!("apple.vmnet forward protocol must be tcp or udp");
        }
        if f.host_port == 0 || f.guest_port == 0 {
            bail!("apple.vmnet forward ports must be nonzero");
        }
        in_net("forward guest_ip", &f.guest_ip)?;
    }
    if v.disable_dhcp && v.reserved_ip.is_some() {
        bail!("apple.vmnet reserved_ip needs DHCP; drop disable_dhcp");
    }
    if let Some(p) = &v.ipv6_prefix {
        let ok = p.split_once('/').is_some_and(|(addr, len)| {
            addr.parse::<std::net::Ipv6Addr>().is_ok()
                && len.parse::<u8>().is_ok_and(|l| (1..=128).contains(&l))
        });
        if !ok {
            bail!("apple.vmnet ipv6_prefix {p:?} must look like fd00:1::/64");
        }
    }
    if v.mtu.is_some_and(|m| !(1280..=9000).contains(&m)) {
        bail!("apple.vmnet mtu must be 1280..=9000");
    }
    if let Some(i) = &v.external_interface {
        if v.mode != fluxvm_core::model::AppleVmnetMode::Shared {
            bail!("apple.vmnet external_interface needs mode shared");
        }
        if i.is_empty() || i.len() > 15 || !i.bytes().all(|b| b.is_ascii_alphanumeric()) {
            bail!("apple.vmnet external_interface {i:?} is not an interface name such as en0");
        }
    }
    Ok(())
}

/// EFI Secure Boot (macOS 27+) is applied to the EFI variable store, so it needs a Linux guest that boots EFI.
fn validate_secure_boot(req: &CreateVmRequest, macos_guest: bool) -> Result<()> {
    let keys = req.apple.as_ref().and_then(|a| a.efi_secure_boot.as_ref());
    if req.secure_boot != Some(true) {
        if keys.is_some() {
            bail!("apple.efi_secure_boot needs secure_boot: true");
        }
        return Ok(());
    }
    if macos_guest {
        bail!("secure_boot is for Linux guests; macOS guests always boot securely");
    }
    if req.kernel.is_some() {
        bail!("secure_boot needs EFI boot from the disk; direct kernel boot bypasses the firmware");
    }
    if let Some(k) = keys {
        for p in k
            .platform_key
            .iter()
            .chain(&k.kek)
            .chain(&k.db)
            .chain(&k.dbx)
        {
            if !p.is_absolute() {
                bail!(
                    "apple.efi_secure_boot path {} must be absolute",
                    p.display()
                );
            }
        }
    }
    Ok(())
}

/// Rejects, with a specific message, any request feature the Apple backend cannot honour.
/// Virtio console ports per VM (one console device holds them all).
pub const MAX_CONSOLE_PORTS: usize = 8;

/// A console port name: it becomes `/dev/virtio-ports/<name>` in the guest and part of a socket path on the host.
pub fn valid_console_port(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 32
        && name.as_bytes()[0].is_ascii_alphanumeric()
        && name.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
}

/// One `apple.extra_disks` entry: the fields its `kind` needs and nothing it cannot use.
pub fn validate_disk(d: &fluxvm_core::model::AppleDisk) -> Result<()> {
    use fluxvm_core::model::{AppleDiskCaching, AppleDiskKind, AppleDiskSync};
    if let Some(n) = &d.name {
        let ok = !n.is_empty()
            && n.len() <= 32
            && n != "root"
            && n.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_');
        if !ok {
            bail!("disk name {n:?}: 1-32 of a-z, 0-9, - and _, and not \"root\"");
        }
    }
    match d.kind {
        AppleDiskKind::Image => {
            if !d.path.is_absolute() {
                bail!(
                    "apple.extra_disks path {} must be absolute",
                    d.path.display()
                );
            }
        }
        AppleDiskKind::Block => {
            if !d.path.starts_with("/dev") || d.path.components().count() != 3 {
                bail!(
                    "a block disk's path must be a device such as /dev/disk4, not {}",
                    d.path.display()
                );
            }
        }
        AppleDiskKind::Nbd => {
            let url = d.url.as_deref().unwrap_or("");
            let scheme = url.split_once("://").map(|(s, _)| s);
            if !matches!(scheme, Some("nbd" | "nbds" | "nbd+unix" | "nbds+unix")) {
                bail!(
                    "an nbd disk needs url nbd://host:port/export (or nbds, nbd+unix, nbds+unix), not {url:?}"
                );
            }
            if !d.path.as_os_str().is_empty() {
                bail!("an nbd disk takes url, not path");
            }
        }
    }
    if d.kind != AppleDiskKind::Nbd && d.url.is_some() {
        bail!("url is for nbd disks");
    }
    if let Some(id) = &d.block_device_id {
        if d.controller != fluxvm_core::model::AppleDiskController::Virtio {
            bail!("block_device_id needs the virtio controller");
        }
        if id.is_empty() || id.len() > 20 || !id.bytes().all(|b| b.is_ascii_graphic()) {
            bail!("block_device_id {id:?}: 1-20 printable ASCII characters");
        }
    }
    if d.kind != AppleDiskKind::Image {
        if d.caching != AppleDiskCaching::Automatic {
            bail!("caching applies to image disks only");
        }
        if d.sync == AppleDiskSync::Fsync {
            bail!("sync fsync applies to image disks only; use full or none");
        }
    }
    Ok(())
}

/// Ports the runner uses itself, or that a guest's own services expect (sshd over vsock).
const RESERVED_VSOCK_PORTS: [u32; 4] = [22, 3128, 7790, 7791];

fn validate_vsock_services(services: &[fluxvm_core::model::AppleVsockService]) -> Result<()> {
    if services.len() > 16 {
        bail!("apple.vsock_services allows at most 16 entries");
    }
    let mut seen = std::collections::BTreeSet::new();
    for s in services {
        if !(1024..=65535).contains(&s.port) || RESERVED_VSOCK_PORTS.contains(&s.port) {
            bail!(
                "apple.vsock_services port {} must be 1024..=65535 and not one of {:?}",
                s.port,
                RESERVED_VSOCK_PORTS
            );
        }
        if !seen.insert(s.port) {
            bail!("apple.vsock_services lists port {} twice", s.port);
        }
        match (&s.socket, &s.builtin) {
            (Some(n), None) => {
                if n.is_empty()
                    || n.len() > 32
                    || !n.chars().all(|c| {
                        c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'
                    })
                {
                    bail!("apple.vsock_services socket name {n:?} must match [a-z0-9_-]{{1,32}}");
                }
            }
            (None, Some(b)) if b == "metadata" || b == "telemetry" => {}
            (None, Some(b)) => {
                bail!("apple.vsock_services builtin {b:?} is not \"metadata\" or \"telemetry\"")
            }
            _ => bail!(
                "apple.vsock_services port {} needs exactly one of socket and builtin",
                s.port
            ),
        }
    }
    Ok(())
}

pub fn validate_request(req: &CreateVmRequest) -> Result<()> {
    macro_rules! reject {
        ($cond:expr, $msg:expr) => {
            if $cond {
                bail!("the vz backend does not support {}", $msg);
            }
        };
    }
    if let Some(apple) = &req.apple
        && apple.self_control
        && matches!(apple.guest_os, fluxvm_core::model::AppleGuest::Macos)
    {
        bail!(
            "apple.self_control needs a Linux guest (the in-guest relay is installed by cloud-init)"
        );
    }
    if let Some(apple) = &req.apple {
        validate_vsock_services(&apple.vsock_services)?;
    }
    if let Some(apple) = &req.apple
        && !apple.egress_allow.is_empty()
    {
        if !matches!(req.network, NetworkSpec::None) {
            bail!(
                "egress_allow needs network.mode = \"none\": with a network card the guest could bypass the proxy"
            );
        }
        for h in &apple.egress_allow {
            let host = h.strip_prefix("*.").unwrap_or(h);
            if host.is_empty()
                || host.starts_with('.')
                || !host
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
            {
                bail!("egress_allow entry {h:?} is not a host name or *.suffix");
            }
        }
    }
    if let Some(apple) = &req.apple {
        if !(1..=8).contains(&apple.display_count) {
            bail!("apple.display_count must be 1..=8");
        }
        if !(800..=5120).contains(&apple.display_width) {
            bail!("apple.display_width must be 800..=5120");
        }
        if !(600..=2880).contains(&apple.display_height) {
            bail!("apple.display_height must be 600..=2880");
        }
        if !(72..=300).contains(&apple.display_ppi) {
            bail!("apple.display_ppi must be 72..=300");
        }
        crate::vznet::validate(&apple.networks)?;
        if !apple.networks.is_empty() {
            if matches!(apple.guest_os, fluxvm_core::model::AppleGuest::Macos) {
                bail!("apple.networks is for Linux guests");
            }
            if !apple.egress_allow.is_empty() {
                bail!(
                    "apple.networks cannot be combined with egress_allow: another guest on the network could relay \
                     around the proxy"
                );
            }
        }
        if matches!(apple.guest_os, fluxvm_core::model::AppleGuest::Macos)
            && (apple.rosetta || apple.nested_virtualization || apple.clipboard)
        {
            bail!(
                "apple.rosetta, apple.nested_virtualization and apple.clipboard are Linux-guest features"
            );
        }
        if matches!(apple.guest_os, fluxvm_core::model::AppleGuest::Macos)
            && req.agent.as_ref().is_some_and(|a| a.enabled)
        {
            bail!("agent.enabled needs a Linux guest: fluxvm-guest-agent is a Linux binary");
        }
        if apple.bridge_interface.as_deref().is_some_and(str::is_empty) {
            bail!("apple.bridge_interface cannot be empty");
        }
        if apple.bridge_interface.is_some() {
            if !matches!(req.network, NetworkSpec::User { .. }) {
                bail!("apple.bridge_interface requires network.mode = \"user\"");
            }
            if let NetworkSpec::User { forwards } = &req.network
                && !forwards.is_empty()
            {
                bail!("TCP host forwards are only supported with Apple NAT, not bridge mode");
            }
        }
        if let Some(v) = &apple.vmnet {
            if apple.bridge_interface.is_some() {
                bail!("apple.vmnet and apple.bridge_interface are mutually exclusive");
            }
            if matches!(req.network, NetworkSpec::None) {
                bail!("apple.vmnet needs a network card; network.mode = \"none\" has none");
            }
            if let NetworkSpec::User { forwards } = &req.network
                && !forwards.is_empty()
            {
                bail!("with apple.vmnet use apple.vmnet.forwards, not network.forwards");
            }
            validate_vmnet(v)?;
            let mut seen = std::collections::HashSet::new();
            for f in &v.forwards {
                if !seen.insert((f.protocol.to_ascii_lowercase(), f.host_port)) {
                    bail!(
                        "apple.vmnet forwards host port {}/{} more than once",
                        f.host_port,
                        f.protocol
                    );
                }
            }
        }
        crate::macos_install::validate(req)?;
        if apple.custom_virtio && matches!(apple.guest_os, fluxvm_core::model::AppleGuest::Macos) {
            bail!("apple.custom_virtio is a Linux-guest feature");
        }
        let any_provision = apple.provision_full_name.is_some()
            || apple.provision_username.is_some()
            || apple.provision_password_file.is_some()
            || apple.provision_auto_login
            || apple.provision_remote_login;
        if any_provision {
            if !matches!(apple.guest_os, fluxvm_core::model::AppleGuest::Macos) {
                bail!("Apple automated provisioning is for macOS guests only");
            }
            if apple
                .provision_username
                .as_deref()
                .is_none_or(str::is_empty)
                || apple
                    .provision_full_name
                    .as_deref()
                    .is_none_or(str::is_empty)
                || apple.provision_password_file.is_none()
            {
                bail!("macOS provisioning needs full name, username and provision_password_file");
            }
        }
    }
    match &req.network {
        NetworkSpec::None => {}
        NetworkSpec::User { forwards } => {
            reject!(
                forwards
                    .iter()
                    .any(|f| !f.protocol.eq_ignore_ascii_case("tcp")),
                "UDP port forwards (only tcp is relayed)"
            );
            // 127.0.0.1 and the NAT gateway are different addresses, so one port number may be used on each.
            let mut seen = std::collections::HashSet::new();
            for f in forwards {
                if f.host_port < 1024 {
                    bail!(
                        "the vz backend cannot forward host port {} (ports below 1024 need root)",
                        f.host_port
                    );
                }
                if !seen.insert((f.host_port, f.guests)) {
                    bail!("host port {} is forwarded more than once", f.host_port);
                }
            }
        }
        _ => bail!(
            "the vz backend supports only network mode `user` (NAT) or `none`; tap and macvtap are Linux features"
        ),
    }
    let macos_guest = req
        .apple
        .as_ref()
        .is_some_and(|a| a.guest_os == fluxvm_core::model::AppleGuest::Macos);
    reject!(
        macos_guest && (req.kernel.is_some() || req.initrd.is_some() || req.kernel_args.is_some()),
        "direct kernel boot for macOS guests"
    );
    if req.kernel.is_none() && (req.initrd.is_some() || req.kernel_args.is_some()) {
        bail!(
            "initrd and kernel_args need kernel (direct boot); without it the guest boots EFI from the disk"
        );
    }
    for p in [&req.kernel, &req.initrd].into_iter().flatten() {
        if !p.is_absolute() {
            bail!(
                "kernel and initrd must be absolute paths, got {}",
                p.display()
            );
        }
    }
    if let Some(apple) = &req.apple {
        if macos_guest && (apple.root_read_only || !apple.extra_disks.is_empty()) {
            bail!("apple.root_read_only and apple.extra_disks are Linux-guest features");
        }
        if apple.root_read_only && apple.asif_overlay {
            bail!("apple.root_read_only cannot be combined with apple.asif_overlay");
        }
        if macos_guest && !apple.console_ports.is_empty() {
            bail!("apple.console_ports is a Linux-guest feature");
        }
        if apple.console_ports.len() > MAX_CONSOLE_PORTS {
            bail!("at most {MAX_CONSOLE_PORTS} apple.console_ports");
        }
        let mut ports = std::collections::HashSet::new();
        for p in &apple.console_ports {
            if !valid_console_port(p) {
                bail!(
                    "console port {p:?}: 1-32 of a-z, 0-9, '.', '-' and '_', starting with a letter or digit"
                );
            }
            if !ports.insert(p) {
                bail!("console port {p} is listed twice");
            }
        }
        let mut names = std::collections::HashSet::new();
        for (i, d) in apple.extra_disks.iter().enumerate() {
            validate_disk(d)?;
            if !names.insert(d.name_at(i)) {
                bail!("apple.extra_disks name {} is used twice", d.name_at(i));
            }
        }
        if macos_guest && !apple.tagged_shares.is_empty() {
            bail!("apple.tagged_shares is a Linux-guest feature");
        }
        let mut tags = std::collections::HashSet::new();
        for s in &apple.tagged_shares {
            // virtiofs tags are at most 36 bytes; `fsN` is taken by shared_folders.
            let ok = !s.tag.is_empty()
                && s.tag.len() <= 36
                && s.tag
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                && !(s.tag.starts_with("fs") && s.tag[2..].bytes().all(|b| b.is_ascii_digit()))
                && s.tag != "rosetta";
            if !ok {
                bail!("apple.tagged_shares tag {:?} is invalid or reserved", s.tag);
            }
            if !tags.insert(s.tag.as_str()) {
                bail!("apple.tagged_shares tag {:?} is used twice", s.tag);
            }
            if !s.host_path.is_absolute() {
                bail!(
                    "apple.tagged_shares path {} must be absolute",
                    s.host_path.display()
                );
            }
        }
        if apple.init_config.is_some() {
            if macos_guest || req.kernel.is_none() {
                bail!(
                    "apple.init_config (an OCI sandbox) needs a Linux guest booted directly from `kernel`"
                );
            }
            if tags.contains(fluxvm_oci_init::config::META_TAG) {
                bail!(
                    "the {} share tag is reserved for apple.init_config",
                    fluxvm_oci_init::config::META_TAG
                );
            }
        }
    }
    reject!(req.firmware.is_some(), "firmware overrides");
    reject!(
        req.numa_node.is_some() || req.cpuset.is_some() || req.hugepages == Some(true),
        "NUMA, cpuset or hugepages"
    );
    reject!(!req.vfio_devices.is_empty(), "VFIO device passthrough");
    reject!(req.tpm == Some(true), "a TPM");
    validate_secure_boot(req, macos_guest)?;
    if let Some(apple) = &req.apple {
        if apple.recovery && !macos_guest {
            bail!("apple.recovery (start up from macOS Recovery) is for macOS guests");
        }
        if let Some(cache) = &apple.rosetta_cache {
            if !apple.rosetta {
                bail!("apple.rosetta_cache needs apple.rosetta");
            }
            let ok = cache == "default"
                || (cache.starts_with('/') && cache.len() <= 104)
                || (!cache.starts_with('/')
                    && !cache.is_empty()
                    && cache.len() <= 107
                    && cache.bytes().all(|b| b.is_ascii_graphic()));
            if !ok {
                bail!(
                    "apple.rosetta_cache must be \"default\", a guest socket path or an abstract socket name, not {cache:?}"
                );
            }
        }
    }
    for share in &req.shared_folders {
        if !share.host_path.is_dir() {
            bail!(
                "shared folder {} is not an existing directory on this Mac",
                share.host_path.display()
            );
        }
        if !share.guest_path.starts_with('/') {
            bail!(
                "shared folder guest_path {:?} must be absolute",
                share.guest_path
            );
        }
    }
    reject!(
        !req.data_disks.is_empty(),
        "data_disks (use apple.extra_disks)"
    );
    reject!(
        !req.cdroms.is_empty(),
        "cdroms (use apple.media for an installer image)"
    );
    reject!(req.hyperv, "Hyper-V enlightenments");
    reject!(
        req.qga.as_ref().is_some_and(|q| q.enabled),
        "the QEMU guest agent channel"
    );
    reject!(
        req.storage != StorageBackend::Default,
        "storage backends other than the default raw clone"
    );
    reject!(
        req.max_vcpus.is_some_and(|m| m > req.vcpus)
            || req.max_memory_mib.is_some_and(|m| m > req.memory_mib),
        "CPU or memory hotplug headroom"
    );
    reject!(req.loadvm_tag.is_some(), "resuming from a snapshot tag");
    reject!(!req.extra_args.is_empty(), "extra VMM arguments");
    reject!(
        req.net_mbit_limit.is_some()
            || req.net_pps_limit.is_some()
            || req.blk_mbit_limit.is_some()
            || req.blk_ops_limit.is_some(),
        "I/O rate limits"
    );
    if req.vcpus == 0 || req.memory_mib < 512 {
        bail!("the vz backend needs at least 1 vCPU and 512 MiB of memory");
    }
    Ok(())
}

use fluxvm_core::model::{CloudInitFile, CloudInitSpec, SharedFolder};

/// Appends the guest-side mount for each virtiofs share (tags `fs0`, `fs1`, … as the runner names them). The fstab
/// line, not just a one-shot `mount`, keeps the share across stop/start, when cloud-init's `runcmd` does not replay.
pub fn with_shared_folder_mounts(mut ci: CloudInitSpec, shares: &[SharedFolder]) -> CloudInitSpec {
    for (i, share) in shares.iter().enumerate() {
        let (tag, path) = (format!("fs{i}"), &share.guest_path);
        let opts = if share.read_only { "ro" } else { "defaults" };
        ci.runcmd.push(format!("mkdir -p {path}"));
        ci.runcmd.push(format!(
            "grep -qF ' {path} ' /etc/fstab || echo '{tag} {path} virtiofs {opts},nofail 0 0' >> /etc/fstab"
        ));
        ci.runcmd.push(format!("mount {path}"));
    }
    ci
}

/// Adds what the Apple backend needs from the guest: a service that prints `VELORA-IP <addr>` on the serial
/// console (the host cannot read DHCP leases or ARP on macOS), and an sshd setting that stops OpenSSH's per-source
/// penalties from locking out the host that manages these local VMs.
pub fn with_guest_reporting(mut ci: CloudInitSpec) -> CloudInitSpec {
    ci.write_files.push(CloudInitFile {
        path: "/etc/ssh/sshd_config.d/10-fluxvm.conf".into(),
        content: "# Local, host-only VMs: do not throttle the host that manages them.\nPerSourcePenalties no\nMaxStartups 100:30:200\n".into(),
        permissions: Some("0644".into()),
    });
    ci.write_files.push(CloudInitFile {
        path: "/usr/local/sbin/fluxvm-report-ip".into(),
        content: concat!(
            "#!/bin/sh\n",
            "# Tells the FluxVM host which address this guest got (printed on the serial console).\n",
            "last=\n",
            "while :; do\n",
            "  ip=$(ip -4 -o addr show scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -n1)\n",
            "  if [ -n \"$ip\" ] && [ \"$ip\" != \"$last\" ]; then echo \"VELORA-IP $ip\" > /dev/hvc0 2>/dev/null; last=$ip; fi\n",
            "  sleep 3\n",
            "done\n"
        )
        .into(),
        permissions: Some("0755".into()),
    });
    // A systemd unit, not a one-shot background process: it must come back on every later boot too.
    ci.write_files.push(CloudInitFile {
        path: "/etc/systemd/system/fluxvm-report-ip.service".into(),
        content: "[Unit]\nDescription=Report IP address to the FluxVM host\n[Service]\nExecStart=/usr/local/sbin/fluxvm-report-ip\nRestart=always\n[Install]\nWantedBy=multi-user.target\n".into(),
        permissions: Some("0644".into()),
    });
    ci.runcmd.insert(
        0,
        "systemctl reload ssh || systemctl reload sshd || true".into(),
    );
    ci.runcmd.insert(
        1,
        "systemctl daemon-reload && systemctl enable --now fluxvm-report-ip.service".into(),
    );
    ci
}

/// A forwarder from guest `127.0.0.1:<port>` to the same vsock port on the host (CID 2), as a systemd service named `name`.
/// Python, because cloud-init itself needs python3, so every guest that runs these files has it.
fn push_vsock_forwarder(ci: &mut CloudInitSpec, name: &str, description: &str, port: u32) {
    ci.write_files.push(CloudInitFile {
        path: format!("/usr/local/sbin/{name}"),
        content: format!(
            concat!(
                "#!/usr/bin/python3\n",
                "import socket, threading\n",
                "def pump(a, b):\n",
                "    try:\n",
                "        while True:\n",
                "            d = a.recv(65536)\n",
                "            if not d: break\n",
                "            b.sendall(d)\n",
                "    except OSError: pass\n",
                "    finally:\n",
                "        for s in (a, b):\n",
                "            try: s.shutdown(socket.SHUT_RDWR)\n",
                "            except OSError: pass\n",
                "def serve(c):\n",
                "    try:\n",
                "        v = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)\n",
                "        v.connect((2, {port}))\n",
                "    except OSError:\n",
                "        c.close(); return\n",
                "    threading.Thread(target=pump, args=(v, c), daemon=True).start()\n",
                "    pump(c, v)\n",
                "s = socket.socket()\n",
                "s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)\n",
                "s.bind(('127.0.0.1', {port}))\n",
                "s.listen(64)\n",
                "while True:\n",
                "    c, _ = s.accept()\n",
                "    threading.Thread(target=serve, args=(c,), daemon=True).start()\n"
            ),
            port = port
        ),
        permissions: Some("0755".into()),
    });
    ci.write_files.push(CloudInitFile {
        path: format!("/etc/systemd/system/{name}.service"),
        content: format!(
            "[Unit]\nDescription={description}\n[Service]\nExecStart=/usr/local/sbin/{name}\nRestart=always\n[Install]\nWantedBy=multi-user.target\n"
        ),
        permissions: Some("0644".into()),
    });
    ci.runcmd.push(format!(
        "systemctl daemon-reload && systemctl enable --now {name}.service"
    ));
}

/// For a guest with no network card and an `egress_allow` list: a forwarder from `127.0.0.1:3128` to the runner's proxy on the
/// host (vsock CID 2), and the proxy settings that make shells, apt and curl use it. The host decides what gets through.
pub fn with_egress_forwarder(mut ci: CloudInitSpec) -> CloudInitSpec {
    let port = crate::runner::EGRESS_PORT;
    push_vsock_forwarder(
        &mut ci,
        "fluxvm-egress",
        "Forward to the FluxVM host's egress proxy",
        port,
    );
    let url = format!("http://127.0.0.1:{port}");
    ci.write_files.push(CloudInitFile {
        path: "/etc/environment".into(),
        content: format!(
            "http_proxy={url}\nhttps_proxy={url}\nHTTP_PROXY={url}\nHTTPS_PROXY={url}\nno_proxy=localhost,127.0.0.1\nNO_PROXY=localhost,127.0.0.1\n"
        ),
        permissions: Some("0644".into()),
    });
    ci.write_files.push(CloudInitFile {
        path: "/etc/apt/apt.conf.d/90fluxvm-proxy".into(),
        content: format!("Acquire::http::Proxy \"{url}\";\nAcquire::https::Proxy \"{url}\";\n"),
        permissions: Some("0644".into()),
    });
    ci
}

/// For a `self_control` VM: `http://127.0.0.1:7790/mcp` in the guest reaches the host's MCP server for this VM over vsock.
pub fn with_self_control_forwarder(mut ci: CloudInitSpec) -> CloudInitSpec {
    push_vsock_forwarder(
        &mut ci,
        "fluxvm-self",
        "Forward to the FluxVM host's self-control MCP server",
        crate::runner::SELF_CONTROL_PORT,
    );
    ci
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vsock_services_are_validated() {
        let ok = r#""apple":{"vsock_services":[{"port":5000,"socket":"metrics"},{"port":5001,"builtin":"metadata"}]}"#;
        assert!(validate_request(&req(ok)).is_ok());
        for bad in [
            r#""apple":{"vsock_services":[{"port":3128,"builtin":"metadata"}]}"#,
            r#""apple":{"vsock_services":[{"port":80,"builtin":"metadata"}]}"#,
            r#""apple":{"vsock_services":[{"port":5000}]}"#,
            r#""apple":{"vsock_services":[{"port":5000,"socket":"../x"}]}"#,
            r#""apple":{"vsock_services":[{"port":5000,"builtin":"shell"}]}"#,
            r#""apple":{"vsock_services":[{"port":5000,"socket":"a","builtin":"metadata"}]}"#,
            r#""apple":{"vsock_services":[{"port":5000,"socket":"a"},{"port":5000,"socket":"b"}]}"#,
        ] {
            assert!(validate_request(&req(bad)).is_err(), "{bad}");
        }
    }

    #[test]
    fn self_control_is_for_linux_guests_and_installs_the_relay() {
        assert!(validate_request(&req(r#""apple":{"self_control":true}"#)).is_ok());
        assert!(
            validate_request(&req(r#""apple":{"self_control":true,"guest_os":"macos"}"#)).is_err()
        );
        let ci = with_self_control_forwarder(CloudInitSpec::default());
        let relay = ci
            .write_files
            .iter()
            .find(|f| f.path == "/usr/local/sbin/fluxvm-self")
            .unwrap();
        assert!(relay.content.contains("v.connect((2, 7790))"));
        assert!(relay.content.contains("s.bind(('127.0.0.1', 7790))"));
        assert!(
            ci.runcmd
                .iter()
                .any(|c| c.contains("enable --now fluxvm-self.service"))
        );
    }

    #[test]
    fn egress_needs_no_network_card_and_sane_names() {
        let ok =
            r#""network":{"mode":"none"},"apple":{"egress_allow":["example.com","*.pypi.org"]}"#;
        assert!(validate_request(&req(ok)).is_ok());
        let nat = r#""network":{"mode":"user"},"apple":{"egress_allow":["example.com"]}"#;
        assert!(validate_request(&req(nat)).is_err());
        let bad = r#""network":{"mode":"none"},"apple":{"egress_allow":["a b"]}"#;
        assert!(validate_request(&req(bad)).is_err());
    }

    fn req(extra: &str) -> CreateVmRequest {
        let sep = if extra.is_empty() { "" } else { "," };
        serde_json::from_str(&format!(
            "{{\"name\":\"t\",\"backend\":\"vz\",\"image\":\"/x.raw\"{sep}{extra}}}"
        ))
        .unwrap()
    }

    #[test]
    fn efi_secure_boot_is_accepted_for_linux_efi_guests() {
        assert!(validate_request(&req(r#""secure_boot":true"#)).is_ok());
        let custom = r#""secure_boot":true,"apple":{"efi_secure_boot":{"platform_key":"/pk.der","db":["/db.esl"],"default_signatures":false}}"#;
        assert!(validate_request(&req(custom)).is_ok());
        let mac = r#""secure_boot":true,"apple":{"guest_os":"macos"}"#;
        assert!(validate_request(&req(mac)).is_err());
    }

    #[test]
    fn a_plain_request_is_accepted() {
        assert!(validate_request(&req(r#""vcpus":2,"memory_mib":2048"#)).is_ok());
        assert!(validate_request(&req(r#""network":{"mode":"user"}"#)).is_ok());
        assert!(validate_request(&req(r#""network":{"mode":"none"}"#)).is_ok());
        assert!(
            validate_request(&req(
                r#""network":{"mode":"user","forwards":[{"host_port":2222,"guest_port":22}]}"#
            ))
            .is_ok()
        );
        assert!(
            validate_request(&req(
                r#""shared_folders":[{"host_path":"/tmp","guest_path":"/mnt/src","read_only":true}]"#
            ))
            .is_ok()
        );
    }

    #[test]
    fn apple_parity_defaults_are_safe_and_backwards_compatible() {
        let r = req(r#""apple":{}"#);
        let a = r.apple.expect("apple options");
        assert_eq!(a.display_width, 2560);
        assert_eq!(a.display_height, 1600);
        assert_eq!(a.display_ppi, 220);
        assert!(a.audio_output);
        assert!(!a.microphone);
        assert!(!a.rosetta);
        assert!(!a.nested_virtualization);
        // XHCI is macOS 15+ while the runner still targets macOS 14.
        assert!(!a.usb_controller);
    }

    #[test]
    fn apple_display_limits_are_rejected_at_admission() {
        for json in [
            r#""apple":{"display_width":799}"#,
            r#""apple":{"display_width":5121}"#,
            r#""apple":{"display_height":599}"#,
            r#""apple":{"display_height":2881}"#,
            r#""apple":{"display_ppi":71}"#,
            r#""apple":{"display_ppi":301}"#,
        ] {
            assert!(validate_request(&req(json)).is_err(), "{json}");
        }
        assert!(
            validate_request(&req(
                r#""apple":{"display_width":5120,"display_height":2880,"display_ppi":220}"#
            ))
            .is_ok()
        );
    }

    #[test]
    fn mac_studio_options_default_off() {
        let a = req(r#""apple":{}"#).apple.expect("apple options");
        assert_eq!(a.display_count, 1);
        assert!(!a.clipboard);
        assert!(a.bridge_interface.is_none());
        assert!(!a.asif_overlay);
        assert!(a.provision_username.is_none());
        assert!(!a.provision_auto_login);
        assert!(!a.provision_remote_login);
    }

    #[test]
    fn display_count_is_one_to_eight() {
        for n in [0, 9] {
            let json = format!(r#""apple":{{"guest_os":"macos","display_count":{n}}}"#);
            assert!(validate_request(&req(&json)).is_err(), "{json}");
        }
        for n in [1, 4, 8] {
            let json = format!(r#""apple":{{"guest_os":"macos","display_count":{n}}}"#);
            assert!(validate_request(&req(&json)).is_ok(), "{json}");
        }
    }

    #[test]
    fn clipboard_is_linux_only() {
        let mac = r#""apple":{"guest_os":"macos","clipboard":true}"#;
        let err = validate_request(&req(mac)).expect_err(mac).to_string();
        assert!(err.contains("clipboard"), "{err}");
        assert!(validate_request(&req(r#""apple":{"clipboard":true}"#)).is_ok());
    }

    #[test]
    fn bridge_needs_nat_mode_without_host_forwards() {
        let ok = r#""network":{"mode":"user"},"apple":{"bridge_interface":"en0"}"#;
        assert!(validate_request(&req(ok)).is_ok());
        let empty = r#""network":{"mode":"user"},"apple":{"bridge_interface":""}"#;
        assert!(validate_request(&req(empty)).is_err());
        let none = r#""network":{"mode":"none"},"apple":{"bridge_interface":"en0"}"#;
        assert!(validate_request(&req(none)).is_err());
        let fwd = r#""network":{"mode":"user","forwards":[{"host_port":2222,"guest_port":22}]},"apple":{"bridge_interface":"en0"}"#;
        let err = validate_request(&req(fwd)).expect_err(fwd).to_string();
        assert!(err.contains("bridge"), "{err}");
    }

    #[test]
    fn vmnet_spec_is_validated() {
        let ok = r#""network":{"mode":"user"},"apple":{"vmnet":{"mode":"host-only","subnet":"192.168.105.0","mask":"255.255.255.0","reserved_ip":"192.168.105.10","forwards":[{"host_port":8080,"guest_port":80,"guest_ip":"192.168.105.10"},{"protocol":"udp","host_port":8080,"guest_port":53,"guest_ip":"192.168.105.10"}]}}"#;
        assert!(validate_request(&req(ok)).is_ok());
        let v6 = r#""apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0","ipv6_prefix":"fd00:1::/64","mtu":9000,"external_interface":"en0","disable_nat66":true,"disable_dns_proxy":true}}"#;
        assert!(validate_request(&req(v6)).is_ok());
        for (json, needle) in [
            (
                r#""apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0","ipv6_prefix":"fd00::"}}"#,
                "ipv6_prefix",
            ),
            (
                r#""apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0","mtu":100}}"#,
                "mtu",
            ),
            (
                r#""apple":{"vmnet":{"mode":"host-only","subnet":"10.0.0.0","mask":"255.0.0.0","external_interface":"en0"}}"#,
                "mode shared",
            ),
            (
                r#""apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0","disable_dhcp":true,"reserved_ip":"10.0.0.9"}}"#,
                "needs DHCP",
            ),
            (
                r#""apple":{"bridge_interface":"en0","vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0"}}"#,
                "mutually exclusive",
            ),
            (
                r#""network":{"mode":"none"},"apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0"}}"#,
                "network card",
            ),
            (
                r#""apple":{"vmnet":{"mode":"shared","subnet":"10.0.0","mask":"255.0.0.0"}}"#,
                "IPv4",
            ),
            (
                r#""apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0","forwards":[{"protocol":"sctp","host_port":1,"guest_port":1,"guest_ip":"10.0.0.2"}]}}"#,
                "tcp or udp",
            ),
            (
                r#""apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0","forwards":[{"host_port":9000,"guest_port":1,"guest_ip":"10.0.0.2"},{"host_port":9000,"guest_port":2,"guest_ip":"10.0.0.3"}]}}"#,
                "more than once",
            ),
            (
                r#""network":{"mode":"user","forwards":[{"host_port":2222,"guest_port":22}]},"apple":{"vmnet":{"mode":"shared","subnet":"10.0.0.0","mask":"255.0.0.0"}}"#,
                "apple.vmnet.forwards",
            ),
        ] {
            let err = validate_request(&req(json)).expect_err(json).to_string();
            assert!(err.contains(needle), "{json}: {err}");
        }
    }

    #[test]
    fn guest_agent_is_linux_only() {
        let agent = r#""agent":{"enabled":true}"#;
        assert!(validate_request(&req(agent)).is_ok());
        let mac = r#""agent":{"enabled":true},"apple":{"guest_os":"macos"}"#;
        let err = validate_request(&req(mac)).unwrap_err().to_string();
        assert!(err.contains("Linux guest"), "{err}");
    }

    #[test]
    fn vmnet_admission_rules() {
        let v = |net: &str, extra: &str| {
            format!(
                r#""network":{{"mode":"{net}"}},"apple":{{{extra}"vmnet":{{"mode":"shared","subnet":"192.168.77.0","mask":"255.255.255.0","reserved_ip":"192.168.77.20","forwards":[{{"protocol":"tcp","host_port":2222,"guest_port":22,"guest_ip":"192.168.77.20"}}]}}}}"#
            )
        };
        assert!(validate_request(&req(&v("user", ""))).is_ok());
        assert!(validate_request(&req(&v("none", ""))).is_err());
        assert!(validate_request(&req(&v("user", r#""bridge_interface":"en0","#))).is_err());
        for (from, to) in [
            ("255.255.255.0", "255.0.255.0"),
            ("255.255.255.0", "255.255.255.254"),
            (
                "\"reserved_ip\":\"192.168.77.20\"",
                "\"reserved_ip\":\"10.0.0.1\"",
            ),
            ("\"tcp\"", "\"icmp\""),
            ("\"host_port\":2222", "\"host_port\":0"),
            (
                "\"reserved_ip\"",
                "\"dhcp_start\":\"192.168.77.10\",\"dhcp_end\":\"192.168.77.99\",\"reserved_ip\"",
            ),
            ("192.168.77.0", "not-an-ip"),
        ] {
            let json = v("user", "").replace(from, to);
            assert!(validate_request(&req(&json)).is_err(), "{from} -> {to}");
        }
    }

    #[test]
    fn direct_kernel_boot_is_for_linux_guests() {
        let ok = r#""kernel":"/k/Image","initrd":"/k/initrd","kernel_args":"console=hvc0","apple":{"root_read_only":true,"extra_disks":[{"path":"/d/b.raw","read_only":true}],"tagged_shares":[{"tag":"fluxvm-meta","host_path":"/m","read_only":true}]}"#;
        assert!(validate_request(&req(ok)).is_ok());
        for (json, needle) in [
            (
                r#""kernel":"/k/Image","apple":{"guest_os":"macos"}"#,
                "macOS guests",
            ),
            (r#""kernel":"Image""#, "absolute"),
            (r#""kernel_args":"quiet""#, "need kernel"),
            (
                r#""apple":{"root_read_only":true,"asif_overlay":true}"#,
                "asif_overlay",
            ),
            (r#""apple":{"extra_disks":[{"path":"b.raw"}]}"#, "absolute"),
            (
                r#""apple":{"guest_os":"macos","extra_disks":[{"path":"/b.raw"}]}"#,
                "Linux-guest",
            ),
            (
                r#""apple":{"tagged_shares":[{"tag":"fs0","host_path":"/m"}]}"#,
                "reserved",
            ),
            (
                r#""apple":{"tagged_shares":[{"tag":"a b","host_path":"/m"}]}"#,
                "invalid",
            ),
            (
                r#""apple":{"tagged_shares":[{"tag":"m","host_path":"/m"},{"tag":"m","host_path":"/n"}]}"#,
                "twice",
            ),
            (
                r#""apple":{"tagged_shares":[{"tag":"fluxvm-meta","host_path":"meta"}]}"#,
                "absolute",
            ),
            (r#""apple":{"init_config":{"mode":"boot"}}"#, "kernel"),
            (
                r#""kernel":"/k","apple":{"init_config":{},"tagged_shares":[{"tag":"fluxvm-meta","host_path":"/m"}]}"#,
                "reserved",
            ),
        ] {
            let err = validate_request(&req(json)).expect_err(json).to_string();
            assert!(err.contains(needle), "{json}: {err}");
        }
    }

    #[test]
    fn custom_virtio_is_linux_only() {
        assert!(validate_request(&req(r#""apple":{"custom_virtio":true}"#)).is_ok());
        let mac = r#""apple":{"guest_os":"macos","custom_virtio":true}"#;
        assert!(validate_request(&req(mac)).is_err());
    }

    #[test]
    fn provisioning_needs_name_user_and_password_file_on_macos() {
        let full = r#""apple":{"guest_os":"macos","provision_full_name":"Flux","provision_username":"flux","provision_password_file":"/tmp/pw","provision_remote_login":true}"#;
        assert!(validate_request(&req(full)).is_ok());
        for json in [
            r#""apple":{"guest_os":"macos","provision_username":"flux","provision_password_file":"/tmp/pw"}"#,
            r#""apple":{"guest_os":"macos","provision_full_name":"Flux","provision_password_file":"/tmp/pw"}"#,
            r#""apple":{"guest_os":"macos","provision_full_name":"Flux","provision_username":"flux"}"#,
            r#""apple":{"guest_os":"macos","provision_remote_login":true}"#,
        ] {
            assert!(validate_request(&req(json)).is_err(), "{json}");
        }
        let linux = r#""apple":{"provision_full_name":"Flux","provision_username":"flux","provision_password_file":"/tmp/pw"}"#;
        let err = validate_request(&req(linux)).expect_err(linux).to_string();
        assert!(err.contains("macOS guests only"), "{err}");
    }

    #[test]
    fn macos_guests_reject_linux_only_rosetta_and_nested_virtualization() {
        for key in ["rosetta", "nested_virtualization"] {
            let json = format!(r#""apple":{{"guest_os":"macos","{key}":true}}"#);
            let err = validate_request(&req(&json)).expect_err(&json).to_string();
            assert!(err.contains("Linux-guest"), "{err}");
        }
    }

    #[test]
    fn one_port_may_be_forwarded_to_the_host_and_to_other_guests() {
        let both = r#""network":{"mode":"user","forwards":[{"host_port":5000,"guest_port":5000},{"host_port":5000,"guest_port":5000,"guests":true}]}"#;
        assert!(validate_request(&req(both)).is_ok());
        let twice = r#""network":{"mode":"user","forwards":[{"host_port":5000,"guest_port":5000,"guests":true},{"host_port":5000,"guest_port":6000,"guests":true}]}"#;
        assert!(validate_request(&req(twice)).is_err());
    }

    #[test]
    fn linux_only_features_are_rejected_with_a_reason() {
        for (json, needle) in [
            (r#""network":{"mode":"tap"}"#, "tap"),
            (
                r#""network":{"mode":"user","forwards":[{"host_port":2222,"guest_port":53,"protocol":"udp"}]}"#,
                "UDP port forwards",
            ),
            (
                r#""network":{"mode":"user","forwards":[{"host_port":80,"guest_port":80}]}"#,
                "below 1024",
            ),
            (
                r#""network":{"mode":"user","forwards":[{"host_port":2222,"guest_port":22},{"host_port":2222,"guest_port":23}]}"#,
                "more than once",
            ),
            (
                r#""shared_folders":[{"host_path":"/nonexistent-fluxvm-dir","guest_path":"/mnt/x"}]"#,
                "not an existing directory",
            ),
            (
                r#""shared_folders":[{"host_path":"/tmp","guest_path":"mnt"}]"#,
                "absolute",
            ),
            (r#""hugepages":true"#, "hugepages"),
            (r#""numa_node":1"#, "NUMA"),
            (r#""tpm":true"#, "TPM"),
            (r#""secure_boot":true,"kernel":"/boot/Image""#, "EFI boot"),
            (
                r#""apple":{"efi_secure_boot":{"db":["/k.der"]}}"#,
                "needs secure_boot",
            ),
            (
                r#""secure_boot":true,"apple":{"efi_secure_boot":{"db":["k.der"]}}"#,
                "absolute",
            ),
            (r#""apple":{"recovery":true}"#, "macOS guests"),
            (
                r#""apple":{"rosetta_cache":"default"}"#,
                "needs apple.rosetta",
            ),
            (r#""initrd":"/boot/initrd""#, "need kernel"),
            (r#""vfio_devices":["0000:01:00.0"]"#, "VFIO"),
            (r#""memory_mib":128"#, "512 MiB"),
        ] {
            let err = validate_request(&req(json)).expect_err(json).to_string();
            assert!(err.contains(needle), "{json}: {err}");
        }
    }

    #[test]
    fn the_matrix_names_what_is_and_is_not_supported() {
        assert!(
            CAPABILITIES
                .iter()
                .any(|c| c.supported && c.feature.contains("pause"))
        );
        assert!(
            CAPABILITIES
                .iter()
                .any(|c| !c.supported && c.feature.contains("tap"))
        );
        assert!(
            CAPABILITIES
                .iter()
                .any(|c| !c.supported && c.feature.contains("GPU"))
        );
    }

    #[test]
    fn shared_folders_get_a_persistent_fstab_mount() {
        let share = |p: &str, ro| SharedFolder {
            host_path: "/tmp".into(),
            guest_path: p.into(),
            read_only: ro,
        };
        let ci = with_shared_folder_mounts(
            CloudInitSpec::default(),
            &[share("/mnt/a", false), share("/mnt/b", true)],
        );
        let all = ci.runcmd.join("\n");
        assert!(all.contains("fs0 /mnt/a virtiofs defaults,nofail"));
        assert!(all.contains("fs1 /mnt/b virtiofs ro,nofail"));
        assert!(all.contains("mount /mnt/b"));
    }

    #[test]
    fn guest_reporting_adds_a_persistent_service_and_ssh_settings() {
        let ci = with_guest_reporting(CloudInitSpec::default());
        assert!(
            ci.write_files
                .iter()
                .any(|f| f.path.ends_with("fluxvm-report-ip.service"))
        );
        assert!(
            ci.write_files
                .iter()
                .any(|f| f.path.ends_with("fluxvm-report-ip") && f.content.contains("VELORA-IP"))
        );
        assert!(
            ci.write_files
                .iter()
                .any(|f| f.content.contains("PerSourcePenalties no"))
        );
        assert!(
            ci.runcmd
                .iter()
                .any(|c| c.contains("systemctl enable --now fluxvm-report-ip.service"))
        );
    }

    #[test]
    fn extra_disks_take_only_what_their_kind_uses() {
        let ok = [
            r#"{"path":"/d/a.raw","caching":"uncached","sync":"fsync","controller":"nvme"}"#,
            r#"{"name":"data","kind":"block","path":"/dev/disk4","sync":"none","controller":"usb"}"#,
            r#"{"kind":"nbd","url":"nbd://10.0.0.5:10809/vol","read_only":true}"#,
            r#"{"kind":"nbd","url":"nbd+unix:///vol?socket=/tmp/nbd.sock"}"#,
            r#"{"path":"/d/a.raw","block_device_id":"data-01"}"#,
        ];
        for d in ok {
            let r = req(&format!(r#""apple":{{"extra_disks":[{d}]}}"#));
            validate_request(&r).unwrap_or_else(|e| panic!("{d}: {e:#}"));
        }
        for (d, needle) in [
            (r#"{"path":"a.raw"}"#, "absolute"),
            (r#"{"kind":"block","path":"/tmp/x"}"#, "device"),
            (
                r#"{"kind":"block","path":"/dev/disk4","caching":"cached"}"#,
                "caching",
            ),
            (
                r#"{"kind":"block","path":"/dev/disk4","sync":"fsync"}"#,
                "fsync",
            ),
            (r#"{"kind":"nbd","url":"http://x/y"}"#, "nbd://"),
            (
                r#"{"kind":"nbd","url":"nbd://x/y","path":"/d/a.raw"}"#,
                "not path",
            ),
            (r#"{"path":"/d/a.raw","url":"nbd://x/y"}"#, "nbd disks"),
            (r#"{"name":"root","path":"/d/a.raw"}"#, "root"),
            (r#"{"name":"Big Disk","path":"/d/a.raw"}"#, "a-z"),
            (
                r#"{"path":"/d/a.raw","controller":"nvme","block_device_id":"x"}"#,
                "virtio controller",
            ),
            (
                r#"{"path":"/d/a.raw","block_device_id":"this-serial-is-way-too-long"}"#,
                "1-20",
            ),
        ] {
            let r = req(&format!(r#""apple":{{"extra_disks":[{d}]}}"#));
            let err = format!("{:#}", validate_request(&r).expect_err(d));
            assert!(err.contains(needle), "{d}: {err}");
        }
        let twice =
            req(r#""apple":{"extra_disks":[{"path":"/a.raw"},{"name":"disk0","path":"/b.raw"}]}"#);
        assert!(format!("{:#}", validate_request(&twice).unwrap_err()).contains("twice"));
    }

    #[test]
    fn console_ports_are_named_and_linux_only() {
        assert!(validate_request(&req(r#""apple":{"console_ports":["agent","log.v1"]}"#)).is_ok());
        for (json, needle) in [
            (r#""apple":{"console_ports":["Agent"]}"#, "a-z"),
            (r#""apple":{"console_ports":["../x"]}"#, "a-z"),
            (r#""apple":{"console_ports":[".x"]}"#, "a-z"),
            (r#""apple":{"console_ports":["a","a"]}"#, "twice"),
            (
                r#""apple":{"console_ports":["a","b","c","d","e","f","g","h","i"]}"#,
                "at most",
            ),
            (
                r#""apple":{"guest_os":"macos","console_ports":["a"]}"#,
                "Linux",
            ),
        ] {
            let err = format!("{:#}", validate_request(&req(json)).expect_err(json));
            assert!(err.contains(needle), "{json}: {err}");
        }
    }
}
