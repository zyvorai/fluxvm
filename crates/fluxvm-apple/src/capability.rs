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
        "macOS 26+ shared/host-only network, DHCP reservation, TCP/UDP forwards; one network per VM until the broker lands",
    ),
    yes(
        "custom Virtio device",
        "macOS 27+ Linux guests; discoverable device, host provider is a follow-up",
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
    no(
        "secure boot, TPM, confidential profiles",
        "not offered by Virtualization.framework",
    ),
    no("hotplug (cpu, memory, disks, nics)", "not supported"),
    no(
        "data disks, cdroms, non-default storage",
        "not implemented yet",
    ),
    no(
        "direct kernel boot, firmware overrides",
        "EFI boot from the disk only",
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

/// Rejects, with a specific message, any request feature the Apple backend cannot honour.
pub fn validate_request(req: &CreateVmRequest) -> Result<()> {
    macro_rules! reject {
        ($cond:expr, $msg:expr) => {
            if $cond {
                bail!("the vz backend does not support {}", $msg);
            }
        };
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
        if matches!(apple.guest_os, fluxvm_core::model::AppleGuest::Macos)
            && (apple.rosetta || apple.nested_virtualization || apple.clipboard)
        {
            bail!(
                "apple.rosetta, apple.nested_virtualization and apple.clipboard are Linux-guest features"
            );
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
            let ipv4 = |s: &str| s.parse::<std::net::Ipv4Addr>().is_ok();
            if !ipv4(&v.subnet) || !ipv4(&v.mask) {
                bail!("apple.vmnet subnet and mask must be IPv4 addresses");
            }
            if v.reserved_ip.as_deref().is_some_and(|ip| !ipv4(ip)) {
                bail!("apple.vmnet.reserved_ip must be an IPv4 address");
            }
            let mut seen = std::collections::HashSet::new();
            for f in &v.forwards {
                if !matches!(f.protocol.as_str(), "tcp" | "udp") {
                    bail!("apple.vmnet forward protocol must be tcp or udp");
                }
                if !ipv4(&f.guest_ip) {
                    bail!("apple.vmnet forward guest_ip must be an IPv4 address");
                }
                if f.host_port == 0 || f.guest_port == 0 {
                    bail!("apple.vmnet forward ports must be non-zero");
                }
                if !seen.insert((f.protocol.clone(), f.host_port)) {
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
    reject!(
        req.kernel.is_some() || req.initrd.is_some() || req.kernel_args.is_some(),
        "direct kernel boot (it boots EFI from the disk)"
    );
    reject!(req.firmware.is_some(), "firmware overrides");
    reject!(
        req.numa_node.is_some() || req.cpuset.is_some() || req.hugepages == Some(true),
        "NUMA, cpuset or hugepages"
    );
    reject!(!req.vfio_devices.is_empty(), "VFIO device passthrough");
    reject!(
        req.secure_boot == Some(true) || req.tpm == Some(true),
        "secure boot or a TPM"
    );
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
    reject!(!req.data_disks.is_empty(), "data disks");
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

/// For a guest with no network card and an `egress_allow` list: a forwarder from `127.0.0.1:3128` to the runner's proxy on the
/// host (vsock CID 2), and the proxy settings that make shells, apt and curl use it. The host decides what gets through.
pub fn with_egress_forwarder(mut ci: CloudInitSpec) -> CloudInitSpec {
    let port = crate::runner::EGRESS_PORT;
    ci.write_files.push(CloudInitFile {
        path: "/usr/local/sbin/fluxvm-egress".into(),
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
        path: "/etc/systemd/system/fluxvm-egress.service".into(),
        content: "[Unit]\nDescription=Forward to the FluxVM host's egress proxy\n[Service]\nExecStart=/usr/local/sbin/fluxvm-egress\nRestart=always\n[Install]\nWantedBy=multi-user.target\n".into(),
        permissions: Some("0644".into()),
    });
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
    ci.runcmd
        .push("systemctl daemon-reload && systemctl enable --now fluxvm-egress.service".into());
    ci
}

#[cfg(test)]
mod tests {
    use super::*;

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
        for (json, needle) in [
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
            (r#""secure_boot":true"#, "secure boot"),
            (r#""kernel":"/boot/vmlinuz""#, "direct kernel boot"),
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
}
