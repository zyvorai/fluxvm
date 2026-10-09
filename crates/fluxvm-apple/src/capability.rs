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
        "shared folders (virtiofs)",
        "host directory mounted in the guest as tag fs0, fs1, …",
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
        "IPSW install required before first boot (unverified on hardware here)",
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
    if let Some(apple) = &req.apple {
        if !apple.egress_allow.is_empty() {
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
