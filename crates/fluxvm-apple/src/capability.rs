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
    Capability { feature, supported: true, note }
}
const fn no(feature: &'static str, note: &'static str) -> Capability {
    Capability { feature, supported: false, note }
}

pub const CAPABILITIES: &[Capability] = &[
    yes("vcpus", "any count the host allows"),
    yes("memory_mib", "checked against the host"),
    yes("disk (raw image, APFS clone)", "qcow2 must be converted to raw first"),
    yes("cloud_init", "NoCloud seed built with hdiutil"),
    yes("network user (NAT)", "guest reachable by its address; no port forwards"),
    yes("serial console", "VM log and /v1/vms/{id}/serial"),
    yes("pause / resume", "Virtualization.framework"),
    yes("graceful shutdown / stop", "ACPI power button, then force stop"),
    yes("guest agent over vsock", "needs the guest agent in the image; proxied like Firecracker"),
    yes("macOS guests", "IPSW install required before first boot (unverified on hardware here)"),
    no("tap / macvtap / netns / eBPF networking", "Linux kernel features"),
    no("port forwards", "NAT has no host-side forwards"),
    no("NUMA, hugepages, cpuset, vfio", "no such controls on Apple silicon"),
    no("secure boot, TPM, confidential profiles", "not offered by Virtualization.framework"),
    no("hotplug (cpu, memory, disks, nics)", "not supported"),
    no("shared folders (virtiofs)", "not implemented yet"),
    no("data disks, cdroms, non-default storage", "not implemented yet"),
    no("direct kernel boot, firmware overrides", "EFI boot from the disk only"),
    no("live migration, snapshots of running VMs", "not implemented"),
    no("GPU passthrough", "macOS guests get Metal-accelerated paravirtual graphics; Linux guests a 2D virtio display"),
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
    match &req.network {
        NetworkSpec::None => {}
        NetworkSpec::User { forwards } => reject!(!forwards.is_empty(), "port forwards (use the guest's NAT address)"),
        _ => bail!("the vz backend supports only network mode `user` (NAT) or `none`; tap and macvtap are Linux features"),
    }
    reject!(req.kernel.is_some() || req.initrd.is_some() || req.kernel_args.is_some(), "direct kernel boot (it boots EFI from the disk)");
    reject!(req.firmware.is_some(), "firmware overrides");
    reject!(req.numa_node.is_some() || req.cpuset.is_some() || req.hugepages == Some(true), "NUMA, cpuset or hugepages");
    reject!(!req.vfio_devices.is_empty(), "VFIO device passthrough");
    reject!(req.secure_boot == Some(true) || req.tpm == Some(true), "secure boot or a TPM");
    reject!(!req.shared_folders.is_empty(), "shared folders");
    reject!(!req.data_disks.is_empty(), "data disks");
    reject!(!req.cdroms.is_empty(), "cdroms (use apple.media for an installer image)");
    reject!(req.hyperv, "Hyper-V enlightenments");
    reject!(req.qga.as_ref().is_some_and(|q| q.enabled), "the QEMU guest agent channel");
    reject!(req.storage != StorageBackend::Default, "storage backends other than the default raw clone");
    reject!(req.max_vcpus.is_some_and(|m| m > req.vcpus) || req.max_memory_mib.is_some_and(|m| m > req.memory_mib), "CPU or memory hotplug headroom");
    reject!(req.loadvm_tag.is_some(), "resuming from a snapshot tag");
    reject!(!req.extra_args.is_empty(), "extra VMM arguments");
    reject!(
        req.net_mbit_limit.is_some() || req.net_pps_limit.is_some() || req.blk_mbit_limit.is_some() || req.blk_ops_limit.is_some(),
        "I/O rate limits"
    );
    if req.vcpus == 0 || req.memory_mib < 512 {
        bail!("the vz backend needs at least 1 vCPU and 512 MiB of memory");
    }
    Ok(())
}

use fluxvm_core::model::{CloudInitFile, CloudInitSpec};

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
    ci.runcmd.insert(0, "systemctl reload ssh || systemctl reload sshd || true".into());
    ci.runcmd.insert(1, "systemctl daemon-reload && systemctl enable --now fluxvm-report-ip.service".into());
    ci
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(extra: &str) -> CreateVmRequest {
        let sep = if extra.is_empty() { "" } else { "," };
        serde_json::from_str(&format!("{{\"name\":\"t\",\"backend\":\"vz\",\"image\":\"/x.raw\"{sep}{extra}}}")).unwrap()
    }

    #[test]
    fn a_plain_request_is_accepted() {
        assert!(validate_request(&req(r#""vcpus":2,"memory_mib":2048"#)).is_ok());
        assert!(validate_request(&req(r#""network":{"mode":"user"}"#)).is_ok());
        assert!(validate_request(&req(r#""network":{"mode":"none"}"#)).is_ok());
    }

    #[test]
    fn linux_only_features_are_rejected_with_a_reason() {
        for (json, needle) in [
            (r#""network":{"mode":"tap"}"#, "tap"),
            (r#""network":{"mode":"user","forwards":[{"host_port":2222,"guest_port":22}]}"#, "port forwards"),
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
        assert!(CAPABILITIES.iter().any(|c| c.supported && c.feature.contains("pause")));
        assert!(CAPABILITIES.iter().any(|c| !c.supported && c.feature.contains("tap")));
        assert!(CAPABILITIES.iter().any(|c| !c.supported && c.feature.contains("GPU")));
    }

    #[test]
    fn guest_reporting_adds_a_persistent_service_and_ssh_settings() {
        let ci = with_guest_reporting(CloudInitSpec::default());
        assert!(ci.write_files.iter().any(|f| f.path.ends_with("fluxvm-report-ip.service")));
        assert!(ci.write_files.iter().any(|f| f.path.ends_with("fluxvm-report-ip") && f.content.contains("VELORA-IP")));
        assert!(ci.write_files.iter().any(|f| f.content.contains("PerSourcePenalties no")));
        assert!(ci.runcmd.iter().any(|c| c.contains("systemctl enable --now fluxvm-report-ip.service")));
    }
}
