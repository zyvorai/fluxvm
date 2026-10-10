// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AppleHostCapabilities {
    pub os_version: String,
    pub cpu_count: usize,
    #[serde(rename = "maximumVmCPUs")]
    pub maximum_vm_cpus: usize,
    pub physical_memory_bytes: u64,
    pub maximum_vm_memory_bytes: u64,
    pub nested_virtualization: bool,
    pub bridged_interfaces: Vec<String>,
    pub vmnet_custom_networks: bool,
    pub vmnet_serialization: bool,
    pub custom_virtio: bool,
    pub custom_virtio_queue_backend: bool,
    pub guest_memory_mapping: bool,
    #[serde(rename = "usbPassthroughAPI")]
    pub usb_passthrough_api: bool,
}

/// Query the signed Swift helper without creating a VM. The daemon itself
/// continues not to link Virtualization.framework.
pub fn host_capabilities() -> Result<AppleHostCapabilities> {
    #[cfg(target_os = "macos")]
    {
        let runner = crate::find_runner()?;
        let output = std::process::Command::new(&runner)
            .arg("host-capabilities")
            .output()
            .with_context(|| format!("running {} host-capabilities", runner.display()))?;
        if !output.status.success() {
            bail!(
                "host-capabilities failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        serde_json::from_slice(&output.stdout).context("decoding VZ host capabilities")
    }
    #[cfg(not(target_os = "macos"))]
    {
        bail!("Apple host capabilities are only available on macOS")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Shape emitted by `fluxvm-vz-runner host-capabilities` (Swift Codable keys).
    #[test]
    fn decodes_runner_output() {
        let json = r#"{"guestMemoryMapping":true,"maximumVmCPUs":64,"vmnetCustomNetworks":true,
            "customVirtio":true,"physicalMemoryBytes":17179869184,"maximumVmMemoryBytes":17179869184,
            "nestedVirtualization":true,"cpuCount":10,"customVirtioQueueBackend":true,
            "osVersion":"Version 27.2","usbPassthroughAPI":true,"vmnetSerialization":true,
            "bridgedInterfaces":["en0"]}"#;
        let caps: AppleHostCapabilities = serde_json::from_str(json).unwrap();
        assert_eq!(caps.maximum_vm_cpus, 64);
        assert!(caps.usb_passthrough_api && caps.guest_memory_mapping);
    }
}
