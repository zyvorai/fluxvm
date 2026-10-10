// SPDX-License-Identifier: Apache-2.0
//! Every Virtualization/vmnet API listed in docs/macos-vz27-remaining-complete.md is used by the runner sources, so a
//! refactor cannot silently drop one. Runs on any OS; the Swift itself is compiled only on macOS.
use std::fs;
use std::path::PathBuf;

fn sources() -> String {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let mut all = String::new();
    for sub in ["runner", "macos/vmnetd"] {
        for e in fs::read_dir(dir.join(sub)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "swift") {
                all.push_str(&fs::read_to_string(p).unwrap());
            }
        }
    }
    all
}

fn assert_all(needles: &[&str]) {
    let s = sources();
    let missing: Vec<_> = needles.iter().filter(|n| !s.contains(**n)).collect();
    assert!(missing.is_empty(), "runner does not use {missing:?}");
}

#[test]
fn macos_27_virtualization_apis() {
    assert_all(&[
        // EFI Secure Boot
        "enableSecureBootUsingDefaultPlatformKey()",
        "enableSecureBoot(platformKey:",
        "disableSecureBoot()",
        "resetSecureBoot()",
        "enrollDefaultSecureBootSignatures()",
        "enrollSecureBootSignatures(",
        "isSecureBootEnabled",
        "enrolledSecureBootSignatures",
        "VZEFISignatureList(contentsOf:",
        "VZEFISignatureDatabaseConfiguration(",
        // Custom Virtio device
        "customVirtioDevices",
        "customVirtioDeviceDidAcceptDriverOk",
        "customVirtioDeviceWillStop",
        "customVirtioDeviceWillPause",
        "customVirtioDeviceWillResume",
        "customVirtioDeviceWillReset",
        "customVirtioDeviceSaveState(forRestore",
        "customVirtioDeviceShouldRestore",
        "requestReset()",
        "guestMemoryMapping(atPhysicalAddress:",
        // USB
        "VZUSBController.Delegate",
        "usbPassthroughDeviceDidDisconnect",
        "VZUSBPassthroughDeviceConfiguration",
        // Configuration, view, provisioning, DiskImageKit
        "c.label = ",
        "VZVirtualMachineViewAdaptor(virtualMachine:",
        "setGuestProvisioning(",
        "VZDiskImageStorageDeviceAttachment(diskImage:",
        // Error codes
        ".guestProvisioningInvalidFullName",
        ".guestProvisioningInvalidUsername",
        ".guestProvisioningInvalidPassword",
        ".efiSecureBootEnrollmentFailed",
        ".efiVariableInaccessible",
    ]);
}

#[test]
fn earlier_virtualization_and_vmnet_apis() {
    assert_all(&[
        "attachmentWasDisconnectedWithError",
        "VZNetworkBlockDeviceStorageDeviceAttachmentDelegate",
        "blockDeviceIdentifier",
        "validateBlockDeviceIdentifier(",
        "startUpFromMacOSRecovery",
        "VZLinuxRosettaDirectoryShare.availability",
        "installRosetta",
        "setCachingOptions(",
        "saveMachineStateTo(",
        "restoreMachineStateFrom(",
        "vmnet_network_configuration_set_ipv6_prefix",
        "vmnet_network_configuration_set_mtu",
        "vmnet_network_configuration_set_external_interface",
        "vmnet_network_configuration_disable_dhcp",
        "vmnet_network_configuration_disable_dns_proxy",
        "vmnet_network_configuration_disable_nat44",
        "vmnet_network_configuration_disable_nat66",
        "vmnet_network_configuration_disable_router_advertisement",
    ]);
}

#[test]
fn macos_guests_can_restore_saved_state() {
    let runner = sources();
    assert!(
        !runner.contains("cfg.restore_state, cfg.guest_os == \"linux\""),
        "restore must not be gated to Linux guests"
    );
}

#[test]
fn vmnetd_compiles_the_shared_options_file() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let script = fs::read_to_string(dir.join("macos/vmnetd/build-install.sh")).unwrap();
    assert!(script.contains("runner/VmnetOptions.swift"));
}
