// SPDX-License-Identifier: Apache-2.0
use std::fs;
use std::path::PathBuf;

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}
fn text(p: &str) -> String {
    fs::read_to_string(root().join(p)).unwrap()
}

#[test]
fn custom_virtio_has_real_bulk_queue() {
    let s = text("runner/CustomVirtio.swift");
    for needle in [
        "bulk-zero",
        "bulk-fill",
        "bulk-copy",
        "bulk-crc32",
        "VZGuestMemoryMapping",
        "maximumBulkBytes",
    ] {
        assert!(s.contains(needle), "missing {needle}");
    }
}

#[test]
fn brokers_are_wired() {
    let net = text("runner/VmnetSerialization.swift");
    assert!(net.contains("xpc_connection_create_mach_service"));
    assert!(net.contains("vmnet_network_create_with_serialization"));
    let usb = text("runner/USBPassthrough.swift");
    assert!(usb.contains("AAUSBAccessory(xpcRepresentation:"));
    assert!(usb.contains("VZUSBPassthroughDeviceConfiguration"));
}

#[test]
fn linux_guest_driver_is_shipped() {
    let p = root().join("../../guest/virtio-flux/virtio_flux.c");
    let s = fs::read_to_string(p).unwrap();
    assert!(s.contains("VIRTIO_ID_FLUXVM 0x3f"));
    assert!(s.contains("FLUXVM_IOC_BULK_TEST"));
}
