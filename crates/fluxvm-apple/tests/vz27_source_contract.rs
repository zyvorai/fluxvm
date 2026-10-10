// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
// Source-contract tests run on Linux CI even though Virtualization.framework cannot.

#[test]
fn custom_virtio_has_a_real_provider_and_queue_handler() {
    let src = include_str!("../runner/CustomVirtio.swift");
    for needle in [
        "VZCustomVirtioDeviceDelegateProvider",
        "didCreateDevice",
        "didReceiveNotificationFor",
        "queue.nextElement()",
        "element.returnToQueue()",
        "readBytes(withExactLength:",
        "guestMemoryMapping(atPhysicalAddress:",
    ] {
        assert!(src.contains(needle), "missing custom Virtio contract: {needle}");
    }
}

#[test]
fn vmnet_cross_process_path_uses_apple_serialization_apis() {
    let src = include_str!("../runner/VmnetSerialization.swift");
    assert!(src.contains("vmnet_network_copy_serialization"));
    assert!(src.contains("vmnet_network_create_with_serialization"));
}

#[test]
fn protocol_is_versioned_and_bounded() {
    let src = include_str!("../runner/FluxVirtioProtocol.swift");
    assert!(src.contains("static let version: UInt16 = 1"));
    assert!(src.contains("static let maximumFrameBytes = 1 << 20"));
}
