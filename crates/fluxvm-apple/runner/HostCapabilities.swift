
// Copyright 2026 Zyvor AI Labs
// SPDX-License-Identifier: Apache-2.0
import Foundation
import Virtualization

struct FluxAppleHostCapabilities: Codable {
    let osVersion: String
    let cpuCount: Int
    let maximumVmCPUs: Int
    let physicalMemoryBytes: UInt64
    let maximumVmMemoryBytes: UInt64
    let nestedVirtualization: Bool
    let bridgedInterfaces: [String]
    let vmnetCustomNetworks: Bool
    let vmnetSerialization: Bool
    let customVirtio: Bool
    let customVirtioQueueBackend: Bool
    let guestMemoryMapping: Bool
    let usbPassthroughAPI: Bool
}

func fluxAppleHostCapabilities() -> FluxAppleHostCapabilities {
    let p = ProcessInfo.processInfo
    let nested: Bool
    if #available(macOS 15.0, *) {
        nested = VZGenericPlatformConfiguration.isNestedVirtualizationSupported
    } else {
        nested = false
    }
    let has26: Bool = {
        if #available(macOS 26.0, *) { return true }
        return false
    }()
    let has27: Bool = {
        if #available(macOS 27.0, *) { return true }
        return false
    }()

    return FluxAppleHostCapabilities(
        osVersion: p.operatingSystemVersionString,
        cpuCount: p.processorCount,
        maximumVmCPUs: VZVirtualMachineConfiguration.maximumAllowedCPUCount,
        physicalMemoryBytes: p.physicalMemory,
        maximumVmMemoryBytes: VZVirtualMachineConfiguration.maximumAllowedMemorySize,
        nestedVirtualization: nested,
        bridgedInterfaces: VZBridgedNetworkInterface.networkInterfaces.map { $0.identifier },
        vmnetCustomNetworks: has26,
        vmnetSerialization: has26,
        customVirtio: has27,
        customVirtioQueueBackend: has27,
        guestMemoryMapping: has27,
        // The API exists on 27; using it still requires an AccessoryAccess UI
        // broker and explicit user consent, so this is not a readiness flag.
        usbPassthroughAPI: has27
    )
}
