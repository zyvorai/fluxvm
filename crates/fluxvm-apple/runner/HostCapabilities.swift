
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
    let customVirtio: Bool
}

func fluxAppleHostCapabilities() -> FluxAppleHostCapabilities {
    let p = ProcessInfo.processInfo
    let nested: Bool
    if #available(macOS 15.0, *) {
        nested = VZGenericPlatformConfiguration.isNestedVirtualizationSupported
    } else {
        nested = false
    }

    return FluxAppleHostCapabilities(
        osVersion: p.operatingSystemVersionString,
        cpuCount: p.processorCount,
        maximumVmCPUs: VZVirtualMachineConfiguration.maximumAllowedCPUCount,
        physicalMemoryBytes: p.physicalMemory,
        maximumVmMemoryBytes: VZVirtualMachineConfiguration.maximumAllowedMemorySize,
        nestedVirtualization: nested,
        bridgedInterfaces: VZBridgedNetworkInterface.networkInterfaces.map { $0.identifier },
        vmnetCustomNetworks: {
            if #available(macOS 26.0, *) { return true }
            return false
        }(),
        customVirtio: {
            if #available(macOS 27.0, *) { return true }
            return false
        }()
    )
}
