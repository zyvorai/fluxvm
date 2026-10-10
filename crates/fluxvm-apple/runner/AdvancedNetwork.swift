// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// macOS 26+ vmnet custom networks (shared or host-only) with a stable DHCP reservation and TCP/UDP host
// forwards, plus the macOS 27 custom Virtio device hook. One network per runner process: VMs that must share
// a network need the broker described in docs/vmnet-broker.md.

import Foundation
import Virtualization
import Darwin
#if canImport(vmnet)
import vmnet
#endif

struct FluxVMNetForward: Codable {
    let `protocol`: String
    let host_port: UInt16
    let guest_port: UInt16
    let guest_ip: String
}

struct FluxVMNetSpec: Codable {
    let mode: String                // "shared" | "host-only"
    let subnet: String
    let mask: String
    let reserved_ip: String?
    let forwards: [FluxVMNetForward]
}

#if canImport(vmnet)
@available(macOS 26.0, *)
final class FluxVMNetNetwork {
    let network: vmnet_network_ref

    private static func error(_ code: Int, _ m: String) -> NSError {
        NSError(domain: "fluxvm.vmnet", code: code, userInfo: [NSLocalizedDescriptionKey: m])
    }

    init(spec: FluxVMNetSpec, macAddress: String) throws {
        var status = vmnet_return_t.VMNET_FAILURE
        let mode: vmnet_mode_t = spec.mode == "host-only" ? .VMNET_HOST_MODE : .VMNET_SHARED_MODE
        guard let cfg = vmnet_network_configuration_create(mode, &status), status == .VMNET_SUCCESS else {
            throw Self.error(1, "vmnet_network_configuration_create failed (\(status.rawValue))")
        }

        var subnet = in_addr()
        var mask = in_addr()
        guard inet_pton(AF_INET, spec.subnet, &subnet) == 1, inet_pton(AF_INET, spec.mask, &mask) == 1 else {
            throw Self.error(2, "vmnet subnet \(spec.subnet)/\(spec.mask) is not IPv4")
        }
        let s = vmnet_network_configuration_set_ipv4_subnet(cfg, &subnet, &mask)
        guard s == .VMNET_SUCCESS else { throw Self.error(2, "vmnet subnet rejected (\(s.rawValue))") }

        if let ip = spec.reserved_ip {
            guard let macPtr = ether_aton(macAddress) else { throw Self.error(3, "vmnet reservation: bad MAC \(macAddress)") }
            var mac = macPtr.pointee
            var addr = in_addr()
            guard inet_pton(AF_INET, ip, &addr) == 1 else { throw Self.error(3, "vmnet reservation: \(ip) is not IPv4") }
            let r = vmnet_network_configuration_add_dhcp_reservation(cfg, &mac, &addr)
            guard r == .VMNET_SUCCESS else { throw Self.error(3, "vmnet DHCP reservation rejected (\(r.rawValue))") }
        }

        for f in spec.forwards {
            var addr = in_addr()
            guard inet_pton(AF_INET, f.guest_ip, &addr) == 1 else { throw Self.error(4, "vmnet forward: \(f.guest_ip) is not IPv4") }
            let proto = f.protocol.lowercased() == "udp" ? UInt8(IPPROTO_UDP) : UInt8(IPPROTO_TCP)
            let r = vmnet_network_configuration_add_port_forwarding_rule(
                cfg, proto, sa_family_t(AF_INET), f.guest_port, f.host_port, &addr)
            guard r == .VMNET_SUCCESS else { throw Self.error(4, "vmnet forward \(f.host_port)->\(f.guest_port) rejected (\(r.rawValue))") }
        }

        guard let net = vmnet_network_create(cfg, &status), status == .VMNET_SUCCESS else {
            throw Self.error(5, "vmnet_network_create failed (\(status.rawValue))")
        }
        self.network = net
    }

    func attachment() -> VZVmnetNetworkDeviceAttachment {
        VZVmnetNetworkDeviceAttachment(network: network)
    }
}
#endif

/// A discoverable but driverless custom Virtio device (vendor-specific device ID). A host-side provider is a follow-up.
@available(macOS 27.0, *)
func fluxVMCustomVirtioConfiguration() -> VZCustomVirtioDeviceConfiguration {
    let d = VZCustomVirtioDeviceConfiguration()
    d.deviceID = 0xFF00
    d.pciClassID = 0xFF
    d.pciSubclassID = 0x00
    d.virtioQueueCount = 2
    return d
}
