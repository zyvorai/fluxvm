// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
import Foundation
import Virtualization
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
    let name: String?            // named network => shared through fluxvm-vmnetd
    let mode: String             // "shared" | "host-only"
    let subnet: String
    let mask: String
    let dhcp_start: String?
    let dhcp_end: String?
    let reserved_ip: String?
    let forwards: [FluxVMNetForward]?
}

#if canImport(vmnet)
var fluxVMNetNetworkKeepAlive: [Any] = []

@available(macOS 26.0, *)
final class FluxVMNetNetwork {
    let network: vmnet_network_ref
    let brokerName: String?

    private static func fail(_ what: String, _ status: vmnet_return_t? = nil) -> NSError {
        let detail = status.map { " (vmnet status \($0.rawValue))" } ?? ""
        return NSError(domain: "fluxvm.vmnet", code: 1,
                       userInfo: [NSLocalizedDescriptionKey: "vmnet: \(what)\(detail)"])
    }

    private static func addr(_ s: String, _ what: String) throws -> in_addr {
        var a = in_addr()
        guard inet_pton(AF_INET, s, &a) == 1 else { throw fail("invalid IPv4 \(what) \(s)") }
        return a
    }

    private static func parseMAC(_ s: String) throws -> ether_addr_t {
        let parts = s.split(separator: ":").compactMap { UInt8($0, radix: 16) }
        guard parts.count == 6, s.split(separator: ":").count == 6 else { throw fail("invalid MAC address \(s)") }
        return ether_addr_t(octet: (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]))
    }

    init(spec: FluxVMNetSpec, macAddress: String?) throws {
        if let name = spec.name, !name.isEmpty {
            self.network = try FluxVmnetBrokerClient().acquire(name: name, spec: spec, macAddress: macAddress)
            self.brokerName = name
            fluxVMNetNetworkKeepAlive.append(self)
            return
        }

        var status = vmnet_return_t.VMNET_FAILURE
        let mode: vmnet_mode_t = spec.mode == "host-only" ? .VMNET_HOST_MODE : .VMNET_SHARED_MODE
        guard let cfg = vmnet_network_configuration_create(mode, &status), status == .VMNET_SUCCESS else {
            throw Self.fail("could not create network configuration", status)
        }

        var subnet = try Self.addr(spec.subnet, "subnet")
        var mask = try Self.addr(spec.mask, "mask")
        status = vmnet_network_configuration_set_ipv4_subnet(cfg, &subnet, &mask)
        guard status == .VMNET_SUCCESS else { throw Self.fail("set_ipv4_subnet failed", status) }

        if spec.dhcp_start != nil || spec.dhcp_end != nil {
            throw Self.fail("a custom DHCP range is not supported by the vmnet SDK; use reserved_ip")
        }
        if let ip = spec.reserved_ip {
            guard let macAddress else { throw Self.fail("reserved_ip needs the VM to have a MAC address") }
            var mac = try Self.parseMAC(macAddress)
            var a = try Self.addr(ip, "reserved_ip")
            status = vmnet_network_configuration_add_dhcp_reservation(cfg, &mac, &a)
            guard status == .VMNET_SUCCESS else { throw Self.fail("add_dhcp_reservation failed", status) }
        }
        for f in spec.forwards ?? [] {
            var a = try Self.addr(f.guest_ip, "forward guest_ip")
            let proto = f.protocol.lowercased() == "udp" ? UInt8(IPPROTO_UDP) : UInt8(IPPROTO_TCP)
            status = vmnet_network_configuration_add_port_forwarding_rule(
                cfg, proto, sa_family_t(AF_INET), f.guest_port, f.host_port, &a)
            guard status == .VMNET_SUCCESS else { throw Self.fail("add_port_forwarding_rule failed", status) }
        }
        guard let net = vmnet_network_create(cfg, &status), status == .VMNET_SUCCESS else {
            throw Self.fail("could not create network (needs the com.apple.vm.networking entitlement)", status)
        }
        self.network = net
        self.brokerName = nil
        fluxVMNetNetworkKeepAlive.append(self)
    }

    deinit {
        if let brokerName { FluxVmnetBrokerClient().release(name: brokerName) }
    }

    func attachment() -> VZVmnetNetworkDeviceAttachment {
        VZVmnetNetworkDeviceAttachment(network: network)
    }
}
#endif

@available(macOS 27.0, *)
func fluxVMCustomVirtioConfiguration(vmID: String) -> VZCustomVirtioDeviceConfiguration {
    fluxVMCustomVirtioConfigurationImpl(vmID: vmID)
}
