// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Compiled into both the VZ runner and fluxvm-vmnetd, so it imports only Foundation and vmnet.
import Foundation
#if canImport(vmnet)
import vmnet

/// The macOS 26 vmnet options beyond subnet, reservation and forwards.
@available(macOS 26.0, *)
func fluxVmnetApplyOptions(_ cfg: vmnet_network_configuration_ref, ipv6Prefix: String?, mtu: UInt32?,
                           externalInterface: String?, disableDHCP: Bool, disableDNSProxy: Bool,
                           disableNAT44: Bool, disableNAT66: Bool, disableRouterAdvertisement: Bool) throws {
    func fail(_ what: String, _ status: vmnet_return_t) -> NSError {
        NSError(domain: "fluxvm.vmnet", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "vmnet: \(what) (vmnet status \(status.rawValue))"])
    }
    if let p = ipv6Prefix {
        let parts = p.split(separator: "/", maxSplits: 1).map(String.init)
        var prefix = in6_addr()
        guard parts.count == 2, let len = UInt8(parts[1]), len > 0, len <= 128,
              inet_pton(AF_INET6, parts[0], &prefix) == 1 else {
            throw NSError(domain: "fluxvm.vmnet", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "vmnet: invalid IPv6 prefix \(p)"])
        }
        let status = vmnet_network_configuration_set_ipv6_prefix(cfg, &prefix, len)
        guard status == .VMNET_SUCCESS else { throw fail("set_ipv6_prefix failed", status) }
    }
    if let mtu {
        let status = vmnet_network_configuration_set_mtu(cfg, mtu)
        guard status == .VMNET_SUCCESS else { throw fail("set_mtu \(mtu) failed", status) }
    }
    if let name = externalInterface {
        let status = vmnet_network_configuration_set_external_interface(cfg, name)
        guard status == .VMNET_SUCCESS else { throw fail("set_external_interface \(name) failed", status) }
    }
    if disableDHCP { vmnet_network_configuration_disable_dhcp(cfg) }
    if disableDNSProxy { vmnet_network_configuration_disable_dns_proxy(cfg) }
    if disableNAT44 { vmnet_network_configuration_disable_nat44(cfg) }
    if disableNAT66 { vmnet_network_configuration_disable_nat66(cfg) }
    if disableRouterAdvertisement { vmnet_network_configuration_disable_router_advertisement(cfg) }
}
#endif
