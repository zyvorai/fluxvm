// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#if os(macOS) && canImport(vmnet)
import Foundation
import vmnet
import XPC

let fluxVmnetBrokerService = "dev.zyvor.fluxvm.vmnetd"

@available(macOS 26.0, *)
func fluxVmnetCopySerialization(_ network: vmnet_network_ref) throws -> xpc_object_t {
    var status = vmnet_return_t.VMNET_FAILURE
    guard let object = vmnet_network_copy_serialization(network, &status), status == .VMNET_SUCCESS else {
        throw NSError(domain: "fluxvm.vmnet", code: Int(status.rawValue),
                      userInfo: [NSLocalizedDescriptionKey: "vmnet network serialization failed (\(status.rawValue))"])
    }
    return object
}

@available(macOS 26.0, *)
func fluxVmnetCreateFromSerialization(_ object: xpc_object_t) throws -> vmnet_network_ref {
    var status = vmnet_return_t.VMNET_FAILURE
    guard let network = vmnet_network_create_with_serialization(object, &status), status == .VMNET_SUCCESS else {
        throw NSError(domain: "fluxvm.vmnet", code: Int(status.rawValue),
                      userInfo: [NSLocalizedDescriptionKey: "vmnet network import failed (\(status.rawValue))"])
    }
    return network
}

@available(macOS 26.0, *)
final class FluxVmnetBrokerClient {
    private let connection: xpc_connection_t

    init() {
        connection = xpc_connection_create_mach_service(fluxVmnetBrokerService, nil, 0)
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_activate(connection)
    }

    deinit { xpc_connection_cancel(connection) }

    func acquire(name: String, spec: FluxVMNetSpec, macAddress: String?) throws -> vmnet_network_ref {
        let m = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(m, "op", "acquire")
        xpc_dictionary_set_string(m, "name", name)
        xpc_dictionary_set_string(m, "mode", spec.mode)
        xpc_dictionary_set_string(m, "subnet", spec.subnet)
        xpc_dictionary_set_string(m, "mask", spec.mask)
        if let macAddress { xpc_dictionary_set_string(m, "mac", macAddress) }
        if let ip = spec.reserved_ip { xpc_dictionary_set_string(m, "reserved_ip", ip) }
        // Strings, so the broker's fingerprint of a named network covers every option.
        let options: [(String, String?)] = [
            ("ipv6_prefix", spec.ipv6_prefix), ("mtu", spec.mtu.map(String.init)),
            ("external_interface", spec.external_interface),
            ("disable_dhcp", spec.disable_dhcp == true ? "true" : nil),
            ("disable_dns_proxy", spec.disable_dns_proxy == true ? "true" : nil),
            ("disable_nat44", spec.disable_nat44 == true ? "true" : nil),
            ("disable_nat66", spec.disable_nat66 == true ? "true" : nil),
            ("disable_router_advertisement", spec.disable_router_advertisement == true ? "true" : nil),
        ]
        for case let (key, value?) in options { xpc_dictionary_set_string(m, key, value) }
        if let forwards = spec.forwards, !forwards.isEmpty {
            let a = xpc_array_create(nil, 0)
            for f in forwards {
                let d = xpc_dictionary_create(nil, nil, 0)
                xpc_dictionary_set_string(d, "protocol", f.protocol)
                xpc_dictionary_set_uint64(d, "host_port", UInt64(f.host_port))
                xpc_dictionary_set_uint64(d, "guest_port", UInt64(f.guest_port))
                xpc_dictionary_set_string(d, "guest_ip", f.guest_ip)
                xpc_array_append_value(a, d)
            }
            xpc_dictionary_set_value(m, "forwards", a)
        }
        let reply = try send(m)
        if let error = xpc_dictionary_get_string(reply, "error") {
            throw NSError(domain: "fluxvm.vmnet", code: 50,
                          userInfo: [NSLocalizedDescriptionKey: String(cString: error)])
        }
        guard let object = xpc_dictionary_get_value(reply, "network") else {
            throw NSError(domain: "fluxvm.vmnet", code: 51,
                          userInfo: [NSLocalizedDescriptionKey: "vmnetd returned no serialized network"])
        }
        return try fluxVmnetCreateFromSerialization(object)
    }

    func release(name: String) {
        let m = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(m, "op", "release")
        xpc_dictionary_set_string(m, "name", name)
        _ = try? send(m)
    }

    private func send(_ message: xpc_object_t) throws -> xpc_object_t {
        let sem = DispatchSemaphore(value: 0)
        var answer: xpc_object_t?
        xpc_connection_send_message_with_reply(connection, message, DispatchQueue.global()) { reply in
            answer = reply
            sem.signal()
        }
        guard sem.wait(timeout: .now() + 5) == .success, let answer else {
            throw NSError(domain: "fluxvm.vmnet", code: 52,
                          userInfo: [NSLocalizedDescriptionKey: "vmnetd timed out"])
        }
        if xpc_get_type(answer) == XPC_TYPE_ERROR {
            throw NSError(domain: "fluxvm.vmnet", code: 53,
                          userInfo: [NSLocalizedDescriptionKey: "vmnetd XPC connection failed"])
        }
        return answer
    }
}
#endif
