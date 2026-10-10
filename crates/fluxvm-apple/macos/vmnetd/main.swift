// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
import Foundation
import Dispatch
import XPC
import vmnet
import Darwin

private let service = "dev.zyvor.fluxvm.vmnetd"
private let q = DispatchQueue(label: "dev.zyvor.fluxvm.vmnetd")

@available(macOS 26.0, *)
final class NetworkEntry {
    let network: vmnet_network_ref
    let fingerprint: String
    var refs: Int
    init(network: vmnet_network_ref, fingerprint: String) {
        self.network = network
        self.fingerprint = fingerprint
        self.refs = 1
    }
}

@available(macOS 26.0, *)
var networks: [String: NetworkEntry] = [:]

func string(_ d: xpc_object_t, _ key: String) -> String? {
    key.withCString { k in xpc_dictionary_get_string(d, k).map { String(cString: $0) } }
}

func replyError(_ request: xpc_object_t, _ peer: xpc_connection_t, _ text: String) {
    guard let reply = xpc_dictionary_create_reply(request) else { return }
    xpc_dictionary_set_string(reply, "error", text)
    xpc_connection_send_message(peer, reply)
}

@available(macOS 26.0, *)
func ip(_ value: String, _ what: String) throws -> in_addr {
    var a = in_addr()
    guard inet_pton(AF_INET, value, &a) == 1 else {
        throw NSError(domain: service, code: 10, userInfo: [NSLocalizedDescriptionKey: "invalid \(what): \(value)"])
    }
    return a
}

@available(macOS 26.0, *)
func mac(_ value: String) throws -> ether_addr_t {
    let p = value.split(separator: ":").compactMap { UInt8($0, radix: 16) }
    guard p.count == 6 else {
        throw NSError(domain: service, code: 11, userInfo: [NSLocalizedDescriptionKey: "invalid MAC: \(value)"])
    }
    return ether_addr_t(octet: (p[0], p[1], p[2], p[3], p[4], p[5]))
}

@available(macOS 26.0, *)
func fingerprint(_ request: xpc_object_t) -> String {
    let keys = ["mode", "subnet", "mask", "mac", "reserved_ip"]
    var parts = keys.map { "\($0)=\(string(request, $0) ?? "")" }
    if let forwards = xpc_dictionary_get_value(request, "forwards"), xpc_get_type(forwards) == XPC_TYPE_ARRAY {
        xpc_array_apply(forwards) { index, raw in
            let proto = xpc_dictionary_get_string(raw, "protocol").map { String(cString: $0) } ?? ""
            let guest = xpc_dictionary_get_string(raw, "guest_ip").map { String(cString: $0) } ?? ""
            let hp = xpc_dictionary_get_uint64(raw, "host_port")
            let gp = xpc_dictionary_get_uint64(raw, "guest_port")
            parts.append("f\(index)=\(proto):\(hp)->\(guest):\(gp)")
            return true
        }
    }
    return parts.joined(separator: "|")
}

@available(macOS 26.0, *)
func makeNetwork(_ request: xpc_object_t) throws -> vmnet_network_ref {
    guard let modeString = string(request, "mode"), let subnetString = string(request, "subnet"),
          let maskString = string(request, "mask") else {
        throw NSError(domain: service, code: 12, userInfo: [NSLocalizedDescriptionKey: "missing mode/subnet/mask"])
    }
    var status = vmnet_return_t.VMNET_FAILURE
    let mode: vmnet_mode_t = modeString == "host-only" ? .VMNET_HOST_MODE : .VMNET_SHARED_MODE
    guard let config = vmnet_network_configuration_create(mode, &status), status == .VMNET_SUCCESS else {
        throw NSError(domain: service, code: Int(status.rawValue), userInfo: [NSLocalizedDescriptionKey: "configuration create failed"])
    }
    var subnet = try ip(subnetString, "subnet")
    var maskValue = try ip(maskString, "mask")
    status = vmnet_network_configuration_set_ipv4_subnet(config, &subnet, &maskValue)
    guard status == .VMNET_SUCCESS else {
        throw NSError(domain: service, code: Int(status.rawValue), userInfo: [NSLocalizedDescriptionKey: "set subnet failed"])
    }

    if let reserved = string(request, "reserved_ip") {
        guard let macString = string(request, "mac") else {
            throw NSError(domain: service, code: 13, userInfo: [NSLocalizedDescriptionKey: "reserved_ip requires MAC"])
        }
        var m = try mac(macString)
        var a = try ip(reserved, "reserved_ip")
        status = vmnet_network_configuration_add_dhcp_reservation(config, &m, &a)
        guard status == .VMNET_SUCCESS else {
            throw NSError(domain: service, code: Int(status.rawValue), userInfo: [NSLocalizedDescriptionKey: "DHCP reservation failed"])
        }
    }

    if let forwards = xpc_dictionary_get_value(request, "forwards"), xpc_get_type(forwards) == XPC_TYPE_ARRAY {
        xpc_array_apply(forwards) { _, raw in
            guard let protoC = xpc_dictionary_get_string(raw, "protocol"),
                  let guestC = xpc_dictionary_get_string(raw, "guest_ip") else { return true }
            let proto = String(cString: protoC).lowercased() == "udp" ? UInt8(IPPROTO_UDP) : UInt8(IPPROTO_TCP)
            let hp = UInt16(clamping: xpc_dictionary_get_uint64(raw, "host_port"))
            let gp = UInt16(clamping: xpc_dictionary_get_uint64(raw, "guest_port"))
            var guest = in_addr()
            if inet_pton(AF_INET, guestC, &guest) == 1 {
                _ = vmnet_network_configuration_add_port_forwarding_rule(config, proto, sa_family_t(AF_INET), gp, hp, &guest)
            }
            return true
        }
    }

    guard let network = vmnet_network_create(config, &status), status == .VMNET_SUCCESS else {
        throw NSError(domain: service, code: Int(status.rawValue), userInfo: [NSLocalizedDescriptionKey: "network create failed; com.apple.vm.networking entitlement required"])
    }
    return network
}

@available(macOS 26.0, *)
func handle(_ request: xpc_object_t, peer: xpc_connection_t) {
    guard xpc_get_type(request) == XPC_TYPE_DICTIONARY, let op = string(request, "op") else { return }
    guard let reply = xpc_dictionary_create_reply(request) else { return }
    do {
        switch op {
        case "acquire":
            guard let name = string(request, "name"), !name.isEmpty, name.utf8.count <= 64 else {
                throw NSError(domain: service, code: 20, userInfo: [NSLocalizedDescriptionKey: "invalid network name"])
            }
            let fp = fingerprint(request)
            let entry: NetworkEntry
            if let existing = networks[name] {
                guard existing.fingerprint == fp else {
                    throw NSError(domain: service, code: 21, userInfo: [NSLocalizedDescriptionKey: "network name already exists with a different configuration"])
                }
                existing.refs += 1
                entry = existing
            } else {
                let created = try makeNetwork(request)
                entry = NetworkEntry(network: created, fingerprint: fp)
                networks[name] = entry
            }
            var status = vmnet_return_t.VMNET_FAILURE
            guard let serialized = vmnet_network_copy_serialization(entry.network, &status), status == .VMNET_SUCCESS else {
                throw NSError(domain: service, code: Int(status.rawValue), userInfo: [NSLocalizedDescriptionKey: "network serialization failed"])
            }
            xpc_dictionary_set_value(reply, "network", serialized)
            xpc_dictionary_set_int64(reply, "refs", Int64(entry.refs))
        case "release":
            if let name = string(request, "name"), let entry = networks[name] {
                entry.refs = max(0, entry.refs - 1)
                if entry.refs == 0 { networks.removeValue(forKey: name) }
            }
            xpc_dictionary_set_bool(reply, "ok", true)
        case "list":
            let a = xpc_array_create(nil, 0)
            for (name, entry) in networks.sorted(by: { $0.key < $1.key }) {
                let d = xpc_dictionary_create(nil, nil, 0)
                xpc_dictionary_set_string(d, "name", name)
                xpc_dictionary_set_int64(d, "refs", Int64(entry.refs))
                xpc_array_append_value(a, d)
            }
            xpc_dictionary_set_value(reply, "items", a)
        default:
            throw NSError(domain: service, code: 22, userInfo: [NSLocalizedDescriptionKey: "unknown operation \(op)"])
        }
        xpc_connection_send_message(peer, reply)
    } catch {
        replyError(request, peer, error.localizedDescription)
    }
}

guard #available(macOS 26.0, *) else {
    fputs("fluxvm-vmnetd requires macOS 26+\n", stderr)
    exit(2)
}
let listener = xpc_connection_create_mach_service(service, q, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
xpc_connection_set_event_handler(listener) { object in
    guard xpc_get_type(object) == XPC_TYPE_CONNECTION else { return }
    let peer = object as! xpc_connection_t
    xpc_connection_set_event_handler(peer) { request in handle(request, peer: peer) }
    xpc_connection_activate(peer)
}
xpc_connection_activate(listener)
dispatchMain()
