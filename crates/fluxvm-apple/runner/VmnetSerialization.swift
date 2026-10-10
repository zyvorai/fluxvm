// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Supported bridge between FluxVM's one-runner-per-VM architecture and a
// future XPC vmnet broker. The XPC object must stay an XPC object; never turn
// the serialization into JSON or opaque bytes.
#if os(macOS) && canImport(vmnet)
import Foundation
import vmnet
import XPC

@available(macOS 26.0, *)
func fluxVmnetCopySerialization(_ network: vmnet_network_ref) throws -> xpc_object_t {
    var status = vmnet_return_t.VMNET_FAILURE
    guard let object = vmnet_network_copy_serialization(network, &status),
          status == .VMNET_SUCCESS else {
        throw NSError(domain: "fluxvm.vmnet", code: Int(status.rawValue),
                      userInfo: [NSLocalizedDescriptionKey: "vmnet network serialization failed (\(status.rawValue))"])
    }
    return object
}

@available(macOS 26.0, *)
func fluxVmnetCreateFromSerialization(_ object: xpc_object_t) throws -> vmnet_network_ref {
    var status = vmnet_return_t.VMNET_FAILURE
    guard let network = vmnet_network_create_with_serialization(object, &status),
          status == .VMNET_SUCCESS else {
        throw NSError(domain: "fluxvm.vmnet", code: Int(status.rawValue),
                      userInfo: [NSLocalizedDescriptionKey: "vmnet network import failed (\(status.rawValue))"])
    }
    return network
}
#endif
