// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
#if os(macOS)
import Foundation
import Virtualization
import XPC
#if canImport(AccessoryAccess)
import AccessoryAccess
#endif

private let fluxUSBService = "dev.zyvor.fluxvm.usbd"

#if compiler(>=6.4)
/// Reports a passthrough device the host took back (unplugged, or released from the Accessory Access menu).
@available(macOS 27.0, *)
final class FluxUSBControllerObserver: NSObject, VZUSBController.Delegate {
    func usbController(_ usbController: VZUSBController,
                       usbPassthroughDeviceDidDisconnect device: VZUSBPassthroughDevice) {
        emit(["event": "usb-passthrough-disconnected", "uuid": device.uuid.uuidString])
    }
}
#endif

extension Runner {
    /// Watches every USB controller for passthrough devices the framework detached on its own.
    func observeUSBControllers(_ machine: VZVirtualMachine) {
        #if compiler(>=6.4)
        guard #available(macOS 27.0, *), !machine.usbControllers.isEmpty else { return }
        let observer = FluxUSBControllerObserver()
        for c in machine.usbControllers { c.delegate = observer }
        usbObserver = observer
        #endif
    }

    /// `usb-list`: the devices attached to the VM's USB controllers right now.
    func listUSB() -> [String: Any] {
        guard #available(macOS 15.0, *), let vm else { return ["ok": true, "items": []] }
        var items: [[String: Any]] = []
        for c in vm.usbControllers {
            for d in c.usbDevices {
                var kind = "mass-storage"
                #if compiler(>=6.4)
                if #available(macOS 27.0, *), d is VZUSBPassthroughDevice { kind = "passthrough" }
                #endif
                items.append(["uuid": d.uuid.uuidString, "kind": kind,
                              "hotplugged": kind == "passthrough" || hotplugUSB.contains(d.uuid)])
            }
        }
        return ["ok": true, "items": items]
    }

    func listPhysicalUSB(completion: @escaping ([String: Any]) -> Void) {
        #if compiler(>=6.4)
        guard #available(macOS 27.0, *) else {
            completion(["ok": false, "error": "physical USB passthrough needs macOS 27+"])
            return
        }
        do {
            let reply = try usbBrokerRequest(op: "list", registryID: nil)
            guard let array = xpc_dictionary_get_value(reply, "items"), xpc_get_type(array) == XPC_TYPE_ARRAY else {
                completion(["ok": false, "error": "USB broker returned no item list"]); return
            }
            var items: [[String: Any]] = []
            xpc_array_apply(array) { _, item in
                if let rid = xpc_dictionary_get_string(item, "registry_id") {
                    var d: [String: Any] = ["registry_id": String(cString: rid)]
                    if let s = xpc_dictionary_get_string(item, "description") { d["description"] = String(cString: s) }
                    items.append(d)
                }
                return true
            }
            completion(["ok": true, "items": items])
        } catch { completion(["ok": false, "error": error.localizedDescription]) }
        #else
        completion(["ok": false, "error": "physical USB passthrough needs a runner built with the macOS 27 SDK"])
        #endif
    }

    func attachPhysicalUSB(registryID: UInt64, completion: @escaping ([String: Any]) -> Void) {
        #if compiler(>=6.4)
        guard #available(macOS 27.0, *) else {
            completion(["ok": false, "error": "physical USB passthrough needs macOS 27+"])
            return
        }
        #if canImport(AccessoryAccess)
        guard let controller = vm?.usbControllers.first else {
            completion(["ok": false, "error": "no XHCI controller; set apple.usb_controller=true"]); return
        }
        do {
            let reply = try usbBrokerRequest(op: "get", registryID: registryID)
            if let e = xpc_dictionary_get_string(reply, "error") {
                completion(["ok": false, "error": String(cString: e)]); return
            }
            guard let rep = xpc_dictionary_get_value(reply, "accessory"),
                  let accessory = AAUSBAccessory(xpcRepresentation: rep) else {
                completion(["ok": false, "error": "USB broker returned an invalid accessory representation"]); return
            }
            let config = VZUSBPassthroughDeviceConfiguration(device: accessory)
            let device = try VZUSBPassthroughDevice(configuration: config)
            controller.attach(device: device) { error in
                if let error { completion(["ok": false, "error": error.localizedDescription]) }
                else { completion(["ok": true, "uuid": device.uuid.uuidString, "registry_id": String(registryID)]) }
            }
        } catch { completion(["ok": false, "error": error.localizedDescription]) }
        #else
        completion(["ok": false, "error": "runner was built without AccessoryAccess"])
        #endif
        #else
        completion(["ok": false, "error": "physical USB passthrough needs a runner built with the macOS 27 SDK"])
        #endif
    }

    @available(macOS 27.0, *)
    private func usbBrokerRequest(op: String, registryID: UInt64?) throws -> xpc_object_t {
        let connection = xpc_connection_create_mach_service(fluxUSBService, nil, 0)
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_activate(connection)
        defer { xpc_connection_cancel(connection) }
        let msg = xpc_dictionary_create(nil, nil, 0)
        xpc_dictionary_set_string(msg, "op", op)
        if let registryID { xpc_dictionary_set_uint64(msg, "registry_id", registryID) }
        let sem = DispatchSemaphore(value: 0)
        var answer: xpc_object_t?
        xpc_connection_send_message_with_reply(connection, msg, DispatchQueue.global()) { reply in
            answer = reply; sem.signal()
        }
        guard sem.wait(timeout: .now() + 5) == .success, let answer else {
            throw NSError(domain: "fluxvm.usb", code: 60,
                          userInfo: [NSLocalizedDescriptionKey: "USB Accessory Access broker timed out"])
        }
        guard xpc_get_type(answer) != XPC_TYPE_ERROR else {
            throw NSError(domain: "fluxvm.usb", code: 61,
                          userInfo: [NSLocalizedDescriptionKey: "USB Accessory Access broker is unavailable"])
        }
        return answer
    }
}
#endif
