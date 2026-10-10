// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
import AppKit
import Foundation
import Dispatch
import XPC
import AccessoryAccess

private let service = "dev.zyvor.fluxvm.usbd"

@available(macOS 27.0, *)
final class USBAccessBroker: NSObject, NSApplicationDelegate, AAUSBAccessoryListener {
    private let q = DispatchQueue(label: "dev.zyvor.fluxvm.usbd")
    private var accessories: [UInt64: AAUSBAccessory] = [:]
    private var listener: xpc_connection_t?

    func applicationDidFinishLaunching(_ notification: Notification) {
        NSApp.setActivationPolicy(.accessory)
        startXPC()
        Task { await registerAccessories() }
    }

    private func registerAccessories() async {
        do {
            let existing = try await AAUSBAccessoryManager.shared.registerListener(self, matchingCriteria: [])
            q.sync { for a in existing { accessories[a.registryID] = a } }
        } catch {
            NSLog("FluxVM USB Accessory Access registration failed: %@", error.localizedDescription)
        }
    }

    func usbAccessoryDidConnect(_ usbAccessory: AAUSBAccessory) {
        q.async { self.accessories[usbAccessory.registryID] = usbAccessory }
    }

    func usbAccessoryDidDisconnect(_ usbAccessory: AAUSBAccessory) {
        q.async { self.accessories.removeValue(forKey: usbAccessory.registryID) }
    }

    private func startXPC() {
        let listener = xpc_connection_create_mach_service(service, q, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
        xpc_connection_set_event_handler(listener) { object in
            guard xpc_get_type(object) == XPC_TYPE_CONNECTION else { return }
            let peer = unsafeBitCast(object, to: xpc_connection_t.self)
            xpc_connection_set_event_handler(peer) { request in self.handle(request, peer: peer) }
            xpc_connection_activate(peer)
        }
        xpc_connection_activate(listener)
        self.listener = listener
    }

    private func handle(_ request: xpc_object_t, peer: xpc_connection_t) {
        guard xpc_get_type(request) == XPC_TYPE_DICTIONARY,
              let opRaw = xpc_dictionary_get_string(request, "op"),
              let reply = xpc_dictionary_create_reply(request) else { return }
        let op = String(cString: opRaw)
        switch op {
        case "list":
            let array = xpc_array_create(nil, 0)
            q.sync {
                for (id, accessory) in accessories.sorted(by: { $0.key < $1.key }) {
                    let d = xpc_dictionary_create(nil, nil, 0)
                    xpc_dictionary_set_string(d, "registry_id", String(id))
                    xpc_dictionary_set_string(d, "description", accessory.description)
                    xpc_array_append_value(array, d)
                }
            }
            xpc_dictionary_set_value(reply, "items", array)
        case "get":
            let id = xpc_dictionary_get_uint64(request, "registry_id")
            let accessory = q.sync { accessories[id] }
            if let accessory {
                xpc_dictionary_set_value(reply, "accessory", accessory.createXPCRepresentation())
            } else {
                xpc_dictionary_set_string(reply, "error", "accessory is not authorized/connected; attach it to FluxVM from the Accessory Access menu")
            }
        default:
            xpc_dictionary_set_string(reply, "error", "unknown operation")
        }
        xpc_connection_send_message(peer, reply)
    }
}

guard #available(macOS 27.0, *) else {
    fputs("FluxVMUSBAccess requires macOS 27+\n", stderr); exit(2)
}
let delegate = USBAccessBroker()
let app = NSApplication.shared
app.delegate = delegate
withExtendedLifetime(delegate) { app.run() }
