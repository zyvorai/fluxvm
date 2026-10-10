// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
import Foundation
import Virtualization
#if canImport(DiskImageKit)
import DiskImageKit
#endif

extension Runner {
    func modernError(_ s: String) -> NSError {
        NSError(domain: "fluxvm-vz", code: 2, userInfo: [NSLocalizedDescriptionKey: s])
    }

    func macDisplays() -> [VZMacGraphicsDisplayConfiguration] {
        let count = max(1, min(cfg.display_count ?? 1, 8))
        return (0..<count).map { _ in
            VZMacGraphicsDisplayConfiguration(widthInPixels: cfg.display_width ?? 2560,
                heightInPixels: cfg.display_height ?? 1600, pixelsPerInch: cfg.display_ppi ?? 220)
        }
    }

    func networkAttachment() throws -> VZNetworkDeviceAttachment {
        if let spec = cfg.vmnet {
            guard #available(macOS 26.0, *) else {
                throw modernError("apple.vmnet needs macOS 26 or later (this host is older)")
            }
            return try FluxVMNetNetwork(spec: spec, macAddress: cfg.mac).attachment()
        }
        guard let name = cfg.bridge_interface, !name.isEmpty else { return VZNATNetworkDeviceAttachment() }
        guard let iface = VZBridgedNetworkInterface.networkInterfaces.first(where: { $0.identifier == name }) else {
            throw modernError("bridge interface \(name) not found; available: " +
                VZBridgedNetworkInterface.networkInterfaces.map { $0.identifier }.joined(separator: ", "))
        }
        return VZBridgedNetworkDeviceAttachment(interface: iface)
    }

    func configureClipboard(_ c: VZVirtualMachineConfiguration) throws {
        guard cfg.clipboard == true else { return }
        guard cfg.guest_os == "linux" else { throw modernError("SPICE clipboard is Linux-only") }
        let a = VZSpiceAgentPortAttachment(); a.sharesClipboard = true
        let p = VZVirtioConsolePortConfiguration(); p.name = VZSpiceAgentPortAttachment.spiceAgentPortName
        p.attachment = a; p.isConsole = false
        let d = VZVirtioConsoleDeviceConfiguration(); d.ports[0] = p
        c.consoleDevices.append(d)
    }

    func rootStorageAttachment() throws -> VZStorageDeviceAttachment {
        let u = URL(fileURLWithPath: cfg.disk)
        guard cfg.asif_overlay == true else { return try VZDiskImageStorageDeviceAttachment(url: u, readOnly: false) }
        #if canImport(DiskImageKit)
        if #available(macOS 27.0, *) {
            let base = try DiskImage(opening: .open(url: u, mode: .readOnly))
            let ov = file("disk-overlay.asif")
            if FileManager.default.fileExists(atPath: ov.path) {
                let overlay = try DiskImage(opening: .open(url: ov))
                return try VZDiskImageStorageDeviceAttachment(diskImage: try base.appending(overlay))
            }
            return try VZDiskImageStorageDeviceAttachment(diskImage: try base.appending(.asifLayer(url: ov, type: .overlay)))
        }
        #endif
        throw modernError("ASIF overlay needs macOS 27+ with DiskImageKit")
    }

    func startMachine(_ machine: VZVirtualMachine) {
        guard cfg.guest_os == "macos", let user = cfg.provision_username,
              let full = cfg.provision_full_name, let pwFile = cfg.provision_password_file else {
            machine.start { r in
                switch r { case .success: self.state = "running"; emit(["event":"running"])
                case .failure(let e): fail("start failed: \(e.localizedDescription)") }
            }
            return
        }
        #if compiler(>=6.3)
        if #available(macOS 27.0, *) {
            do {
                let pw = try String(contentsOfFile: pwFile, encoding: .utf8).trimmingCharacters(in: .newlines)
                guard !pw.isEmpty else { fail("provision password file is empty") }
                let p = VZMacGuestProvisioningOptions(); p.fullName = full; p.username = user; p.password = pw
                p.logsInAutomatically = cfg.provision_auto_login == true
                p.enablesRemoteLogin = cfg.provision_remote_login == true
                let o = VZMacOSVirtualMachineStartOptions(); try o.setGuestProvisioning(p)
                try? FileManager.default.removeItem(atPath: pwFile)
                machine.start(options: o) { e in
                    if let e { fail("provisioned start failed: \(e.localizedDescription)") }
                    self.state = "running"; emit(["event":"running","provisioned":true])
                }
                return
            } catch { fail("macOS provisioning: \(error.localizedDescription)") }
        }
        #endif
        fail("automated macOS provisioning needs macOS 27/current SDK")
    }

    func balloonControl(reclaimMiB: UInt64?) -> [String: Any] {
        guard let d = vm?.memoryBalloonDevices.first as? VZVirtioTraditionalMemoryBalloonDevice else {
            return ["ok":false,"error":"no VZ memory balloon device"]
        }
        let configured = cfg.memory_mib
        if let r = reclaimMiB {
            let floor = VZVirtualMachineConfiguration.minimumAllowedMemorySize / 1_048_576
            d.targetVirtualMachineMemorySize = max(floor, configured - min(r, configured)) * 1_048_576
        }
        let available = d.targetVirtualMachineMemorySize / 1_048_576
        let reclaimed = configured > available ? configured - available : 0
        return ["ok":true,"memory_mib":configured,"target_mib":reclaimed,"actual_mib":reclaimed]
    }

    func attachUSBMassStorage(path: String, readOnly: Bool, completion: @escaping ([String: Any])->Void) {
        guard #available(macOS 15.0, *) else { completion(["ok":false,"error":"USB hotplug needs macOS 15+"]); return }
        guard let c = vm?.usbControllers.first else { completion(["ok":false,"error":"no XHCI controller; set apple.usb_controller=true"]); return }
        do {
            let a = try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: path), readOnly: readOnly)
            let d = VZUSBMassStorageDevice(configuration: VZUSBMassStorageDeviceConfiguration(attachment: a))
            c.attach(device: d) { e in e == nil ? completion(["ok":true,"uuid":d.uuid.uuidString]) : completion(["ok":false,"error":e!.localizedDescription]) }
        } catch { completion(["ok":false,"error":error.localizedDescription]) }
    }

    func detachUSB(uuid: String, completion: @escaping ([String: Any])->Void) {
        guard #available(macOS 15.0, *) else { completion(["ok":false,"error":"USB hotplug needs macOS 15+"]); return }
        guard let u = UUID(uuidString: uuid), let c = vm?.usbControllers.first,
              let d = c.usbDevices.first(where: { $0.uuid == u }) else { completion(["ok":false,"error":"USB device not attached"]); return }
        c.detach(device: d) { e in e == nil ? completion(["ok":true,"uuid":uuid]) : completion(["ok":false,"error":e!.localizedDescription]) }
    }
}
