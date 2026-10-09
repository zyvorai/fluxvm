// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Zyvor AI Labs
//
// fluxvm-vz-runner: runs one VM on Apple's Virtualization.framework for FluxVM's `vz` backend.
// Adapted from Zyvor Velora's verified runner code (Apache-2.0). Usage:
//   fluxvm-vz-runner run     --config <json>   boot the VM and serve the control socket
//   fluxvm-vz-runner install --config <json>   install macOS from an IPSW (prints JSON progress lines)
//   fluxvm-vz-runner check   --config <json>   validate the configuration and exit
import AppKit
import Foundation
import Virtualization
import Darwin

struct Share: Decodable {
    let tag: String
    let host_path: String
    let read_only: Bool
}

struct Forward: Decodable {
    let host_port: UInt16
    let guest_port: UInt16
    let guests: Bool?
}

struct Config: Decodable {
    let id: String
    let workspace: String
    let cpus: Int
    let memory_mib: UInt64
    let guest_os: String            // "linux" | "macos"
    let disk: String
    let seed: String?
    let media: String?
    let mac: String?
    let control_socket: String
    let serial_log: String
    let vsock_socket: String?
    let ip_file: String
    let window: Bool?
    let shares: [Share]?
    let forwards: [Forward]?
    let restore_state: String?      // resume from a state file written by `save` instead of cold-booting
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("fluxvm-vz-runner: \(message)\n".utf8))
    exit(code)
}

/// Copies `from` to `to` until EOF, then half-closes `to`. Writes through `withUnsafeBytes`, because `&buf[i]` can
/// hand `write` a pointer to a one-byte temporary instead of the array's storage.
func pump(_ from: Int32, _ to: Int32) {
    DispatchQueue.global().async {
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = read(from, &buf, buf.count)
            if n <= 0 { break }
            var off = 0
            while off < n {
                let w = buf.withUnsafeBytes { write(to, $0.baseAddress! + off, n - off) }
                if w <= 0 { return }
                off += w
            }
        }
        shutdown(to, SHUT_WR)
    }
}

func emit(_ object: [String: Any]) {
    if let d = try? JSONSerialization.data(withJSONObject: object), let s = String(data: d, encoding: .utf8) { print(s); fflush(stdout) }
}

final class Runner: NSObject, VZVirtualMachineDelegate, NSWindowDelegate {
    let cfg: Config
    var vm: VZVirtualMachine?
    var state = "created"
    var installer: VZMacOSInstaller?
    var window: NSWindow?
    var ip: String?
    var signalSources: [DispatchSourceSignal] = []
    var vsockConnections: [VZVirtioSocketConnection] = []
    var lastConfiguration: VZVirtualMachineConfiguration?

    init(_ cfg: Config) { self.cfg = cfg; super.init() }

    func file(_ n: String) -> URL { URL(fileURLWithPath: cfg.workspace).appendingPathComponent(n) }

    // MARK: Configuration

    func configuration(hardware: VZMacHardwareModel? = nil, fresh: Bool = false) throws -> VZVirtualMachineConfiguration {
        let c = VZVirtualMachineConfiguration()
        c.cpuCount = max(cfg.cpus, VZVirtualMachineConfiguration.minimumAllowedCPUCount)
        c.memorySize = max(cfg.memory_mib * 1_048_576, VZVirtualMachineConfiguration.minimumAllowedMemorySize)
        func err(_ m: String) -> NSError { NSError(domain: "fluxvm-vz", code: 1, userInfo: [NSLocalizedDescriptionKey: m]) }

        if cfg.guest_os == "macos" {
            let model: VZMacHardwareModel
            if let hardware { model = hardware }
            else {
                guard let m = VZMacHardwareModel(dataRepresentation: try Data(contentsOf: file("hardware.bin"))) else { throw err("invalid Apple hardware model") }
                model = m
            }
            guard model.isSupported else { throw err("this Mac cannot run that macOS image") }
            let p = VZMacPlatformConfiguration()
            p.hardwareModel = model
            if fresh {
                let id = VZMacMachineIdentifier()
                try id.dataRepresentation.write(to: file("identity.bin"), options: .atomic)
                try model.dataRepresentation.write(to: file("hardware.bin"), options: .atomic)
                p.machineIdentifier = id
                p.auxiliaryStorage = try VZMacAuxiliaryStorage(creatingStorageAt: file("auxiliary.bin"), hardwareModel: model, options: .allowOverwrite)
            } else {
                guard let id = VZMacMachineIdentifier(dataRepresentation: try Data(contentsOf: file("identity.bin"))) else { throw err("invalid Apple machine identifier") }
                p.machineIdentifier = id
                p.auxiliaryStorage = VZMacAuxiliaryStorage(contentsOf: file("auxiliary.bin"))
            }
            c.platform = p
            c.bootLoader = VZMacOSBootLoader()
            let g = VZMacGraphicsDeviceConfiguration()
            g.displays = [VZMacGraphicsDisplayConfiguration(widthInPixels: 2560, heightInPixels: 1600, pixelsPerInch: 220)]
            c.graphicsDevices = [g]
            c.keyboards = [VZMacKeyboardConfiguration()]
            c.pointingDevices = [VZMacTrackpadConfiguration()]
        } else {
            let boot = VZEFIBootLoader()
            boot.variableStore = FileManager.default.fileExists(atPath: file("efi.bin").path)
                ? VZEFIVariableStore(url: file("efi.bin"))
                : try VZEFIVariableStore(creatingVariableStoreAt: file("efi.bin"))
            c.bootLoader = boot
            // A saved VM state is tied to the machine identifier, and a generic platform invents a new one on every
            // launch, so keep one per VM or a restore fails with "invalid argument".
            let platform = VZGenericPlatformConfiguration()
            let idFile = file("generic-id.bin")
            if let data = try? Data(contentsOf: idFile), let id = VZGenericMachineIdentifier(dataRepresentation: data) {
                platform.machineIdentifier = id
            } else {
                try platform.machineIdentifier.dataRepresentation.write(to: idFile, options: .atomic)
            }
            c.platform = platform
            let g = VZVirtioGraphicsDeviceConfiguration()
            g.scanouts = [VZVirtioGraphicsScanoutConfiguration(widthInPixels: 1280, heightInPixels: 800)]
            c.graphicsDevices = [g]
            c.keyboards = [VZUSBKeyboardConfiguration()]
            c.pointingDevices = [VZUSBScreenCoordinatePointingDeviceConfiguration()]
            // Guest serial console (hvc0) goes to the VM log, which FluxVM serves as /v1/vms/{id}/serial.
            FileManager.default.createFile(atPath: cfg.serial_log, contents: nil, attributes: nil)
            if let h = FileHandle(forWritingAtPath: cfg.serial_log) {
                try? h.seekToEnd()
                let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
                serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: nil, fileHandleForWriting: h)
                c.serialPorts = [serial]
            }
            c.socketDevices = [VZVirtioSocketDeviceConfiguration()]   // vsock, used by the guest agent proxy
        }

        var storage: [VZStorageDeviceConfiguration] = [
            VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: cfg.disk), readOnly: false))
        ]
        if cfg.guest_os == "linux" {
            if let seed = cfg.seed, FileManager.default.fileExists(atPath: seed) {
                storage.append(VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: seed), readOnly: true)))
            }
            if let media = cfg.media, !media.isEmpty {
                storage.append(VZUSBMassStorageDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: media), readOnly: true)))
            }
        }
        c.storageDevices = storage

        let net = VZVirtioNetworkDeviceConfiguration()
        net.attachment = VZNATNetworkDeviceAttachment()
        if let m = cfg.mac, let mac = VZMACAddress(string: m) { net.macAddress = mac }
        c.networkDevices = [net]
        if cfg.guest_os == "linux" {
            var fsDevices: [VZDirectorySharingDeviceConfiguration] = []
            for share in cfg.shares ?? [] {
                var isDir: ObjCBool = false
                guard FileManager.default.fileExists(atPath: share.host_path, isDirectory: &isDir), isDir.boolValue else {
                    throw err("shared folder \(share.host_path) is not a directory")
                }
                try VZVirtioFileSystemDeviceConfiguration.validateTag(share.tag)
                let fs = VZVirtioFileSystemDeviceConfiguration(tag: share.tag)
                fs.share = VZSingleDirectoryShare(directory: VZSharedDirectory(url: URL(fileURLWithPath: share.host_path), readOnly: share.read_only))
                fsDevices.append(fs)
            }
            c.directorySharingDevices = fsDevices
        }
        c.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        c.memoryBalloonDevices = [VZVirtioTraditionalMemoryBalloonDeviceConfiguration()]
        try c.validate()
        lastConfiguration = c
        return c
    }

    // MARK: Lifecycle

    func boot() {
        do {
            let machine = VZVirtualMachine(configuration: try configuration())
            machine.delegate = self
            vm = machine
            state = "starting"
            if cfg.window == true { showWindow(machine) }
            if let state = cfg.restore_state, cfg.guest_os == "linux" {
                // Same configuration as when the state was saved; the machine comes back paused and is then resumed.
                guard #available(macOS 14.0, *) else { fail("restoring a saved state needs macOS 14 or later") }
                machine.restoreMachineStateFrom(url: URL(fileURLWithPath: state)) { error in
                    if let error { fail("restore failed: \(error.localizedDescription)") }
                    machine.resume { result in
                        switch result {
                        case .success: self.state = "running"; emit(["event": "running", "restored": true])
                        case .failure(let e): fail("resume after restore failed: \(e.localizedDescription)")
                        }
                    }
                }
            } else {
                machine.start { result in
                    switch result {
                    case .success: self.state = "running"; emit(["event": "running"])
                    case .failure(let e): fail("start failed: \(e.localizedDescription)")
                    }
                }
            }
            startControlServer()
            startIPWatcher()
            if cfg.vsock_socket != nil { startVsockProxy() }
            for f in cfg.forwards ?? [] where f.guests != true { startForward(f, bind: "127.0.0.1", fatal: true) }
            setupSignals()
        } catch { fail(error.localizedDescription) }
    }

    func showWindow(_ machine: VZVirtualMachine) {
        let view = VZVirtualMachineView(frame: NSRect(x: 0, y: 0, width: 1100, height: 700))
        view.virtualMachine = machine
        view.capturesSystemKeys = true
        view.automaticallyReconfiguresDisplay = true
        let w = NSWindow(contentRect: view.frame, styleMask: [.titled, .closable, .miniaturizable, .resizable], backing: .buffered, defer: false)
        w.title = "FluxVM · \(cfg.id.prefix(8))"
        w.contentView = view
        w.delegate = self
        w.center(); w.makeKeyAndOrderFront(nil)
        window = w
        NSApp.setActivationPolicy(.regular)
        NSApp.activate(ignoringOtherApps: true)
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool { sender.miniaturize(nil); return false }

    func install() {
        guard cfg.guest_os == "macos", let media = cfg.media else { fail("install needs guest_os macos and an IPSW in media") }
        emit(["event": "loading", "image": media])
        VZMacOSRestoreImage.load(from: URL(fileURLWithPath: media)) { result in
            DispatchQueue.main.async {
                switch result {
                case .failure(let e): fail("could not load the restore image: \(e.localizedDescription)")
                case .success(let image):
                    guard let req = image.mostFeaturefulSupportedConfiguration else { fail("this IPSW is not supported on this Mac") }
                    guard self.cfg.cpus >= req.minimumSupportedCPUCount, self.cfg.memory_mib * 1_048_576 >= req.minimumSupportedMemorySize else {
                        fail("the image needs at least \(req.minimumSupportedCPUCount) CPUs and \(req.minimumSupportedMemorySize / 1_048_576) MiB")
                    }
                    do {
                        let machine = VZVirtualMachine(configuration: try self.configuration(hardware: req.hardwareModel, fresh: true))
                        self.vm = machine
                        let inst = VZMacOSInstaller(virtualMachine: machine, restoringFromImageAt: URL(fileURLWithPath: media))
                        self.installer = inst
                        let obs = inst.progress.observe(\.fractionCompleted, options: [.new]) { p, _ in emit(["event": "progress", "fraction": p.fractionCompleted]) }
                        _ = obs
                        inst.install { r in
                            switch r {
                            case .success: emit(["event": "installed"]); exit(0)
                            case .failure(let e): fail("install failed: \(e.localizedDescription)")
                            }
                        }
                        withExtendedLifetime(obs) {}
                        self.installObservation = obs
                    } catch { fail(error.localizedDescription) }
                }
            }
        }
    }
    var installObservation: NSKeyValueObservation?

    func guestDidStop(_ virtualMachine: VZVirtualMachine) { state = "stopped"; emit(["event": "stopped"]); cleanupAndExit(0) }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) { state = "error"; fail("guest stopped with an error: \(error.localizedDescription)") }

    func cleanupAndExit(_ code: Int32) {
        unlink(cfg.control_socket)
        if let v = cfg.vsock_socket { unlink(v) }
        exit(code)
    }

    func setupSignals() {
        for s in [SIGTERM, SIGINT] {
            Darwin.signal(s, SIG_IGN)
            let src = DispatchSource.makeSignalSource(signal: s, queue: .main)
            src.setEventHandler { [weak self] in
                guard let self, let vm = self.vm else { exit(0) }
                // A forced stop: the host asked the runner to go away.
                vm.stop { _ in self.state = "stopped"; self.cleanupAndExit(0) }
            }
            src.resume()
            signalSources.append(src)
        }
    }

    // MARK: Control socket (one JSON line in, one JSON line out)

    func startControlServer() {
        unlink(cfg.control_socket)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { fail("control socket: \(String(cString: strerror(errno)))") }
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        let path = cfg.control_socket
        guard path.utf8.count < MemoryLayout.size(ofValue: addr.sun_path) else { fail("control socket path is too long: \(path)") }
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in path.withCString { _ = strncpy(buf.baseAddress!.assumingMemoryBound(to: CChar.self), $0, buf.count - 1) } }
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard ok == 0, listen(fd, 8) == 0 else { fail("control socket: \(String(cString: strerror(errno)))") }
        chmod(path, 0o600)
        DispatchQueue.global().async {
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { continue }
                DispatchQueue.global().async { self.serve(c) }
            }
        }
    }

    func serve(_ c: Int32) {
        defer { close(c) }
        var buf = [UInt8](repeating: 0, count: 4096)
        let n = read(c, &buf, buf.count)
        guard n > 0, let line = String(bytes: buf[0..<n], encoding: .utf8),
              let o = (try? JSONSerialization.jsonObject(with: Data(line.utf8))) as? [String: Any], let cmd = o["cmd"] as? String else { reply(c, ["ok": false, "error": "bad request"]); return }
        let sem = DispatchSemaphore(value: 0)
        var response: [String: Any] = ["ok": false, "error": "unknown command"]
        DispatchQueue.main.async {
            switch cmd {
            case "ping": response = ["ok": true]; sem.signal()
            case "status": response = ["ok": true, "state": self.state, "ip": self.ip as Any? ?? NSNull()]; sem.signal()
            case "pause": self.vm?.pause { r in response = self.result(r, "paused", set: { self.state = "paused" }); sem.signal() }
            case "resume": self.vm?.resume { r in response = self.result(r, "running", set: { self.state = "running" }); sem.signal() }
            case "save":
                // Pauses the guest and writes its memory and device state to `path`. The guest stays paused so the
                // host can clone the disk at the same instant; `resume` continues it.
                guard let path = o["path"] as? String, let vm = self.vm else { response = ["ok": false, "error": "save needs a path and a running guest"]; sem.signal(); break }
                guard #available(macOS 14.0, *) else { response = ["ok": false, "error": "saving a VM needs macOS 14 or later"]; sem.signal(); break }
                do { try self.lastConfiguration?.validateSaveRestoreSupport() } catch {
                    response = ["ok": false, "error": "this VM's devices cannot be saved: \(error.localizedDescription)"]; sem.signal(); break
                }
                let wasRunning = self.state == "running"
                let write = {
                    vm.saveMachineStateTo(url: URL(fileURLWithPath: path)) { error in
                        if let error { response = ["ok": false, "error": error.localizedDescription] }
                        else { self.state = "paused"; response = ["ok": true, "state": "paused", "was_running": wasRunning] }
                        sem.signal()
                    }
                }
                if wasRunning {
                    vm.pause { r in
                        switch r {
                        case .success: write()
                        case .failure(let e): response = ["ok": false, "error": e.localizedDescription]; sem.signal()
                        }
                    }
                } else { write() }
            case "shutdown":
                do { try self.vm?.requestStop(); response = ["ok": true, "state": "stopping"] } catch { response = ["ok": false, "error": error.localizedDescription] }
                sem.signal()
            case "stop": response = ["ok": true]; sem.signal(); self.vm?.stop { _ in self.cleanupAndExit(0) }
            default: sem.signal()
            }
        }
        _ = sem.wait(timeout: .now() + 120)
        reply(c, response)
    }

    func result(_ r: Result<Void, Error>, _ state: String, set: () -> Void) -> [String: Any] {
        switch r { case .success: set(); return ["ok": true, "state": state]; case .failure(let e): return ["ok": false, "error": e.localizedDescription] }
    }

    func reply(_ c: Int32, _ o: [String: Any]) {
        if var d = try? JSONSerialization.data(withJSONObject: o) { d.append(10); _ = d.withUnsafeBytes { write(c, $0.baseAddress, d.count) } }
    }

    // MARK: Guest address (reported by the guest on its serial console)

    func startIPWatcher() {
        // Only look at serial output written by *this* boot; earlier runs append to the same log.
        let bootOffset = ((try? FileManager.default.attributesOfItem(atPath: cfg.serial_log)[.size]) as? UInt64) ?? 0
        if cfg.restore_state != nil {
            // A restored guest does not print its address again; the address it had when saved is still in the file.
            ip = (try? String(contentsOfFile: cfg.ip_file, encoding: .utf8))?.trimmingCharacters(in: .whitespacesAndNewlines)
        } else {
            try? FileManager.default.removeItem(atPath: cfg.ip_file)
        }
        if let known = ip, !known.isEmpty { startGuestForwards(guestIP: known) }
        let timer = DispatchSource.makeTimerSource(queue: .global())
        timer.schedule(deadline: .now() + 1, repeating: 1)
        timer.setEventHandler { [weak self] in
            guard let self, let h = FileHandle(forReadingAtPath: self.cfg.serial_log) else { return }
            defer { try? h.close() }
            let size = (try? h.seekToEnd()) ?? 0
            try? h.seek(toOffset: max(bootOffset, size > 16384 ? size - 16384 : 0))
            guard let text = (try? h.readToEnd()).flatMap({ String(data: $0, encoding: .utf8) }),
                  let re = try? NSRegularExpression(pattern: #"VELORA-IP (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"#),
                  let m = re.matches(in: text, range: NSRange(text.startIndex..., in: text)).last, let r = Range(m.range(at: 1), in: text) else { return }
            let found = String(text[r])
            if found != self.ip { self.ip = found; try? found.write(toFile: self.cfg.ip_file, atomically: true, encoding: .utf8) }
            self.startGuestForwards(guestIP: found)
        }
        timer.resume()
        ipTimer = timer
    }
    var ipTimer: DispatchSourceTimer?

    // MARK: TCP port forwards (127.0.0.1:host_port -> guest NAT address:guest_port)

    func startForward(_ f: Forward, bind address: String, fatal: Bool) {
        func problem(_ what: String) {
            let message = "port forward \(address):\(f.host_port): \(what)"
            if fatal { fail(message) } else { emit(["event": "forward-error", "message": message]) }
        }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { problem(String(cString: strerror(errno))); return }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = f.host_port.bigEndian
        addr.sin_addr.s_addr = inet_addr(address)
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard ok == 0, listen(fd, 32) == 0 else { problem(String(cString: strerror(errno))); close(fd); return }
        DispatchQueue.global().async {
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { continue }
                DispatchQueue.global().async { self.relay(c, to: f.guest_port) }
            }
        }
    }

    // Ports other guests may use. Guests on Virtualization.framework's NAT cannot reach each other, but all of them
    // reach the Mac at the NAT gateway (the guest's /24, address .1), so each such port is listened on there and
    // relayed to this guest. Bound to that address only, so nothing is exposed to the LAN.
    var guestForwardsStarted = false
    func startGuestForwards(guestIP: String) {
        guard !guestForwardsStarted else { return }
        let octets = guestIP.split(separator: ".")
        guard octets.count == 4 else { return }
        guestForwardsStarted = true
        let gateway = octets[0..<3].joined(separator: ".") + ".1"
        for f in cfg.forwards ?? [] where f.guests == true { startForward(f, bind: gateway, fatal: false) }
    }

    func relay(_ c: Int32, to port: UInt16) {
        // The guest address is learned from its serial console, so it can appear after the listener is up.
        guard let ip = self.ip else { close(c); return }
        let g = socket(AF_INET, SOCK_STREAM, 0)
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr(ip)
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(g, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard g >= 0, ok == 0 else { if g >= 0 { close(g) }; close(c); return }
        pump(c, g); pump(g, c)
    }

    // MARK: vsock proxy ("CONNECT <port>\n" over a unix socket, like Firecracker's)

    func startVsockProxy() {
        guard let path = cfg.vsock_socket else { return }
        unlink(path)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un(); addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { buf in path.withCString { _ = strncpy(buf.baseAddress!.assumingMemoryBound(to: CChar.self), $0, buf.count - 1) } }
        let ok = withUnsafePointer(to: &addr) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard ok == 0, listen(fd, 16) == 0 else { return }
        chmod(path, 0o600)
        DispatchQueue.global().async {
            while true {
                let c = accept(fd, nil, nil)
                if c < 0 { continue }
                DispatchQueue.global().async { self.proxy(c) }
            }
        }
    }

    func proxy(_ c: Int32) {
        var line = Data()
        var byte: UInt8 = 0
        while read(c, &byte, 1) == 1 { if byte == 10 { break }; line.append(byte); if line.count > 64 { close(c); return } }
        let parts = (String(data: line, encoding: .utf8) ?? "").split(separator: " ")
        guard parts.count == 2, parts[0] == "CONNECT", let port = UInt32(parts[1]) else { close(c); return }
        DispatchQueue.main.async {
            guard let device = self.vm?.socketDevices.first as? VZVirtioSocketDevice else { close(c); return }
            device.connect(toPort: port) { result in
                switch result {
                case .failure: close(c)
                case .success(let conn):
                    self.vsockConnections.append(conn)
                    let g = conn.fileDescriptor
                    _ = "OK \(port)\n".withCString { write(c, $0, strlen($0)) }
                    pump(c, g); pump(g, c)
                }
            }
        }
    }
}

// MARK: Entry point

let args = CommandLine.arguments
guard args.count == 4, ["run", "install", "check"].contains(args[1]), args[2] == "--config" else {
    fail("usage: fluxvm-vz-runner run|install|check --config <json>", code: 2)
}
guard let data = FileManager.default.contents(atPath: args[3]), let cfg = try? JSONDecoder().decode(Config.self, from: data) else { fail("cannot read config \(args[3])", code: 2) }
let runner = Runner(cfg)
if args[1] == "check" {
    do { _ = try runner.configuration(); print("configuration valid"); exit(0) } catch { fail(error.localizedDescription) }
}
let app = NSApplication.shared
app.setActivationPolicy(.prohibited)
DispatchQueue.main.async { args[1] == "install" ? runner.install() : runner.boot() }
withExtendedLifetime(runner) { app.run() }
