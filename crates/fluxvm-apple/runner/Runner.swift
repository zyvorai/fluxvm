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
    let display_count: Int?
    let clipboard: Bool?
    let bridge_interface: String?
    let asif_overlay: Bool?
    let provision_full_name: String?
    let provision_username: String?
    let provision_password_file: String?
    let provision_auto_login: Bool?
    let provision_remote_login: Bool?
    let display_width: Int?
    let display_height: Int?
    let display_ppi: Int?
    let audio_output: Bool?
    let microphone: Bool?
    let rosetta: Bool?
    let nested_virtualization: Bool?
    let usb_controller: Bool?
    let vmnet: FluxVMNetSpec?       // macOS 26+ per-VM vmnet network (nil: NAT or bridge)
    let custom_virtio: Bool?        // macOS 27+ custom Virtio device hook (Linux guests)
    let shares: [Share]?
    let forwards: [Forward]?
    let network_none: Bool?         // attach no network device at all
    let egress_allow: [String]?     // hosts the guest may reach through the vsock proxy on port 3128 (nil/empty: no proxy)
    let restore_state: String?      // resume from a state file written by `save` instead of cold-booting
    let kernel: String?             // direct boot (VZLinuxBootLoader): uncompressed arm64 Image; nil boots EFI from the disk
    let initrd: String?
    let cmdline: String?
    let root_read_only: Bool?
    let extra_disks: [ExtraDisk]?
    let networks: [PrivateNetwork]?
}

struct PrivateNetwork: Decodable {
    let name: String
    let mac: String
    let socket: String
    let switch_bin: String
}

/// One card on a private network: the guest's end of a datagram socketpair goes to Virtualization, the other end is
/// handed to the network's `fluxvm-vz-switch` over its Unix socket (SCM_RIGHTS). The runner keeps its copy, so when the
/// switch goes away it reconnects (restarting the switch) and hands the same socket over again.
final class PrivateLink {
    let net: PrivateNetwork
    let vmID: String
    let switchEnd: Int32
    let attachment: VZFileHandleNetworkDeviceAttachment

    init(_ net: PrivateNetwork, vmID: String) throws {
        self.net = net
        self.vmID = vmID
        var fds: [Int32] = [0, 0]
        guard socketpair(AF_UNIX, SOCK_DGRAM, 0, &fds) == 0 else {
            throw NSError(domain: "fluxvm-vz", code: 1, userInfo: [NSLocalizedDescriptionKey: "socketpair: \(String(cString: strerror(errno)))"])
        }
        // Apple's guidance for file-handle networking: a receive buffer several times the send buffer.
        for fd in fds {
            var snd: Int32 = 1 << 20, rcv: Int32 = 4 << 20
            setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &snd, socklen_t(MemoryLayout<Int32>.size))
            setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcv, socklen_t(MemoryLayout<Int32>.size))
        }
        switchEnd = fds[1]
        attachment = VZFileHandleNetworkDeviceAttachment(fileHandle: FileHandle(fileDescriptor: fds[0], closeOnDealloc: true))
    }

    func start() {
        let t = Thread { [self] in
            var delay: UInt32 = 0
            while true {
                if delay > 0 { sleep(delay) }
                delay = min(max(delay * 2, 1), 10)
                guard let s = self.connect() else { continue }
                delay = 0
                FileHandle.standardError.write(Data("fluxvm-vz-runner: joined network \(self.net.name)\n".utf8))
                // The switch holds the port while this stream is open; EOF means it went away.
                var b: UInt8 = 0
                while read(s, &b, 1) > 0 {}
                close(s)
                FileHandle.standardError.write(Data("fluxvm-vz-runner: lost the switch for network \(self.net.name); reconnecting\n".utf8))
                delay = 1
            }
        }
        t.start()
    }

    private func dial() -> Int32? {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        if s < 0 { return nil }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let path = Array(net.socket.utf8)
        guard path.count < MemoryLayout.size(ofValue: addr.sun_path) else { close(s); return nil }
        withUnsafeMutableBytes(of: &addr.sun_path) { p in
            for (i, b) in path.enumerated() { p[i] = b }
            p[path.count] = 0
        }
        let ok = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(s, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if ok != 0 { close(s); return nil }
        return s
    }

    private func connect() -> Int32? {
        var s = dial()
        if s == nil {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: net.switch_bin)
            p.arguments = ["--socket", net.socket]
            p.standardInput = FileHandle.nullDevice
            if let log = FileHandle(forWritingAtPath: net.socket + ".log") ?? {
                FileManager.default.createFile(atPath: net.socket + ".log", contents: nil); return FileHandle(forWritingAtPath: net.socket + ".log") }() {
                log.seekToEndOfFile()
                p.standardOutput = log
                p.standardError = log
            }
            try? p.run()
            for _ in 0..<50 {
                usleep(100_000)
                if let c = dial() { s = c; break }
            }
        }
        guard let s else { return nil }
        let hello = (try? JSONSerialization.data(withJSONObject: ["vm": vmID, "mac": net.mac])) ?? Data()
        var line = [UInt8](hello) + [UInt8(ascii: "\n")]
        let space = Int(MemoryLayout<cmsghdr>.size + MemoryLayout<Int32>.size + 3) & ~3
        var control = [UInt8](repeating: 0, count: space)
        let sent: Int = line.withUnsafeMutableBytes { lp in
            control.withUnsafeMutableBytes { cp in
                var iov = iovec(iov_base: lp.baseAddress, iov_len: lp.count)
                return withUnsafeMutablePointer(to: &iov) { iovp in
                    var msg = msghdr()
                    msg.msg_iov = iovp
                    msg.msg_iovlen = 1
                    msg.msg_control = cp.baseAddress
                    msg.msg_controllen = socklen_t(space)
                    let h = cp.baseAddress!.assumingMemoryBound(to: cmsghdr.self)
                    h.pointee.cmsg_level = SOL_SOCKET
                    h.pointee.cmsg_type = SCM_RIGHTS
                    h.pointee.cmsg_len = socklen_t(MemoryLayout<cmsghdr>.size + MemoryLayout<Int32>.size)
                    (cp.baseAddress! + MemoryLayout<cmsghdr>.size).storeBytes(of: switchEnd, as: Int32.self)
                    return sendmsg(s, &msg, 0)
                }
            }
        }
        guard sent == line.count else { close(s); return nil }
        // Keep our copy until the switch confirms: on macOS a descriptor closed while in flight can be lost.
        var ack = [UInt8](repeating: 0, count: 3)
        var got = 0
        while got < 3 {
            let n = ack.withUnsafeMutableBytes { read(s, $0.baseAddress! + got, 3 - got) }
            if n <= 0 { close(s); return nil }
            got += n
        }
        guard ack == Array("ok\n".utf8) else { close(s); return nil }
        return s
    }
}

struct ExtraDisk: Decodable {
    let path: String
    let read_only: Bool?
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    FileHandle.standardError.write(Data("fluxvm-vz-runner: \(message)\n".utf8))
    exit(code)
}

/// Copies `from` to `to` until EOF, then half-closes `to`. Writes through `withUnsafeBytes`, because `&buf[i]` can
/// hand `write` a pointer to a one-byte temporary instead of the array's storage.
/// Copies both ways between two descriptors until both directions end, then runs `done` (which closes them) on the main
/// queue. End of file half-closes the other side; an error shuts both down so the other direction cannot block forever.
func splice(_ a: Int32, _ b: Int32, done: @escaping () -> Void) {
    let group = DispatchGroup()
    for (from, to) in [(a, b), (b, a)] {
        group.enter()
        DispatchQueue.global().async {
            var buf = [UInt8](repeating: 0, count: 64 * 1024)
            var failed = false
            copy: while true {
                let n = read(from, &buf, buf.count)
                if n == 0 { break }
                if n < 0 { if errno == EINTR { continue }; failed = true; break }
                var off = 0
                while off < n {
                    let w = buf.withUnsafeBytes { write(to, $0.baseAddress! + off, n - off) }
                    if w <= 0 { failed = true; break copy }
                    off += w
                }
            }
            if failed { shutdown(a, SHUT_RDWR); shutdown(b, SHUT_RDWR) } else { shutdown(to, SHUT_WR) }
            group.leave()
        }
    }
    group.notify(queue: .main, execute: done)
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
    var privateLinks: [String: PrivateLink] = [:]

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
                // A clone of a prepared guest has no identity yet: give it its own, so two clones are two machines.
                let id: VZMacMachineIdentifier
                if let data = try? Data(contentsOf: file("identity.bin")) {
                    guard let known = VZMacMachineIdentifier(dataRepresentation: data) else { throw err("invalid Apple machine identifier") }
                    id = known
                } else {
                    id = VZMacMachineIdentifier()
                    try id.dataRepresentation.write(to: file("identity.bin"), options: .atomic)
                }
                p.machineIdentifier = id
                p.auxiliaryStorage = VZMacAuxiliaryStorage(contentsOf: file("auxiliary.bin"))
            }
            c.platform = p
            c.bootLoader = VZMacOSBootLoader()
            let g = VZMacGraphicsDeviceConfiguration()
            g.displays = self.macDisplays()
            c.graphicsDevices = [g]
            c.keyboards = [VZMacKeyboardConfiguration()]
            c.pointingDevices = [VZMacTrackpadConfiguration()]
        } else {
            if let kernel = cfg.kernel {
                let boot = VZLinuxBootLoader(kernelURL: URL(fileURLWithPath: kernel))
                if let initrd = cfg.initrd { boot.initialRamdiskURL = URL(fileURLWithPath: initrd) }
                boot.commandLine = cfg.cmdline ?? "console=hvc0"
                c.bootLoader = boot
            } else {
                let boot = VZEFIBootLoader()
                boot.variableStore = FileManager.default.fileExists(atPath: file("efi.bin").path)
                    ? VZEFIVariableStore(url: file("efi.bin"))
                    : try VZEFIVariableStore(creatingVariableStoreAt: file("efi.bin"))
                c.bootLoader = boot
            }
            // A saved VM state is tied to the machine identifier, and a generic platform invents a new one on every
            // launch, so keep one per VM or a restore fails with "invalid argument".
            let platform = VZGenericPlatformConfiguration()
            let idFile = file("generic-id.bin")
            if let data = try? Data(contentsOf: idFile), let id = VZGenericMachineIdentifier(dataRepresentation: data) {
                platform.machineIdentifier = id
            } else {
                try platform.machineIdentifier.dataRepresentation.write(to: idFile, options: .atomic)
            }
            if cfg.nested_virtualization == true {
                guard #available(macOS 15.0, *) else {
                    throw err("nested virtualization needs macOS 15 or later")
                }
                guard VZGenericPlatformConfiguration.isNestedVirtualizationSupported else {
                    throw err("nested virtualization is not supported on this Mac (M3 or later required)")
                }
                platform.isNestedVirtualizationEnabled = true
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
            VZVirtioBlockDeviceConfiguration(attachment: try self.rootStorageAttachment())
        ]
        if cfg.guest_os == "linux" {
            if let seed = cfg.seed, FileManager.default.fileExists(atPath: seed) {
                storage.append(VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: seed), readOnly: true)))
            }
            if let media = cfg.media, !media.isEmpty {
                storage.append(VZUSBMassStorageDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: media), readOnly: true)))
            }
            for d in cfg.extra_disks ?? [] {
                storage.append(VZVirtioBlockDeviceConfiguration(attachment: try VZDiskImageStorageDeviceAttachment(url: URL(fileURLWithPath: d.path), readOnly: d.read_only ?? false)))
            }
        }
        c.storageDevices = storage

        let net = VZVirtioNetworkDeviceConfiguration()
        net.attachment = try self.networkAttachment()
        if let m = cfg.mac, let mac = VZMACAddress(string: m) { net.macAddress = mac }
        // `network: none` means no network card, so the guest has nothing to route through.
        c.networkDevices = cfg.network_none == true ? [] : [net]
        if cfg.guest_os == "linux" {
            for p in cfg.networks ?? [] {
                guard let mac = VZMACAddress(string: p.mac) else { throw err("network \(p.name): bad MAC \(p.mac)") }
                // One socket pair per network for the life of the runner; later configurations reuse it.
                let link: PrivateLink
                if let l = privateLinks[p.name] { link = l } else {
                    link = try PrivateLink(p, vmID: cfg.id)
                    privateLinks[p.name] = link
                    link.start()
                }
                let card = VZVirtioNetworkDeviceConfiguration()
                card.attachment = link.attachment
                card.macAddress = mac
                c.networkDevices.append(card)
            }
        }
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
            if cfg.rosetta == true {
                let fs = VZVirtioFileSystemDeviceConfiguration(tag: "rosetta")
                fs.share = try VZLinuxRosettaDirectoryShare()
                fsDevices.append(fs)
            }
            c.directorySharingDevices = fsDevices
        } else if !(cfg.shares ?? []).isEmpty {
            guard #available(macOS 13.0, *) else {
                throw err("shared folders for macOS guests need a macOS 13+ host")
            }
            var dirs: [String: VZSharedDirectory] = [:]
            for (index, share) in (cfg.shares ?? []).enumerated() {
                var isDir: ObjCBool = false
                guard FileManager.default.fileExists(atPath: share.host_path, isDirectory: &isDir),
                      isDir.boolValue else {
                    throw err("shared folder \(share.host_path) is not a directory")
                }
                let base = URL(fileURLWithPath: share.host_path).lastPathComponent
                let wanted = base.isEmpty ? "share\(index)" : base
                let canonical = VZMultipleDirectoryShare.canonicalizedName(from: wanted) ?? "share\(index)"
                var name = canonical
                var suffix = 2
                while dirs[name] != nil {
                    name = "\(canonical)-\(suffix)"
                    suffix += 1
                }
                dirs[name] = VZSharedDirectory(
                    url: URL(fileURLWithPath: share.host_path),
                    readOnly: share.read_only
                )
            }
            let fs = VZVirtioFileSystemDeviceConfiguration(
                tag: VZVirtioFileSystemDeviceConfiguration.macOSGuestAutomountTag
            )
            fs.share = VZMultipleDirectoryShare(directories: dirs)
            c.directorySharingDevices = [fs]
        }

        var audio: [VZAudioDeviceConfiguration] = []
        if cfg.audio_output != false {
            let stream = VZVirtioSoundDeviceOutputStreamConfiguration()
            stream.sink = VZHostAudioOutputStreamSink()
            let device = VZVirtioSoundDeviceConfiguration()
            device.streams = [stream]
            audio.append(device)
        }
        if cfg.microphone == true {
            let stream = VZVirtioSoundDeviceInputStreamConfiguration()
            stream.source = VZHostAudioInputStreamSource()
            let device = VZVirtioSoundDeviceConfiguration()
            device.streams = [stream]
            audio.append(device)
        }
        c.audioDevices = audio

        if cfg.usb_controller == true {
            guard #available(macOS 15.0, *) else {
                throw err("USB XHCI passthrough support needs macOS 15 or later")
            }
            c.usbControllers = [VZXHCIControllerConfiguration()]
        }
        try self.configureClipboard(c)
        try self.configureCustomVirtio(c)
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
                self.startMachine(machine)
            }
            startControlServer()
            startIPWatcher()
            if cfg.vsock_socket != nil { startVsockProxy() }
            if let allow = cfg.egress_allow, !allow.isEmpty { startEgressProxy(allow) }
            for f in cfg.forwards ?? [] where f.guests != true { startForward(f, bind: "127.0.0.1", fatal: true) }
            setupSignals()
        } catch { fail(error.localizedDescription) }
    }

    func showWindow(_ machine: VZVirtualMachine) {
        let aspect = Double(cfg.display_width ?? 2560) / Double(cfg.display_height ?? 1600)
        let initialWidth = 1100.0
        let view = VZVirtualMachineView(frame: NSRect(
            x: 0, y: 0, width: initialWidth, height: initialWidth / aspect
        ))
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
            case "capabilities":
                if let data = try? JSONEncoder().encode(fluxAppleHostCapabilities()),
                   var caps = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] {
                    caps["ok"] = true
                    response = caps
                } else {
                    response = ["ok": false, "error": "cannot encode host capabilities"]
                }
                sem.signal()
            case "balloon":
                response = self.balloonControl(reclaimMiB: (o["balloon_mib"] as? NSNumber)?.uint64Value)
                sem.signal()
            case "usb-attach":
                guard let path = o["path"] as? String else { response = ["ok": false, "error": "usb-attach needs path"]; sem.signal(); break }
                self.attachUSBMassStorage(path: path, readOnly: (o["read_only"] as? Bool) ?? false) { response = $0; sem.signal() }
            case "usb-detach":
                guard let id = o["uuid"] as? String else { response = ["ok": false, "error": "usb-detach needs uuid"]; sem.signal(); break }
                self.detachUSB(uuid: id) { response = $0; sem.signal() }
            case "share-set":
                // Points a running virtiofs share at another directory (warm-pool slots boot on placeholders).
                guard let tag = o["tag"] as? String, let path = o["path"] as? String, let vm = self.vm else { response = ["ok": false, "error": "share-set needs tag, path and a running guest"]; sem.signal(); break }
                guard let dev = vm.directorySharingDevices.compactMap({ $0 as? VZVirtioFileSystemDevice }).first(where: { $0.tag == tag }) else { response = ["ok": false, "error": "no share tagged \(tag)"]; sem.signal(); break }
                dev.share = VZSingleDirectoryShare(directory: VZSharedDirectory(url: URL(fileURLWithPath: path), readOnly: (o["read_only"] as? Bool) ?? false))
                response = ["ok": true]
                sem.signal()
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
            if self?.cfg.guest_os == "macos" { self?.discoverByLease(); return }
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

    // A macOS guest has no systemd service to print its address. The Mac's own DHCP server for the NAT keeps its leases in
    // /var/db/dhcpd_leases (readable by everyone), and a macOS guest identifies itself by the MAC its network card was given
    // (`hw_address=1,<mac>`, without leading zeros). The ARP table is not usable here: macOS shows it empty to processes that
    // were not started from a terminal.
    var leaseTick = 0
    func discoverByLease() {
        leaseTick += 1
        guard leaseTick % 2 == 0, let mac = cfg.mac,
              let text = try? String(contentsOfFile: "/var/db/dhcpd_leases", encoding: .utf8) else { return }
        func norm(_ s: String) -> String { s.lowercased().split(separator: ":").map { String(Int($0, radix: 16) ?? -1, radix: 16) }.joined(separator: ":") }
        let want = "1," + norm(mac)
        var best: (ip: String, expires: UInt64)?
        for block in text.components(separatedBy: "}") {
            var fields: [String: String] = [:]
            for line in block.split(separator: "\n") {
                let kv = line.split(separator: "=", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                if kv.count == 2 { fields[kv[0]] = kv[1] }
            }
            guard let hw = fields["hw_address"], hw.lowercased() == want, let ip = fields["ip_address"] else { continue }
            let expires = fields["lease"].flatMap { UInt64($0.dropFirst(2), radix: 16) } ?? 0
            if best == nil || expires >= best!.expires { best = (ip, expires) }
        }
        guard let found = best?.ip else { return }
        if found != ip {
            ip = found
            try? found.write(toFile: cfg.ip_file, atomically: true, encoding: .utf8)
        }
        startGuestForwards(guestIP: found)
    }

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
        splice(c, g) { close(c); close(g) }
    }

    // MARK: egress proxy (guest -> host over vsock, allow-listed HTTP CONNECT / plain HTTP)

    // The guest has no network card, so this is the only way out. Names are matched here, on the host, and the address they
    // resolve to must be a public one, so an allowed name cannot be pointed at the Mac or at the local network.
    var egressListener: VZVirtioSocketListener?
    var egressDelegate: EgressDelegate?

    func startEgressProxy(_ allow: [String]) {
        DispatchQueue.main.async {
            guard let device = self.vm?.socketDevices.first as? VZVirtioSocketDevice else { return }
            let rules = allow.map { $0.lowercased() }
            let delegate = EgressDelegate { conn in
                self.vsockConnections.append(conn)
                let fd = conn.fileDescriptor
                DispatchQueue.global().async { self.serveEgress(fd, rules) { DispatchQueue.main.async { self.release(conn) } } }
            }
            let listener = VZVirtioSocketListener()
            listener.delegate = delegate
            device.setSocketListener(listener, forPort: 3128)
            self.egressListener = listener
            self.egressDelegate = delegate
        }
    }

    func hostAllowed(_ host: String, _ rules: [String]) -> Bool {
        let h = host.lowercased().trimmingCharacters(in: CharacterSet(charactersIn: "."))
        return rules.contains { r in r.hasPrefix("*.") ? h.hasSuffix(String(r.dropFirst(1))) : h == r }
    }

    func publicAddress(_ a: UInt32) -> Bool {   // host byte order
        let b0 = a >> 24, b1 = (a >> 16) & 255
        if b0 == 0 || b0 == 10 || b0 == 127 || b0 >= 224 { return false }
        if b0 == 169 && b1 == 254 { return false }
        if b0 == 172 && (16...31).contains(b1) { return false }
        if b0 == 192 && b1 == 168 { return false }
        if b0 == 100 && (64...127).contains(b1) { return false }
        return true
    }

    func connectUpstream(_ host: String, _ port: UInt16) -> Int32? {
        var hints = addrinfo(); hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM
        var res: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { return nil }
        defer { freeaddrinfo(res) }
        var p: UnsafeMutablePointer<addrinfo>? = first
        while let ai = p {
            let sin = ai.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
            if publicAddress(UInt32(bigEndian: sin.sin_addr.s_addr)) {
                let s = socket(AF_INET, SOCK_STREAM, 0)
                if s >= 0 {
                    if Darwin.connect(s, ai.pointee.ai_addr, ai.pointee.ai_addrlen) == 0 { return s }
                    close(s)
                }
            }
            p = ai.pointee.ai_next
        }
        return nil
    }

    /// The guest's side `c` belongs to a vsock connection; `finish` releases it.
    func serveEgress(_ c: Int32, _ rules: [String], finish: @escaping () -> Void) {
        func reply(_ status: String, _ body: String) {
            let text = "HTTP/1.1 \(status)\r\nContent-Type: text/plain\r\nContent-Length: \(body.utf8.count)\r\nConnection: close\r\n\r\n\(body)"
            _ = text.withCString { write(c, $0, strlen($0)) }
            finish()
        }
        var head = Data()
        var byte: UInt8 = 0
        let end = Data("\r\n\r\n".utf8)
        while head.count < 16384, read(c, &byte, 1) == 1 {
            head.append(byte)
            if head.suffix(4) == end { break }
        }
        guard head.suffix(4) == end, let text = String(data: head, encoding: .utf8) else { finish(); return }
        var lines = text.components(separatedBy: "\r\n")
        let first = lines.removeFirst().split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        guard first.count == 3 else { reply("400 Bad Request", "bad request\n"); return }
        let method = first[0], target = first[1], version = first[2]
        var host = "", port: UInt16 = 80, path = "/"
        if method.uppercased() == "CONNECT" {
            let hp = target.split(separator: ":").map(String.init)
            host = hp.first ?? ""; port = hp.count == 2 ? (UInt16(hp[1]) ?? 0) : 443
        } else if let u = URLComponents(string: target), u.scheme == "http", let h = u.host {
            host = h; port = UInt16(u.port ?? 80)
            path = (u.percentEncodedPath.isEmpty ? "/" : u.percentEncodedPath) + (u.percentEncodedQuery.map { "?" + $0 } ?? "")
        } else { reply("400 Bad Request", "this proxy needs an absolute http:// URL or CONNECT\n"); return }
        guard port == 80 || port == 443, hostAllowed(host, rules) else {
            emit(["event": "egress-denied", "host": host, "port": Int(port)])
            reply("403 Forbidden", "\(host):\(port) is not on this sandbox's allow-list\n"); return
        }
        guard let up = connectUpstream(host, port) else {
            emit(["event": "egress-unreachable", "host": host])
            reply("502 Bad Gateway", "cannot reach \(host)\n"); return
        }
        emit(["event": "egress-allowed", "host": host, "port": Int(port)])
        if method.uppercased() == "CONNECT" {
            _ = "HTTP/1.1 200 Connection Established\r\n\r\n".withCString { write(c, $0, strlen($0)) }
        } else {
            // Forward as an ordinary origin-form request on a connection that closes after the response, so a keep-alive
            // client cannot send a second request for another host down the same tunnel.
            let kept = lines.filter { l in
                let k = l.lowercased()
                return !l.isEmpty && !k.hasPrefix("connection:") && !k.hasPrefix("proxy-connection:") && !k.hasPrefix("proxy-authorization:")
            }
            let out = (["\(method) \(path) \(version)"] + kept + ["Connection: close", "", ""]).joined(separator: "\r\n")
            _ = out.withCString { write(up, $0, strlen($0)) }
        }
        splice(c, up) { close(up); finish() }
    }

    // MARK: vsock proxy ("CONNECT <port>\n" over a unix socket, like Firecracker's)

    /// Closes a finished vsock connection and drops the reference that kept its descriptor open. Main queue.
    func release(_ conn: VZVirtioSocketConnection) {
        conn.close()
        vsockConnections.removeAll { $0 === conn }
    }

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
        // `CONNECT <port>` answers `OK <port>`; `CONNECT <port> QUIET` does not, for clients (ssh's ProxyCommand) that
        // need the stream to start with the guest's own bytes.
        guard parts.count == 2 || (parts.count == 3 && parts[2] == "QUIET"), parts[0] == "CONNECT", let port = UInt32(parts[1]) else { close(c); return }
        let quiet = parts.count == 3
        DispatchQueue.main.async {
            guard let device = self.vm?.socketDevices.first as? VZVirtioSocketDevice else { close(c); return }
            device.connect(toPort: port) { result in
                switch result {
                case .failure: close(c)
                case .success(let conn):
                    self.vsockConnections.append(conn)
                    let g = conn.fileDescriptor
                    if !quiet { _ = "OK \(port)\n".withCString { write(c, $0, strlen($0)) } }
                    splice(c, g) { close(c); self.release(conn) }
                }
            }
        }
    }
}

final class EgressDelegate: NSObject, VZVirtioSocketListenerDelegate {
    let accept: (VZVirtioSocketConnection) -> Void
    init(_ accept: @escaping (VZVirtioSocketConnection) -> Void) { self.accept = accept }
    func listener(_ listener: VZVirtioSocketListener, shouldAcceptNewConnection connection: VZVirtioSocketConnection, from socketDevice: VZVirtioSocketDevice) -> Bool {
        accept(connection)
        return true
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
