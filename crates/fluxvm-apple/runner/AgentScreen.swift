// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Screen capture and keyboard/mouse input for agents. Virtualization.framework has no framebuffer or input API, so
// the runner drives the VM's own display view: screenshots come from the view's window and input is delivered as
// AppKit events to the view, which forwards them to the guest's keyboard and pointing device.
import AppKit
import Virtualization

/// US-layout key codes (kVK_*) for the characters `type` can send; `true` means Shift is held.
private let fluxKeyMap: [Character: (UInt16, Bool)] = {
    var m: [Character: (UInt16, Bool)] = [:]
    let letters: [(Character, UInt16)] = [
        ("a", 0), ("s", 1), ("d", 2), ("f", 3), ("h", 4), ("g", 5), ("z", 6), ("x", 7), ("c", 8), ("v", 9),
        ("b", 11), ("q", 12), ("w", 13), ("e", 14), ("r", 15), ("y", 16), ("t", 17), ("o", 31), ("u", 32),
        ("i", 34), ("p", 35), ("l", 37), ("j", 38), ("k", 40), ("n", 45), ("m", 46),
    ]
    for (c, k) in letters {
        m[c] = (k, false)
        m[Character(c.uppercased())] = (k, true)
    }
    let plain: [(Character, UInt16)] = [
        ("1", 18), ("2", 19), ("3", 20), ("4", 21), ("6", 22), ("5", 23), ("=", 24), ("9", 25), ("7", 26),
        ("-", 27), ("8", 28), ("0", 29), ("]", 30), ("[", 33), ("'", 39), (";", 41), ("\\", 42), (",", 43),
        ("/", 44), (".", 47), ("`", 50), (" ", 49), ("\n", 36), ("\t", 48),
    ]
    for (c, k) in plain { m[c] = (k, false) }
    let shifted: [(Character, UInt16)] = [
        ("!", 18), ("@", 19), ("#", 20), ("$", 21), ("^", 22), ("%", 23), ("+", 24), ("(", 25), ("&", 26),
        ("_", 27), ("*", 28), (")", 29), ("}", 30), ("{", 33), ("\"", 39), (":", 41), ("|", 42), ("<", 43),
        ("?", 44), (">", 47), ("~", 50),
    ]
    for (c, k) in shifted { m[c] = (k, true) }
    return m
}()

/// Named keys for `key`.
private let fluxNamedKeys: [String: UInt16] = [
    "enter": 36, "return": 36, "tab": 48, "space": 49, "backspace": 51, "delete": 117, "escape": 53, "esc": 53,
    "left": 123, "right": 124, "down": 125, "up": 126, "home": 115, "end": 119, "pageup": 116, "pagedown": 121, "page_up": 116, "page_down": 121,
    "f1": 122, "f2": 120, "f3": 99, "f4": 118, "f5": 96, "f6": 97, "f7": 98, "f8": 100, "f9": 101, "f10": 109,
    "f11": 103, "f12": 111,
]

/// Modifier name → (left-hand key code, flag). The flag carries the device bit for the left-hand key
/// (NX_DEVICEL*KEYMASK); the VM view ignores a modifier without it.
private let fluxModifiers: [String: (UInt16, NSEvent.ModifierFlags)] = {
    let shift = NSEvent.ModifierFlags(rawValue: NSEvent.ModifierFlags.shift.rawValue | 0x02)
    let control = NSEvent.ModifierFlags(rawValue: NSEvent.ModifierFlags.control.rawValue | 0x01)
    let option = NSEvent.ModifierFlags(rawValue: NSEvent.ModifierFlags.option.rawValue | 0x20)
    let command = NSEvent.ModifierFlags(rawValue: NSEvent.ModifierFlags.command.rawValue | 0x08)
    return [
        "shift": (56, shift), "ctrl": (59, control), "control": (59, control), "alt": (58, option),
        "option": (58, option), "cmd": (55, command), "command": (55, command), "super": (55, command),
        "meta": (55, command), "win": (55, command),
    ]
}()

extension Runner {
    /// The view agents see and drive: the console window's view, or a hidden one created on first use.
    func agentDisplayView() -> VZVirtualMachineView? {
        if let view = window?.contentView as? VZVirtualMachineView { return view }
        if let view = agentView { return view }
        guard let machine = vm else { return nil }
        // A capture of the hidden window comes out blank whenever its backing store is exactly the guest display's
        // size, so a large display renders at half its pixels, and a small one at twice its pixels, captured at the
        // window's nominal size.
        let scale = NSScreen.main?.backingScaleFactor ?? 2
        let pixels = CGSize(width: cfg.display_width ?? (cfg.guest_os == "macos" ? 2560 : 1280),
                            height: cfg.display_height ?? (cfg.guest_os == "macos" ? 1600 : 800))
        let large = pixels.width >= 1920
        let points = large ? 0.5 / scale : 2 / scale
        let width = pixels.width * points, height = pixels.height * points
        agentCaptureNominal = !large
        let view = VZVirtualMachineView(frame: NSRect(x: 0, y: 0, width: width, height: height))
        #if compiler(>=6.4)
        if #available(macOS 27.0, *) {
            view.adaptor = VZVirtualMachineViewAdaptor(virtualMachine: machine)
        } else {
            view.virtualMachine = machine
        }
        #else
        view.virtualMachine = machine
        #endif
        view.capturesSystemKeys = true
        let w = NSWindow(contentRect: view.frame, styleMask: [.borderless], backing: .buffered, defer: false)
        w.contentView = view
        w.isReleasedWhenClosed = false
        w.ignoresMouseEvents = true
        // Opaque (a transparent window captures as transparent) and ordered in, but placed off every screen.
        w.setFrameOrigin(NSPoint(x: -20000, y: -20000))
        w.collectionBehavior = [.canJoinAllSpaces, .stationary, .ignoresCycle]
        w.orderFrontRegardless()
        agentView = view
        agentWindow = w
        agentViewCreated = Date()
        return view
    }

    /// `screenshot`: writes a PNG of the guest display to `path`.
    func agentScreenshot(path: String, maxWidth: Int? = nil, done: @escaping ([String: Any]) -> Void) {
        guard let view = agentDisplayView(), let w = view.window else {
            done(["ok": false, "error": "the VM is not running"]); return
        }
        let nominal = view === agentView && agentCaptureNominal
        func capture() -> (CGImage?, String) {
            let resolution: CGWindowImageOption = nominal ? .nominalResolution : .bestResolution
            if let image = CGWindowListCreateImage(.null, .optionIncludingWindow, CGWindowID(w.windowNumber),
                                                   [.boundsIgnoreFraming, resolution]),
               !fluxImageIsBlank(image) {
                return (image, "window")
            }
            if let rep = view.bitmapImageRepForCachingDisplay(in: view.bounds) {
                view.cacheDisplay(in: view.bounds, to: rep)
                return (rep.cgImage, "view")
            }
            return (nil, "view")
        }
        // A freshly created view shows nothing until the guest's first frame arrives, which an idle text console
        // may take a few seconds to send.
        func attempt(_ n: Int) {
            let (image, method) = capture()
            let fresh = Date().timeIntervalSince(self.agentViewCreated ?? .distantPast) < 6
            if fresh, n < 10, image.map(fluxImageIsBlank) ?? true {
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { attempt(n + 1) }
                return
            }
            finish(image, method)
        }
        func finish(_ captured: CGImage?, _ method: String) {
            guard var image = captured else { done(["ok": false, "error": "could not capture the display"]); return }
            let blank = fluxImageIsBlank(image)
            if let maxWidth, maxWidth > 0, image.width > maxWidth, let small = fluxScaled(image, width: maxWidth) {
                image = small
            }
            let rep = NSBitmapImageRep(cgImage: image)
            guard let png = rep.representation(using: .png, properties: [:]) else {
                done(["ok": false, "error": "could not encode the screenshot"]); return
            }
            do {
                try png.write(to: URL(fileURLWithPath: path), options: .atomic)
                done(["ok": true, "path": path, "width": image.width, "height": image.height,
                      "blank": blank, "method": method])
            } catch {
                done(["ok": false, "error": "could not write \(path): \(error.localizedDescription)"])
            }
        }
        let delay = max(0, 1.0 - Date().timeIntervalSince(agentViewCreated ?? .distantPast))
        DispatchQueue.main.asyncAfter(deadline: .now() + delay) { attempt(0) }
    }

    /// `input`: one keyboard or mouse action. Coordinates are pixels in the screenshot.
    func agentInput(_ o: [String: Any]) -> [String: Any] {
        guard let view = agentDisplayView(), let w = view.window else { return ["ok": false, "error": "the VM is not running"] }
        let action = o["action"] as? String ?? ""
        let mods = (o["modifiers"] as? [String] ?? []).map { $0.lowercased() }
        for m in mods where fluxModifiers[m] == nil { return ["ok": false, "error": "unknown modifier \(m)"] }
        // Coordinates are pixels of a screenshot `screen_width` wide (default: the full-resolution one).
        let fullPerPoint = view === agentView && agentCaptureNominal ? 1 : (view.window?.backingScaleFactor ?? 2)
        let perPoint = (o["screen_width"] as? NSNumber).map { $0.doubleValue / max(view.bounds.width, 1) } ?? fullPerPoint
        let viewPoint = { (x: Double, y: Double) in self.viewPoint(view, x: x, y: y, perPoint: perPoint) }
        switch action {
        case "type":
            guard let text = o["text"] as? String, !text.isEmpty else { return ["ok": false, "error": "type needs text"] }
            if let bad = text.first(where: { fluxKeyMap[$0] == nil }) {
                return ["ok": false, "error": "cannot type \(String(reflecting: String(bad))) (US keyboard layout, printable ASCII, newline and tab)"]
            }
            for ch in text {
                let (code, shift) = fluxKeyMap[ch]!
                sendKey(view, w, code: code, chars: String(ch), modifiers: shift ? ["shift"] : [])
            }
            return ["ok": true, "typed": text.count]
        case "key":
            guard let name = (o["key"] as? String)?.lowercased() else { return ["ok": false, "error": "key needs key"] }
            let code: UInt16, chars: String
            if let named = fluxNamedKeys[name] {
                code = named; chars = ""
            } else if name.count == 1, let (c, _) = fluxKeyMap[Character(name)] {
                code = c; chars = name
            } else {
                return ["ok": false, "error": "unknown key \(name)"]
            }
            sendKey(view, w, code: code, chars: chars, modifiers: mods)
            return ["ok": true]
        case "move", "click", "double_click", "right_click", "middle_click", "down", "up", "drag":
            guard let x = (o["x"] as? NSNumber)?.doubleValue, let y = (o["y"] as? NSNumber)?.doubleValue else {
                return ["ok": false, "error": "\(action) needs x and y"]
            }
            let p = viewPoint(x, y)
            let flagSet = press(view, w, mods)
            defer { release(view, w, mods) }
            switch action {
            case "move":
                mouse(view, w, .mouseMoved, p, flagSet)
            case "click", "double_click":
                mouse(view, w, .mouseMoved, p, flagSet)
                for n in 1...(action == "click" ? 1 : 2) {
                    mouse(view, w, .leftMouseDown, p, flagSet, clicks: n)
                    mouse(view, w, .leftMouseUp, p, flagSet, clicks: n)
                }
            case "right_click", "middle_click":
                // The view takes the button from the event's button number, which AppKit's synthesized mouse events
                // leave at 0 (left). A CoreGraphics "other" button event carries it and leaves the pointer in place.
                mouse(view, w, .mouseMoved, p, flagSet)
                let button: CGMouseButton = action == "right_click" ? .right : .center
                otherButton(view, .otherMouseDown, button)
                otherButton(view, .otherMouseUp, button)
            case "down":
                mouse(view, w, .leftMouseDown, p, flagSet)
            case "up":
                mouse(view, w, .leftMouseUp, p, flagSet)
            default: // drag from (x, y) to (to_x, to_y)
                guard let tx = (o["to_x"] as? NSNumber)?.doubleValue, let ty = (o["to_y"] as? NSNumber)?.doubleValue else {
                    return ["ok": false, "error": "drag needs to_x and to_y"]
                }
                let q = viewPoint(tx, ty)
                mouse(view, w, .mouseMoved, p, flagSet)
                mouse(view, w, .leftMouseDown, p, flagSet)
                let steps = 12
                for i in 1...steps {
                    let t = Double(i) / Double(steps)
                    mouse(view, w, .leftMouseDragged, NSPoint(x: p.x + (q.x - p.x) * t, y: p.y + (q.y - p.y) * t), flagSet)
                }
                mouse(view, w, .leftMouseUp, q, flagSet)
            }
            return ["ok": true]
        case "scroll":
            let dx = (o["dx"] as? NSNumber)?.int32Value ?? 0, dy = (o["dy"] as? NSNumber)?.int32Value ?? 0
            if let x = (o["x"] as? NSNumber)?.doubleValue, let y = (o["y"] as? NSNumber)?.doubleValue {
                mouse(view, w, .mouseMoved, viewPoint(x, y), [])
            }
            // One unit is one wheel notch in the guest; the view turns a line into a tenth of a notch.
            guard let cg = CGEvent(scrollWheelEvent2Source: nil, units: .line, wheelCount: 2,
                                   wheel1: -dy * 12, wheel2: -dx * 12, wheel3: 0),
                  let e = NSEvent(cgEvent: cg) else { return ["ok": false, "error": "could not create a scroll event"] }
            w.sendEvent(e)
            return ["ok": true]
        default:
            return ["ok": false, "error": "unknown input action \(action)"]
        }
    }

    /// Screenshot pixels (top-left origin) to view points (bottom-left origin).
    private func viewPoint(_ view: NSView, x: Double, y: Double, perPoint: Double) -> NSPoint {
        let local = NSPoint(x: x / perPoint, y: view.bounds.height - y / perPoint)
        return view.convert(local, to: nil)
    }

    private func sendKey(_ view: NSView, _ w: NSWindow, code: UInt16, chars: String, modifiers: [String]) {
        let flagSet = press(view, w, modifiers)
        defer { release(view, w, modifiers) }
        for type in [NSEvent.EventType.keyDown, .keyUp] {
            if let e = NSEvent.keyEvent(with: type, location: .zero, modifierFlags: flagSet,
                                        timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: w.windowNumber,
                                        context: nil, characters: chars, charactersIgnoringModifiers: chars.lowercased(),
                                        isARepeat: false, keyCode: code) {
                type == .keyDown ? view.keyDown(with: e) : view.keyUp(with: e)
            }
            usleep(4000)
        }
    }

    /// Presses `names` in order; each flagsChanged event carries every modifier held so far.
    @discardableResult
    private func press(_ view: NSView, _ w: NSWindow, _ names: [String]) -> NSEvent.ModifierFlags {
        var held = NSEvent.ModifierFlags()
        for name in names {
            let (code, flag) = fluxModifiers[name]!
            held.formUnion(flag)
            flagsEvent(view, w, code, held)
        }
        return held
    }

    private func release(_ view: NSView, _ w: NSWindow, _ names: [String]) {
        var held = names.reduce(into: NSEvent.ModifierFlags()) { $0.formUnion(fluxModifiers[$1]!.1) }
        for name in names.reversed() {
            let (code, flag) = fluxModifiers[name]!
            held.subtract(flag)
            flagsEvent(view, w, code, held)
        }
    }

    private func flagsEvent(_ view: NSView, _ w: NSWindow, _ code: UInt16, _ held: NSEvent.ModifierFlags) {
        guard let e = NSEvent.keyEvent(with: .flagsChanged, location: .zero, modifierFlags: held,
                                       timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: w.windowNumber,
                                       context: nil, characters: "", charactersIgnoringModifiers: "",
                                       isARepeat: false, keyCode: code) else { return }
        view.flagsChanged(with: e)
        usleep(4000)
    }

    private func mouse(_ view: NSView, _ w: NSWindow, _ type: NSEvent.EventType, _ p: NSPoint,
                       _ flags: NSEvent.ModifierFlags, clicks: Int = 1) {
        guard let e = NSEvent.mouseEvent(with: type, location: p, modifierFlags: flags,
                                         timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: w.windowNumber,
                                         context: nil, eventNumber: 0, clickCount: clicks,
                                         pressure: type == .leftMouseDown || type == .rightMouseDown ? 1 : 0) else { return }
        w.sendEvent(e)
        usleep(4000)
    }

    private func otherButton(_ view: NSView, _ type: CGEventType, _ button: CGMouseButton) {
        guard let cg = CGEvent(mouseEventSource: nil, mouseType: type, mouseCursorPosition: .zero, mouseButton: button),
              let e = NSEvent(cgEvent: cg) else { return }
        type == .otherMouseDown ? view.otherMouseDown(with: e) : view.otherMouseUp(with: e)
        usleep(4000)
    }
}

/// True when every sampled pixel has the same color (a black or empty frame).
func fluxImageIsBlank(_ image: CGImage) -> Bool {
    let w = 64, h = 40
    var px = [UInt8](repeating: 0, count: w * h * 4)
    guard let ctx = CGContext(data: &px, width: w, height: h, bitsPerComponent: 8, bytesPerRow: w * 4,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue) else { return true }
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: w, height: h))
    let first = Array(px[0..<4])
    return stride(from: 0, to: px.count, by: 4).allSatisfy { Array(px[$0..<$0 + 4]) == first }
}

/// `image` resized to `width` pixels wide, keeping the aspect ratio.
func fluxScaled(_ image: CGImage, width: Int) -> CGImage? {
    let height = max(1, Int((Double(image.height) * Double(width) / Double(image.width)).rounded()))
    guard let ctx = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
                              space: CGColorSpaceCreateDeviceRGB(),
                              bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) else { return nil }
    ctx.interpolationQuality = .high
    ctx.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
    return ctx.makeImage()
}
