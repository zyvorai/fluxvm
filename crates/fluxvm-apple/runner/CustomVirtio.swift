// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// macOS 27 custom Virtio device implementation for Linux guests.
// Queue 0: bounded JSON request/response control plane.
// Queue 1: guest-DRAM bulk operations using VZGuestMemoryMapping.
#if os(macOS)
import Foundation
import Virtualization

@available(macOS 27.0, *)
private var fluxVirtioBusKeepAlive: [String: FluxVirtioBus] = [:]

@available(macOS 27.0, *)
final class FluxVirtioBus: NSObject, VZCustomVirtioDeviceConfigurationDelegate, VZCustomVirtioDeviceDelegate {
    // Linux binds a virtio-pci device only when 0x1040 + id fits 0x1040...0x107f, so the id must be <= 0x3f.
    static let deviceID: UInt16 = 0x003F
    static let controlQueue: UInt16 = 0
    static let bulkQueue: UInt16 = 1
    static let maximumBulkBytes = 64 * 1024 * 1024

    private let vmID: String
    private let deviceQueue: DispatchQueue
    private var device: VZCustomVirtioDevice?
    private var requestCount: UInt64 = 0
    private var bulkRequestCount: UInt64 = 0
    private var errorCount: UInt64 = 0

    init(vmID: String) {
        self.vmID = vmID
        self.deviceQueue = DispatchQueue(label: "dev.zyvor.fluxvm.virtio.\(vmID)")
        super.init()
    }

    func configuration() -> VZCustomVirtioDeviceConfiguration {
        let configuration = VZCustomVirtioDeviceConfiguration()
        configuration.deviceID = Self.deviceID
        configuration.pciClassID = 0xFF
        configuration.pciSubclassID = 0x00
        configuration.virtioQueueCount = 2
        configuration.provider = VZCustomVirtioDeviceDelegateProvider(
            deviceQueue: deviceQueue,
            delegate: self
        )
        return configuration
    }

    func customVirtioConfiguration(
        _ deviceConfiguration: VZCustomVirtioDeviceConfiguration,
        didCreateDevice device: VZCustomVirtioDevice
    ) {
        self.device = device
        device.delegate = self
    }

    func customVirtioDevice(_ device: VZCustomVirtioDevice,
                            didReceiveNotificationFor queue: VZVirtioQueue) {
        while let element = queue.nextElement() {
            autoreleasepool {
                defer { element.returnToQueue() }
                do {
                    try service(element: element, queueIndex: queue.queueIndex, device: device)
                } catch {
                    errorCount &+= 1
                    let reply = FluxVirtioProtocol.failure(requestID: "unknown", error.localizedDescription)
                    if let data = try? FluxVirtioProtocol.encode(reply),
                       data.count <= element.writeBuffersAvailableByteCount {
                        try? element.write(data)
                    }
                }
            }
        }
    }

    private func service(element: VZVirtioQueueElement, queueIndex: UInt16,
                         device: VZCustomVirtioDevice) throws {
        guard queueIndex == Self.controlQueue || queueIndex == Self.bulkQueue else {
            throw fluxError(10, "unsupported virtqueue \(queueIndex)")
        }
        let available = element.readBuffersAvailableByteCount
        guard available > 0, available <= FluxVirtioProtocol.maximumFrameBytes else {
            throw fluxError(11, "invalid request size \(available)")
        }

        // Guest descriptors are mutable by the guest. Consume the descriptor
        // payload exactly once, then validate/process our private Data copy.
        let requestData = try element.readBytes(withExactLength: available)
        let request = try FluxVirtioProtocol.decodeRequest(requestData)
        requestCount &+= 1
        if queueIndex == Self.bulkQueue { bulkRequestCount &+= 1 }

        let response = queueIndex == Self.controlQueue
            ? handleControl(request, device: device)
            : handleBulk(request, device: device)
        let responseData = try FluxVirtioProtocol.encode(response)
        guard responseData.count <= element.writeBuffersAvailableByteCount else {
            throw fluxError(12, "guest response buffer is too small")
        }
        try element.write(responseData)
    }

    private func handleControl(_ request: FluxVirtioRequest,
                               device: VZCustomVirtioDevice) -> FluxVirtioResponse {
        switch request.operation {
        case "ping":
            return FluxVirtioProtocol.success(request, payload: ["reply": "pong", "vm_id": vmID])
        case "echo":
            return FluxVirtioProtocol.success(request, payload: request.payload ?? [:])
        case "capabilities":
            return FluxVirtioProtocol.success(request, payload: [
                "protocol": String(FluxVirtioProtocol.version),
                "queues": "2",
                "control_queue": String(Self.controlQueue),
                "bulk_queue": String(Self.bulkQueue),
                "bulk_max_bytes": String(Self.maximumBulkBytes),
                "guest_memory_mapping": "true",
                "bulk_zero": "true",
                "bulk_fill": "true",
                "bulk_copy": "true",
                "bulk_crc32": "true",
                "telemetry": "true",
            ])
        case "stats":
            return FluxVirtioProtocol.success(request, payload: [
                "requests": String(requestCount),
                "bulk_requests": String(bulkRequestCount),
                "errors": String(errorCount),
            ])
        case "map-probe":
            guard let (address, length) = mappingTuple(request.payload, prefix: "") else {
                return FluxVirtioProtocol.failure(requestID: request.requestID,
                                                   "map-probe needs physical_address and length")
            }
            let mapped = device.guestMemoryMapping(atPhysicalAddress: address, length: length) != nil
            return FluxVirtioProtocol.success(request, payload: ["mapped": String(mapped)])
        case "telemetry":
            let payload = request.payload ?? [:]
            guard payload.count <= 64 else {
                return FluxVirtioProtocol.failure(requestID: request.requestID,
                                                   "telemetry accepts at most 64 fields")
            }
            var event: [String: Any] = ["event": "virtio-telemetry", "vm_id": vmID]
            for (k, v) in payload where k.utf8.count <= 64 && v.utf8.count <= 1024 {
                event[k] = v
            }
            emit(event)
            return FluxVirtioProtocol.success(request)
        default:
            return FluxVirtioProtocol.failure(requestID: request.requestID,
                                               "unsupported control operation \(request.operation)")
        }
    }

    private func handleBulk(_ request: FluxVirtioRequest,
                            device: VZCustomVirtioDevice) -> FluxVirtioResponse {
        switch request.operation {
        case "bulk-zero":
            guard let (address, length) = mappingTuple(request.payload, prefix: "") else {
                return FluxVirtioProtocol.failure(requestID: request.requestID,
                                                   "bulk-zero needs physical_address and length")
            }
            guard let map = mapGuest(device, address: address, length: length) else {
                return FluxVirtioProtocol.failure(requestID: request.requestID, "guest range is not mappable")
            }
            memset(map.mutableBytes, 0, length)
            return FluxVirtioProtocol.success(request, payload: ["bytes": String(length)])

        case "bulk-fill":
            guard let (address, length) = mappingTuple(request.payload, prefix: ""),
                  let raw = request.payload?["value"], let value = UInt8(raw) else {
                return FluxVirtioProtocol.failure(requestID: request.requestID,
                                                   "bulk-fill needs physical_address, length and value=0..255")
            }
            guard let map = mapGuest(device, address: address, length: length) else {
                return FluxVirtioProtocol.failure(requestID: request.requestID, "guest range is not mappable")
            }
            memset(map.mutableBytes, Int32(value), length)
            return FluxVirtioProtocol.success(request, payload: ["bytes": String(length)])

        case "bulk-copy":
            guard let src = mappingTuple(request.payload, prefix: "src_"),
                  let dst = mappingTuple(request.payload, prefix: "dst_"),
                  src.1 == dst.1 else {
                return FluxVirtioProtocol.failure(requestID: request.requestID,
                                                   "bulk-copy needs src_physical_address/src_length and dst_physical_address/dst_length of equal size")
            }
            guard let srcMap = mapGuest(device, address: src.0, length: src.1),
                  let dstMap = mapGuest(device, address: dst.0, length: dst.1) else {
                return FluxVirtioProtocol.failure(requestID: request.requestID, "source or destination range is not mappable")
            }
            memmove(dstMap.mutableBytes, srcMap.mutableBytes, src.1)
            return FluxVirtioProtocol.success(request, payload: ["bytes": String(src.1)])

        case "bulk-crc32":
            guard let (address, length) = mappingTuple(request.payload, prefix: "") else {
                return FluxVirtioProtocol.failure(requestID: request.requestID,
                                                   "bulk-crc32 needs physical_address and length")
            }
            guard let map = mapGuest(device, address: address, length: length) else {
                return FluxVirtioProtocol.failure(requestID: request.requestID, "guest range is not mappable")
            }
            let crc = crc32(UnsafeRawBufferPointer(start: map.mutableBytes, count: length))
            return FluxVirtioProtocol.success(request, payload: [
                "bytes": String(length),
                "crc32": String(format: "%08x", crc),
            ])
        default:
            return FluxVirtioProtocol.failure(requestID: request.requestID,
                                               "unsupported bulk operation \(request.operation)")
        }
    }

    private func mappingTuple(_ payload: [String: String]?, prefix: String) -> (UInt64, Int)? {
        guard let payload,
              let a = payload["\(prefix)physical_address"],
              let l = payload["\(prefix)length"],
              let address = UInt64(a), let length = Int(l),
              length > 0, length <= Self.maximumBulkBytes,
              address <= UInt64.max - UInt64(length) else { return nil }
        return (address, length)
    }

    private func mapGuest(_ device: VZCustomVirtioDevice, address: UInt64,
                          length: Int) -> VZGuestMemoryMapping? {
        guard length > 0, length <= Self.maximumBulkBytes else { return nil }
        return device.guestMemoryMapping(atPhysicalAddress: address, length: length)
    }

    private func crc32(_ bytes: UnsafeRawBufferPointer) -> UInt32 {
        var crc: UInt32 = 0xffff_ffff
        for byte in bytes {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc >> 1) ^ ((crc & 1) == 1 ? 0xedb8_8320 : 0)
            }
        }
        return ~crc
    }

    private func fluxError(_ code: Int, _ message: String) -> NSError {
        NSError(domain: "fluxvm.virtio", code: code,
                userInfo: [NSLocalizedDescriptionKey: message])
    }
}

@available(macOS 27.0, *)
func fluxVMCustomVirtioConfigurationImpl(vmID: String) -> VZCustomVirtioDeviceConfiguration {
    let bus = FluxVirtioBus(vmID: vmID)
    // Provider/delegate references are weak. The runner owns this table for
    // exactly the lifetime of its one VM process.
    fluxVirtioBusKeepAlive[vmID] = bus
    return bus.configuration()
}
#endif
