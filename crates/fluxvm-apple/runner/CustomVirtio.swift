// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// macOS 27 custom Virtio device implementation for Linux guests.
// Queue 0 is a request/response control queue. Queue 1 is reserved for future
// bulk/zero-copy operations. Requests are JSON FluxVirtioRequest frames in the
// readable descriptors and responses are written to the writable descriptors.
#if os(macOS)
import Foundation
import Virtualization

@available(macOS 27.0, *)
private var fluxVirtioBusKeepAlive: [String: FluxVirtioBus] = [:]

@available(macOS 27.0, *)
final class FluxVirtioBus: NSObject, VZCustomVirtioDeviceConfigurationDelegate, VZCustomVirtioDeviceDelegate {
    static let deviceID: UInt16 = 0xFF00
    static let controlQueue: UInt16 = 0
    static let bulkQueue: UInt16 = 1

    private let vmID: String
    private let deviceQueue: DispatchQueue
    private var device: VZCustomVirtioDevice?
    private var requestCount: UInt64 = 0
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
                    let requestID = "unknown"
                    let reply = FluxVirtioProtocol.failure(requestID: requestID,
                                                           error.localizedDescription)
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
        guard queueIndex == Self.controlQueue else {
            // Queue 1 is intentionally reserved. Returning the chain without
            // writing makes unsupported bulk operations fail closed.
            throw NSError(domain: "fluxvm.virtio", code: 10,
                          userInfo: [NSLocalizedDescriptionKey: "bulk queue is not enabled yet"])
        }
        let available = element.readBuffersAvailableByteCount
        guard available > 0, available <= FluxVirtioProtocol.maximumFrameBytes else {
            throw NSError(domain: "fluxvm.virtio", code: 11,
                          userInfo: [NSLocalizedDescriptionKey: "invalid request size \(available)"])
        }

        // Read guest-controlled memory exactly once. Apple's API warns against
        // repeated reads because the guest can mutate descriptors concurrently.
        let requestData = try element.readBytes(withExactLength: available)
        let request = try FluxVirtioProtocol.decodeRequest(requestData)
        requestCount &+= 1
        let response = handle(request, device: device)
        let responseData = try FluxVirtioProtocol.encode(response)
        guard responseData.count <= element.writeBuffersAvailableByteCount else {
            throw NSError(domain: "fluxvm.virtio", code: 12,
                          userInfo: [NSLocalizedDescriptionKey: "guest response buffer is too small"])
        }
        try element.write(responseData)
    }

    private func handle(_ request: FluxVirtioRequest,
                        device: VZCustomVirtioDevice) -> FluxVirtioResponse {
        switch request.operation {
        case "ping":
            return FluxVirtioProtocol.success(request, payload: [
                "reply": "pong",
                "vm_id": vmID,
            ])
        case "echo":
            return FluxVirtioProtocol.success(request, payload: request.payload ?? [:])
        case "capabilities":
            return FluxVirtioProtocol.success(request, payload: [
                "protocol": "1",
                "queues": "2",
                "control_queue": "0",
                "bulk_queue": "1",
                "guest_memory_mapping": "true",
            ])
        case "stats":
            return FluxVirtioProtocol.success(request, payload: [
                "requests": String(requestCount),
                "errors": String(errorCount),
            ])
        case "map-probe":
            guard let payload = request.payload,
                  let rawAddress = payload["physical_address"],
                  let rawLength = payload["length"],
                  let address = UInt64(rawAddress),
                  let length = Int(rawLength),
                  length > 0, length <= 16 * 1024 * 1024 else {
                return FluxVirtioProtocol.failure(requestID: request.requestID,
                                                   "map-probe needs physical_address and length <= 16 MiB")
            }
            // Probe only; never expose a host pointer to guest-controlled code.
            let mapped = device.guestMemoryMapping(atPhysicalAddress: address, length: length) != nil
            return FluxVirtioProtocol.success(request, payload: ["mapped": String(mapped)])
        default:
            return FluxVirtioProtocol.failure(requestID: request.requestID,
                                               "unsupported operation \(request.operation)")
        }
    }
}

@available(macOS 27.0, *)
func fluxVMCustomVirtioConfigurationImpl(vmID: String) -> VZCustomVirtioDeviceConfiguration {
    let bus = FluxVirtioBus(vmID: vmID)
    // The provider and VZ device use weak delegate references, so retain the
    // implementation for the lifetime of this runner/VM.
    fluxVirtioBusKeepAlive[vmID] = bus
    return bus.configuration()
}
#endif
