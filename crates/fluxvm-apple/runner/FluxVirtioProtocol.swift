// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// Wire protocol for FluxVM's macOS 27 custom Virtio control device.
// Kept Foundation-only so the codec can be compiled and tested away from macOS.
import Foundation

struct FluxVirtioRequest: Codable {
    let version: UInt16
    let requestID: String
    let operation: String
    let payload: [String: String]?

    enum CodingKeys: String, CodingKey {
        case version
        case requestID = "request_id"
        case operation
        case payload
    }
}

struct FluxVirtioResponse: Codable {
    let version: UInt16
    let requestID: String
    let ok: Bool
    let payload: [String: String]?
    let error: String?

    enum CodingKeys: String, CodingKey {
        case version
        case requestID = "request_id"
        case ok, payload, error
    }
}

enum FluxVirtioProtocol {
    static let version: UInt16 = 1
    static let maximumFrameBytes = 1 << 20

    static func decodeRequest(_ data: Data) throws -> FluxVirtioRequest {
        guard !data.isEmpty, data.count <= maximumFrameBytes else {
            throw NSError(domain: "fluxvm.virtio.protocol", code: 1,
                          userInfo: [NSLocalizedDescriptionKey: "request frame must be 1..=1048576 bytes"])
        }
        let request = try JSONDecoder().decode(FluxVirtioRequest.self, from: data)
        guard request.version == version else {
            throw NSError(domain: "fluxvm.virtio.protocol", code: 2,
                          userInfo: [NSLocalizedDescriptionKey: "unsupported protocol version \(request.version)"])
        }
        guard !request.requestID.isEmpty, request.requestID.utf8.count <= 128 else {
            throw NSError(domain: "fluxvm.virtio.protocol", code: 3,
                          userInfo: [NSLocalizedDescriptionKey: "request_id must be 1..=128 bytes"])
        }
        guard !request.operation.isEmpty, request.operation.utf8.count <= 64 else {
            throw NSError(domain: "fluxvm.virtio.protocol", code: 4,
                          userInfo: [NSLocalizedDescriptionKey: "operation must be 1..=64 bytes"])
        }
        return request
    }

    static func encode(_ response: FluxVirtioResponse) throws -> Data {
        let data = try JSONEncoder().encode(response)
        guard data.count <= maximumFrameBytes else {
            throw NSError(domain: "fluxvm.virtio.protocol", code: 5,
                          userInfo: [NSLocalizedDescriptionKey: "response exceeds 1 MiB"])
        }
        return data
    }

    static func success(_ request: FluxVirtioRequest, payload: [String: String] = [:]) -> FluxVirtioResponse {
        FluxVirtioResponse(version: version, requestID: request.requestID, ok: true,
                           payload: payload, error: nil)
    }

    static func failure(requestID: String, _ message: String) -> FluxVirtioResponse {
        FluxVirtioResponse(version: version, requestID: requestID, ok: false,
                           payload: nil, error: message)
    }
}
