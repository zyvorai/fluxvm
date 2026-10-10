// Copyright 2026 Zyvor AI Labs · https://zyvor.dev
// SPDX-License-Identifier: Apache-2.0
//
// macOS 27 EFI Secure Boot for Linux guests, applied to the VM's EFI variable store (efi.bin) before boot.
import Foundation
import Security
import Virtualization

/// Readable text for Virtualization errors, including the macOS 27 provisioning and EFI codes.
func fluxVZErrorDescription(_ error: Error) -> String {
    let e = error as NSError
    guard e.domain == VZErrorDomain else { return e.localizedDescription }
    #if compiler(>=6.4)
    if #available(macOS 27.0, *), let code = VZError.Code(rawValue: e.code) {
        switch code {
        case .guestProvisioningInvalidFullName:
            return "macOS provisioning rejected the full name (\(e.localizedDescription))"
        case .guestProvisioningInvalidUsername:
            return "macOS provisioning rejected the username: use a short lowercase account name (\(e.localizedDescription))"
        case .guestProvisioningInvalidPassword:
            return "macOS provisioning rejected the password (\(e.localizedDescription))"
        case .efiSecureBootEnrollmentFailed:
            return "Secure Boot signatures could not be enrolled; check the KEK/db/dbx files (\(e.localizedDescription))"
        case .efiVariableInaccessible:
            return "the EFI variable store efi.bin cannot be accessed (\(e.localizedDescription))"
        default:
            break
        }
    }
    #endif
    return e.localizedDescription
}

/// A DER or PEM encoded X.509 certificate.
func fluxLoadCertificate(_ path: String) throws -> SecCertificate {
    let raw = try Data(contentsOf: URL(fileURLWithPath: path))
    var der = raw
    if let text = String(data: raw, encoding: .utf8), text.contains("-----BEGIN CERTIFICATE-----") {
        let body = text.components(separatedBy: "\n")
            .filter { !$0.hasPrefix("-----") }
            .joined()
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard let decoded = Data(base64Encoded: body, options: .ignoreUnknownCharacters) else {
            throw NSError(domain: "fluxvm-vz", code: 3, userInfo: [NSLocalizedDescriptionKey: "\(path): bad PEM certificate"])
        }
        der = decoded
    }
    guard let cert = SecCertificateCreateWithData(nil, der as CFData) else {
        throw NSError(domain: "fluxvm-vz", code: 3, userInfo: [NSLocalizedDescriptionKey: "\(path): not an X.509 certificate"])
    }
    return cert
}

extension Runner {
    /// Brings `store` to the Secure Boot state the config asks for. `secure_boot` nil leaves the store untouched.
    func configureSecureBoot(_ store: VZEFIVariableStore) throws {
        guard let wanted = cfg.secure_boot, !dryRun else { return }
        #if compiler(>=6.4)
        guard #available(macOS 27.0, *) else {
            if wanted { throw modernError("EFI Secure Boot needs a macOS 27+ host") }
            return
        }
        do {
            if cfg.secure_boot_reset == true { try store.resetSecureBoot() }
            guard wanted else {
                if try store.isSecureBootEnabled { try store.disableSecureBoot() }
                emit(["event": "secure-boot", "enabled": false])
                return
            }
            if cfg.secure_boot_default_signatures ?? true { try store.enrollDefaultSecureBootSignatures() }
            let lists = { (paths: [String]?) throws -> [VZEFISignatureList] in
                try (paths ?? []).map { try VZEFISignatureList(contentsOf: URL(fileURLWithPath: $0)) }
            }
            let kek = try lists(cfg.secure_boot_kek), db = try lists(cfg.secure_boot_db), dbx = try lists(cfg.secure_boot_dbx)
            if !kek.isEmpty || !db.isEmpty || !dbx.isEmpty {
                try store.enrollSecureBootSignatures(
                    VZEFISignatureDatabaseConfiguration(keyExchangeKeys: kek, dbSignatures: db, dbxSignatures: dbx))
            }
            // An explicit platform key is (re)applied on every boot; the Apple-managed key only when Secure Boot is off.
            if let pk = cfg.secure_boot_platform_key {
                try store.enableSecureBoot(platformKey: try fluxLoadCertificate(pk))
            } else if try !store.isSecureBootEnabled {
                try store.enableSecureBootUsingDefaultPlatformKey()
            }
            emit(["event": "secure-boot", "enabled": try store.isSecureBootEnabled])
        } catch {
            throw modernError("EFI Secure Boot: \(fluxVZErrorDescription(error))")
        }
        #else
        if wanted { throw modernError("EFI Secure Boot needs a runner built with the macOS 27 SDK") }
        #endif
    }

    /// `secure-boot-status`: whether Secure Boot is on and how many signatures each database holds. While the VM
    /// runs, the store is locked, so the answer is the state read just before it started (`"as_of": "boot"`).
    func secureBootStatus() -> [String: Any] {
        #if compiler(>=6.4)
        guard #available(macOS 27.0, *) else { return ["ok": false, "error": "EFI Secure Boot needs a macOS 27+ host"] }
        guard let store = (lastConfiguration?.bootLoader as? VZEFIBootLoader)?.variableStore else {
            return ["ok": false, "error": "this VM does not boot through EFI"]
        }
        if let vm, vm.state != .stopped, vm.state != .error, var cached = secureBootAtBoot {
            cached["as_of"] = "boot"
            return cached
        }
        return readSecureBoot(store)
        #else
        return ["ok": false, "error": "EFI Secure Boot needs a runner built with the macOS 27 SDK"]
        #endif
    }

    func readSecureBoot(_ store: VZEFIVariableStore) -> [String: Any] {
        #if compiler(>=6.4)
        guard #available(macOS 27.0, *) else { return ["ok": false, "error": "EFI Secure Boot needs a macOS 27+ host"] }
        do {
            let sigs = try store.enrolledSecureBootSignatures
            func count(_ l: [VZEFISignatureList]) -> Int { l.reduce(0) { $0 + $1.signatures.count } }
            return ["ok": true, "enabled": try store.isSecureBootEnabled,
                    "kek": count(sigs.keyExchangeKeys), "db": count(sigs.dbSignatures), "dbx": count(sigs.dbxSignatures)]
        } catch {
            return ["ok": false, "error": fluxVZErrorDescription(error)]
        }
        #else
        return ["ok": false, "error": "EFI Secure Boot needs a runner built with the macOS 27 SDK"]
        #endif
    }
}
