// PGPPrivateKeyStore.swift
//
// Geheime OpenPGP-Schlüssel für den Versand. Ein Eintrag pro normalisierter
// Adresse, damit ein Konto genau einen aktiven Signaturschlüssel hat.
//
// Ablage: Keychain, `WhenUnlockedThisDeviceOnly`, kein iCloud-Sync. Der
// armierte geheime Schlüssel und die dazugehörige Passphrase liegen in zwei
// getrennten Einträgen. Die Passphrase wird gebraucht, damit der Nutzer nicht
// bei jeder Mail danach gefragt wird; sie verlässt das Gerät nicht. Die
// Secure Enclave speichert nur P-256-Schlüssel und kommt für OpenPGP nicht in
// Frage — auch nicht für die Passphrase.
//
// Import und Entfernen laufen immer über diese Klasse. Es gibt keine
// Erzeugung neuer Schlüssel in der App: Der Nutzer bringt seinen eigenen
// Schlüssel mit und prüft den Fingerprint vor der Übernahme.

import Foundation
import Security

/// Ein importierter geheimer Schlüssel.
struct StoredPGPPrivateKey: Codable, Equatable, Identifiable, Sendable {
    /// Normalisierte Adresse — Schlüssel des Keychain-Eintrags.
    let email: String
    /// Primäre User-ID aus dem Schlüssel, falls vorhanden.
    let userID: String?
    /// Fingerprint des primären Schlüssels, Großbuchstaben-Hex.
    let fingerprint: String
    /// Armierter geheimer Schlüssel, wie importiert (passphrasegeschützt).
    let armored: String
    let addedAt: Date

    var id: String { email }

    var formattedFingerprint: String {
        PGPKeyInfo(fingerprint: fingerprint).formattedFingerprint
    }
}

enum PGPPrivateKeyStoreError: LocalizedError, Equatable {
    case notFound
    case emailMismatch(keyEmail: String)
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .notFound:
            return String(localized: "Für dieses Konto ist kein privater Schlüssel hinterlegt.")
        case let .emailMismatch(keyEmail):
            return String(
                format: String(localized: "Dieser Schlüssel gehört zu %@, nicht zu der eingegebenen Adresse."),
                keyEmail
            )
        case .keychain:
            return String(localized: "Der private Schlüssel konnte nicht gespeichert werden.")
        }
    }
}

final class PGPPrivateKeyStore {
    static let shared = PGPPrivateKeyStore()

    private let service = "io.imailsecure.pgpprivatekeys"
    private let passphraseService = "io.imailsecure.pgppassphrases"

    private init() {}

    // MARK: – Lesen

    func keys() -> [StoredPGPPrivateKey] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [Data] else { return [] }

        let decoder = JSONDecoder()
        return items
            .compactMap { try? decoder.decode(StoredPGPPrivateKey.self, from: $0) }
            .sorted { $0.email < $1.email }
    }

    func key(forEmail email: String) -> StoredPGPPrivateKey? {
        keys().first { $0.email == Self.normalize(email) }
    }

    func hasKey(forEmail email: String) -> Bool {
        key(forEmail: email) != nil
    }

    /// Die Passphrase liegt in einem eigenen Keychain-Eintrag — nie im
    /// Schlüssel Datensatz selbst und nie im UserDefaults.
    func passphrase(forEmail email: String) throws -> String {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: passphraseService,
            kSecAttrAccount as String: Self.normalize(email),
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else {
            throw PGPPrivateKeyStoreError.notFound
        }
        guard let passphrase = String(data: data, encoding: .utf8) else {
            throw PGPPrivateKeyStoreError.keychain(errSecDecode)
        }
        return passphrase
    }

    // MARK: – Schreiben

    /// Importiert einen geheimen Schlüssel. Die FFI prüft zuerst die
    /// Passphrase und liefert Fingerprint und User-ID — die App vertraut also
    /// nicht dem Text aus dem Importfeld.
    @discardableResult
    func importKey(
        armored: Data,
        passphrase: String,
        email: String
    ) throws -> StoredPGPPrivateKey {
        let info = try PGP.secretKeyInfo(armored, passphrase: passphrase)
        let normalizedEmail = Self.normalize(email)
        guard !normalizedEmail.isEmpty else {
            throw PGPPrivateKeyStoreError.emailMismatch(keyEmail: info.userID ?? "—")
        }
        if let keyEmail = PGPKeyStore.email(in: info.userID), keyEmail != normalizedEmail {
            throw PGPPrivateKeyStoreError.emailMismatch(keyEmail: keyEmail)
        }
        guard let armoredString = String(data: armored, encoding: .utf8) else {
            throw PGPError.invalidKey(detail: nil)
        }

        let record = StoredPGPPrivateKey(
            email: normalizedEmail,
            userID: info.userID,
            fingerprint: info.fingerprint,
            armored: armoredString,
            addedAt: Date()
        )
        try save(data: JSONEncoder().encode(record), service: service, account: normalizedEmail)
        do {
            try save(
                data: Data(passphrase.utf8),
                service: passphraseService,
                account: normalizedEmail
            )
        } catch {
            // Kein halber Import: Wenn die Passphrase nicht gespeichert wurde,
            // darf kein signierbarer Schlüssel ohne Passphrase zurückbleiben.
            try? deleteKeyOnly(email: normalizedEmail)
            throw error
        }
        return record
    }

    func remove(email: String) throws {
        let normalized = Self.normalize(email)
        let keyQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: normalized,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let status = SecItemDelete(keyQuery as CFDictionary)
        if status == errSecItemNotFound {
            throw PGPPrivateKeyStoreError.notFound
        }
        guard status == errSecSuccess else {
            throw PGPPrivateKeyStoreError.keychain(status)
        }
        let passphraseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: passphraseService,
            kSecAttrAccount as String: normalized,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        _ = SecItemDelete(passphraseQuery as CFDictionary)
    }

    // MARK: – Intern

    private func deleteKeyOnly(email: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: email,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw PGPPrivateKeyStoreError.keychain(status)
        }
    }

    private func save(data: Data, service: String, account: String) throws {
        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        ]
        let update = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if update == errSecItemNotFound {
            var add = baseQuery
            add.merge(attributes) { _, new in new }
            let status = SecItemAdd(add as CFDictionary, nil)
            guard status == errSecSuccess else {
                throw PGPPrivateKeyStoreError.keychain(status)
            }
        } else if update != errSecSuccess {
            throw PGPPrivateKeyStoreError.keychain(update)
        }
    }

    private static func normalize(_ email: String) -> String {
        PGPKeyStore.normalize(email)
    }
}
