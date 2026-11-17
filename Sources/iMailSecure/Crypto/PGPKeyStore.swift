// PGPKeyStore.swift
//
// Öffentliche OpenPGP-Schlüssel, die der Nutzer bewusst hinzugefügt hat.
// Gespeichert wird der armierte Schlüssel selbst (damit die Prüfung später
// unabhängig von der Quelle funktioniert) plus Fingerprint und User-ID.
//
// Ablage: Keychain, `ThisDeviceOnly`, kein iCloud-Sync. Öffentliche Schlüssel
// sind zwar nicht geheim, aber sie sind ein Vertrauensanker — sie sollen nicht
// unbemerkt über Geräte wandern. Ein Eintrag pro E-Mail-Adresse; ein neuer
// Import ersetzt den alten Schlüssel derselben Adresse.

import Foundation
import Security

/// Ein importierter öffentlicher Schlüssel.
struct StoredPGPKey: Codable, Equatable, Identifiable, Sendable {
    /// Normalisierte Adresse (klein, ohne Leerzeichen) — der Schlüssel des
    /// Eintrags in der Keychain.
    let email: String
    /// Primäre User-ID aus dem Schlüssel, falls vorhanden.
    let userID: String?
    /// Fingerprint des primären Schlüssels, Großbuchstaben-Hex.
    let fingerprint: String
    /// Armierter Schlüssel, unverändert wie importiert.
    let armored: String
    let addedAt: Date

    var id: String { email }

    /// Fingerprint in Vierergruppen für die Anzeige.
    var formattedFingerprint: String {
        PGPKeyInfo(fingerprint: fingerprint).formattedFingerprint
    }
}

enum PGPKeyStoreError: LocalizedError, Equatable {
    /// Kein Schlüssel für diese Adresse abgelegt.
    case notFound
    /// Die Adresse im Feld passt nicht zur User-ID des Schlüssels.
    case emailMismatch(keyEmail: String)
    /// Keychain meldet einen Fehler.
    case keychain(OSStatus)

    var errorDescription: String? {
        switch self {
        case .notFound:
            return String(localized: "Für diese Adresse ist kein öffentlicher Schlüssel hinterlegt.")
        case let .emailMismatch(keyEmail):
            return String(
                format: String(localized: "Dieser Schlüssel gehört zu %@, nicht zu der eingegebenen Adresse."),
                keyEmail
            )
        case .keychain:
            return String(localized: "Der Schlüssel konnte nicht gespeichert werden.")
        }
    }
}

final class PGPKeyStore {
    static let shared = PGPKeyStore()

    private let service = "io.imailsecure.pgpkeys"

    private init() {}

    // MARK: – Lesen

    /// Alle hinterlegten Schlüssel, nach Adresse sortiert.
    func keys() -> [StoredPGPKey] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll
        ]

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let items = result as? [Data] else {
            return []
        }

        let decoder = JSONDecoder()
        return items
            .compactMap { try? decoder.decode(StoredPGPKey.self, from: $0) }
            .sorted { $0.email < $1.email }
    }

    func key(forEmail email: String) -> StoredPGPKey? {
        keys().first { $0.email == Self.normalize(email) }
    }

    /// Wahr, wenn für diese Adresse ein Schlüssel liegt. Für die Anzeige in
    /// der Nachrichtenansicht, ohne den Schlüssel zu laden.
    func hasKey(forEmail email: String) -> Bool {
        key(forEmail: email) != nil
    }

    // MARK: – Schreiben

    /// Importiert einen öffentlichen Schlüssel für `email`.
    ///
    /// Geprüft wird gegen den Fingerprint aus der FFI, nicht gegen selbst
    /// geparste Bytes. Enthält die User-ID eine Adresse, muss sie zur
    /// eingegebenen passen — sonst wäre der Vertrauensanker falsch zugeordnet.
    @discardableResult
    func importKey(armored: Data, email: String) throws -> StoredPGPKey {
        let info = try PGP.parsePublicKey(armored)
        let normalizedEmail = Self.normalize(email)
        guard !normalizedEmail.isEmpty else {
            throw PGPKeyStoreError.emailMismatch(keyEmail: info.userID ?? "—")
        }

        if let keyEmail = Self.email(in: info.userID), keyEmail != normalizedEmail {
            throw PGPKeyStoreError.emailMismatch(keyEmail: keyEmail)
        }

        guard let armoredString = String(data: armored, encoding: .utf8) else {
            throw PGPError.invalidKey(detail: nil)
        }

        let record = StoredPGPKey(
            email: normalizedEmail,
            userID: info.userID,
            fingerprint: info.fingerprint,
            armored: armoredString,
            addedAt: Date()
        )
        let data = try JSONEncoder().encode(record)

        let baseQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: normalizedEmail,
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        ]

        let updateStatus = SecItemUpdate(baseQuery as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecItemNotFound {
            var addQuery = baseQuery
            addQuery.merge(attributes) { _, new in new }
            let addStatus = SecItemAdd(addQuery as CFDictionary, nil)
            guard addStatus == errSecSuccess else {
                throw PGPKeyStoreError.keychain(addStatus)
            }
        } else if updateStatus != errSecSuccess {
            throw PGPKeyStoreError.keychain(updateStatus)
        }

        return record
    }

    func remove(email: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: Self.normalize(email),
            kSecAttrSynchronizable as String: kCFBooleanFalse as Any
        ]
        let status = SecItemDelete(query as CFDictionary)
        if status == errSecItemNotFound {
            throw PGPKeyStoreError.notFound
        }
        guard status == errSecSuccess else {
            throw PGPKeyStoreError.keychain(status)
        }
    }

    // MARK: – Hilfen

    static func normalize(_ email: String) -> String {
        email.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Zieht die Adresse aus einer User-ID wie `Name <mail@example.org>`.
    /// Gibt `nil` zurück, wenn keine eindeutige Adresse enthalten ist.
    static func email(in userID: String?) -> String? {
        guard let userID else { return nil }
        guard let open = userID.firstIndex(of: "<"),
              let close = userID.firstIndex(of: ">"),
              open < close else {
            // Auch eine nackte Adresse ohne spitze Klammern ist gültig.
            let trimmed = normalize(userID)
            return trimmed.contains("@") ? trimmed : nil
        }
        let address = String(userID[userID.index(after: open)..<close])
        let normalized = normalize(address)
        return normalized.contains("@") ? normalized : nil
    }
}
