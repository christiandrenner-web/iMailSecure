// PGP.swift
//
// Dünner Swift-Wrapper um die rpgp-FFI (`Crypto/pgp-ffi`, C-API in
// `imailpgp.h`). Hier endet Swift: `Data` hinein, Fingerprint oder
// Ja/Nein heraus. Die Kryptographie läuft ausschließlich in Rust; dieser
// Code reicht Bytes durch und übersetzt Rückgabecodes in Swift-Fehler.
//
// Nichts hier speichert Schlüssel oder Nachrichten. Der Schlüsselbund liegt
// darüber in `PGPKeyStore`.

import Foundation
import imailpgp

// MARK: – Statuscodes

/// Muss zu den `#define`s in `imailpgp.h` passen. Bewusst hier gespiegelt,
/// damit ein Leser beide Seiten vergleichen kann, ohne das andere Projekt
/// zu öffnen.
private enum PGPStatus {
    static let ok: Int32 = 1
    static let invalid: Int32 = 0
    static let badArgument: Int32 = -1
    static let parseError: Int32 = -2
    static let panic: Int32 = -3
}

// MARK: – Fehler

enum PGPError: LocalizedError, Equatable {
    /// Die Bytes sind kein OpenPGP-Schlüssel (oder der Schlüssel ist kaputt).
    case invalidKey(detail: String?)
    /// Die Signatur ließ sich nicht parsen — nicht zu verwechseln mit
    /// „Signatur ist falsch“, das ist ein reguläres `false`.
    case unreadableSignature(detail: String?)
    /// Alles andere aus der Bibliothek (Panic, zu kleiner Puffer …).
    case library(detail: String)

    var errorDescription: String? {
        switch self {
        case .invalidKey:
            return String(localized: "Das ist kein gültiger öffentlicher Schlüssel.")
        case .unreadableSignature:
            return String(localized: "Die Signatur konnte nicht gelesen werden.")
        case .library:
            return String(localized: "Die Kryptographie-Bibliothek meldet einen Fehler.")
        }
    }

    var failureReason: String? {
        switch self {
        case let .invalidKey(detail), let .unreadableSignature(detail):
            return detail.flatMap { $0.isEmpty ? nil : $0 }
        case let .library(detail):
            return detail.isEmpty ? nil : detail
        }
    }
}

// MARK: – Schlüsselinfo

/// Was die App über einen öffentlichen Schlüssel wissen muss, bevor sie ihn
/// anzeigt oder zum Verschlüsseln anbietet.
struct PGPKeyInfo: Equatable, Sendable {
    /// Primärer Fingerprint, Großbuchstaben-Hex ohne Trennzeichen.
    let fingerprint: String

    /// Fingerprint in Vierergruppen, wie ihn GnuPG und Schlüsselanhänger
    /// anzeigen: `D6F8 84A7 E63B E870 …`. Nur für die Darstellung.
    var formattedFingerprint: String {
        stride(from: 0, to: fingerprint.count, by: 4)
            .map { offset -> String in
                let start = fingerprint.index(fingerprint.startIndex, offsetBy: offset)
                let end = fingerprint.index(start, offsetBy: min(4, fingerprint.count - offset))
                return String(fingerprint[start..<end])
            }
            .joined(separator: " ")
    }

    /// Letzte 16 Zeichen — die „Key ID“, die Nutzer von anderen Programmen
    /// kennen. Nicht eindeutig genug zum Prüfen, aber gut zum Wiedererkennen.
    var shortIdentifier: String {
        String(fingerprint.suffix(16))
    }
}

// MARK: – Schnittstelle

enum PGP {
    /// Version der eingebundenen Bibliothek, z. B.
    /// `imailpgp 0.1.0 / rpgp 0.21.1`. Für die Diagnose in den Einstellungen.
    static var version: String {
        String(cString: imailpgp_version())
    }

    /// Prüft einen öffentlichen Schlüssel (armiert oder binär) und liefert
    /// seinen Fingerprint.
    static func parsePublicKey(_ data: Data) throws -> PGPKeyInfo {
        let status = withBytes(data) { bytes, count in
            imailpgp_parse_public_key(bytes, count)
        }
        switch status {
        case PGPStatus.ok:
            break
        case PGPStatus.badArgument:
            throw PGPError.invalidKey(detail: nil)
        default:
            throw PGPError.invalidKey(detail: lastError)
        }

        var output = [UInt8](repeating: 0, count: 128)
        let length = withBytes(data) { bytes, count in
            output.withUnsafeMutableBufferPointer { buffer in
                imailpgp_primary_fingerprint(bytes, count, buffer.baseAddress, buffer.count)
            }
        }
        guard length > 0 else {
            throw PGPError.invalidKey(detail: lastError)
        }
        let fingerprint = String(decoding: output[0..<Int(length)], as: UTF8.self)
        return PGPKeyInfo(fingerprint: fingerprint)
    }

    /// Prüft eine abgetrennte Signatur über `data`.
    ///
    /// - Returns: `true`, wenn die Signatur zu Daten und Schlüssel passt.
    ///   Eine falsche Signatur ist kein Fehler, sondern `false` — der
    ///   Unterschied zwischen „geprüft und falsch“ und „nicht prüfbar“ muss
    ///   in der Oberfläche sichtbar bleiben.
    static func verifyDetached(
        signature: Data,
        data: Data,
        publicKey: Data
    ) throws -> Bool {
        let status = withBytes(signature) { signatureBytes, signatureCount in
            withBytes(data) { dataBytes, dataCount in
                withBytes(publicKey) { keyBytes, keyCount in
                    imailpgp_verify_detached(
                        signatureBytes, signatureCount,
                        dataBytes, dataCount,
                        keyBytes, keyCount
                    )
                }
            }
        }

        switch status {
        case PGPStatus.ok:
            return true
        case PGPStatus.invalid:
            return false
        case PGPStatus.badArgument:
            throw PGPError.library(detail: lastError)
        default:
            // Parsen von Signatur und Schlüssel sind getrennte Schritte in
            // Rust; aus dem Code allein ist nicht ablesbar, was scheiterte.
            // Deshalb entscheidet die Fehlermeldung.
            let detail = lastError
            if detail.localizedCaseInsensitiveContains("schlüssel") {
                throw PGPError.invalidKey(detail: detail)
            }
            throw PGPError.unreadableSignature(detail: detail)
        }
    }

    // MARK: – Intern

    /// Letzte Fehlermeldung des aktuellen Threads. Leer, wenn kein Fehler.
    private static var lastError: String {
        String(cString: imailpgp_last_error())
    }

    /// Reicht `Data` als Zeiger weiter. Leere Daten sind zulässig (Signatur
    /// über eine leere Nachricht), dürfen aber keinen Null-Zeiger ergeben.
    private static func withBytes<T>(
        _ data: Data,
        _ body: (UnsafePointer<UInt8>, Int) throws -> T
    ) rethrows -> T {
        if data.isEmpty {
            var placeholder: UInt8 = 0
            return try withUnsafePointer(to: &placeholder) { pointer in
                try body(pointer, 0)
            }
        }
        return try data.withUnsafeBytes { raw in
            // `Data` ist bei nicht-leerem Inhalt immer belegt.
            try body(raw.bindMemory(to: UInt8.self).baseAddress!, raw.count)
        }
    }
}
