// AutocryptHeader.swift
//
// Autocrypt-Header (https://autocrypt.org/level1.html): Der Absender kann
// seinen öffentlichen Schlüssel im Kopf der Mail mitliefern. iMail Secure
// liest ihn, importiert aber nichts automatisch — der Nutzer sieht zuerst
// Adresse und Fingerprint und entscheidet selbst.
//
// Der Schlüssel wird ausschließlich aus dem Kopf der gerade geöffneten Mail
// genommen. Es gibt keine stillen Abfragen und keine Speicherung des
// Roh-Kopfes über die Nachricht hinaus.

import Foundation

struct AutocryptKey: Equatable, Sendable {
    /// Adresse aus dem `addr`-Parameter (nicht zwingend die Absenderadresse).
    let address: String
    /// Binärer öffentlicher Schlüssel aus `keydata`.
    let keyData: Data
}

enum AutocryptHeader {
    /// Liest `Autocrypt: addr=…; keydata=…` aus einem bereits entfalteten
    /// Header-Wert. `nil` bedeutet: kein brauchbarer Schlüssel enthalten.
    /// Unbekannte Parameter werden ignoriert, wie die Spezifikation verlangt.
    static func parse(_ value: String) -> AutocryptKey? {
        var address: String?
        var encodedKey: String?

        for piece in splitOutsideQuotes(value, separator: ";") {
            guard let equals = piece.firstIndex(of: "=") else { continue }
            let name = piece[..<equals]
                .trimmingCharacters(in: .whitespaces)
                .lowercased()
            var parameter = piece[piece.index(after: equals)...]
                .trimmingCharacters(in: .whitespaces)
            if parameter.count >= 2,
               parameter.hasPrefix("\""), parameter.hasSuffix("\"") {
                parameter = String(parameter.dropFirst().dropLast())
            }

            switch name {
            case "addr":
                address = String(parameter)
            case "keydata":
                encodedKey = String(parameter)
            default:
                break
            }
        }

        guard let address,
              PGPKeyStore.normalize(address).contains("@"),
              let encodedKey else { return nil }

        // Entfaltung durch den IMAP-Parser fügt an Zeilenumbrüchen Leerzeichen
        // ein; Base64 darf beliebige Whitespace-Zeichen enthalten.
        let compact = encodedKey.filter { !$0.isWhitespace }
        guard !compact.isEmpty,
              let keyData = Data(base64Encoded: compact, options: .ignoreUnknownCharacters),
              !keyData.isEmpty
        else { return nil }

        return AutocryptKey(address: PGPKeyStore.normalize(address), keyData: keyData)
    }

    private static func splitOutsideQuotes(_ value: String, separator: Character) -> [String] {
        var pieces: [String] = []
        var current = ""
        var inQuotes = false
        for character in value {
            if character == "\"" { inQuotes.toggle() }
            if character == separator, !inQuotes {
                pieces.append(current)
                current = ""
            } else {
                current.append(character)
            }
        }
        pieces.append(current)
        return pieces
    }
}
