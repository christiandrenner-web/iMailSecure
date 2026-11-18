// PGPSignature.swift
//
// PGP/MIME nach RFC 3156, Leseseite: eine Nachricht mit
// `multipart/signed` wird zerlegt, die Signatur über die *Rohbytes* des
// ersten Teils geprüft. Es wird nichts umgebaut, nichts nachparst und nichts
// gespeichert — die Bytes, die auf dem Server liegen, sind die Prüfgrundlage.
//
// Wichtig: Die Grenzlinie zwischen Teil und `--boundary` gehört laut RFC 2046
// zur Grenze, nicht zum Teil. Beim Extrahieren fällt deshalb genau ein
// Zeilenende weg. Genau daran scheitern naive Prüfungen, weil Sender und
// Empfänger sich uneinig sind, ob der letzte Zeilenumbruch dazugehört. Beide
// Varianten werden geprüft; sie unterscheiden sich nur in einem Zeilenende,
// nie im Inhalt.
//
// Nicht hier: Entschlüsselung (`multipart/encrypted`) und das Senden.

import Foundation

// MARK: – Zustand einer Nachricht

/// Wird beim Sync aus der MIME-Struktur erkannt. Bestimmt, ob die
/// Detailansicht die Rohbytes nachlädt, um die Signatur zu prüfen.
enum PGPMessageState: String, Equatable, Sendable {
    case none
    case signed
    case encrypted
}

// MARK: – Ergebnis der Prüfung

enum PGPSignatureStatus: Equatable, Sendable {
    /// Kein `multipart/signed` — es gibt nichts zu prüfen.
    case notSigned
    /// Verschlüsselt; ohne Entschlüsselung nicht prüfbar.
    case encrypted
    /// Signatur passt zu Daten und Schlüssel.
    case valid(StoredPGPKey)
    /// Signatur und Daten passen nicht zusammen. Immer ein Alarm.
    case invalid
    /// Signatur vorhanden, aber der passende Schlüssel fehlt lokal.
    case unknownKey(issuer: String?, senderEmail: String)
    /// Technischer Fehler (Netz, IMAP, Bibliothek).
    case failed(String)
}

// MARK: – Prüfung

enum PGPSignatureVerifier {
    /// Prüft eine rohe RFC-822-Nachricht gegen die lokal hinterlegten
    /// Schlüssel. `keys` wird übergeben, damit die Funktion ohne Keychain
    /// testbar bleibt.
    static func analyze(
        raw: Data,
        senderEmail: String,
        keys: [StoredPGPKey]
    ) -> PGPSignatureStatus {
        guard let entity = PGPMIMEParser.signedEntity(in: raw) else {
            return PGPMIMEParser.isEncrypted(raw) ? .encrypted : .notSigned
        }

        // Der Aussteller ist nur ein Hinweis. Fehlt er, bleibt der Absender
        // als plausibelste Zuordnung — mehr nicht.
        let issuer = try? PGP.signatureIssuer(in: entity.signature)
        let normalizedSender = PGPKeyStore.normalize(senderEmail)

        let candidates: [StoredPGPKey]
        if let issuer, !issuer.isEmpty {
            candidates = keys.filter { key in
                let fingerprint = key.fingerprint.uppercased()
                return fingerprint == issuer || fingerprint.hasSuffix(issuer)
            }
            if candidates.isEmpty {
                return .unknownKey(issuer: issuer, senderEmail: normalizedSender)
            }
        } else {
            candidates = keys.filter { $0.email == normalizedSender }
            if candidates.isEmpty {
                return .unknownKey(issuer: nil, senderEmail: normalizedSender)
            }
        }

        for key in candidates {
            let keyData = Data(key.armored.utf8)
            for candidate in entity.signedDataCandidates {
                do {
                    if try PGP.verifyDetached(
                        signature: entity.signature,
                        data: candidate,
                        publicKey: keyData
                    ) {
                        return .valid(key)
                    }
                } catch {
                    return .failed(error.localizedDescription)
                }
            }
        }
        return .invalid
    }
}

// MARK: – MIME

enum PGPMIMEParser {
    struct SignedEntity {
        /// Signatur als armierter Text (oder binär, wenn so geliefert).
        let signature: Data
        /// Mögliche Fassungen der signierten Bytes. Sie unterscheiden sich
        /// höchstens um ein abschließendes CRLF.
        let signedDataCandidates: [Data]
    }

    /// Liefert die signierte Einheit, wenn die Nachricht `multipart/signed`
    /// mit `protocol="application/pgp-signature"` ist. Sonst `nil`.
    static func signedEntity(in raw: Data) -> SignedEntity? {
        let bytes = [UInt8](raw)
        guard let (headers, bodyStart) = splitHeadersAndBody(bytes),
              let contentType = headerValue("content-type", in: headers),
              let parsed = parseContentType(contentType),
              parsed.type == "multipart/signed",
              let boundary = parsed.parameters["boundary"],
              !boundary.isEmpty
        else { return nil }

        let protocolValue = parsed.parameters["protocol"]?.lowercased() ?? ""
        if !protocolValue.isEmpty, !protocolValue.contains("pgp-signature") {
            // S/MIME oder anderes: nicht unsere Baustelle.
            return nil
        }

        let body = Array(bytes[bodyStart...])
        guard let parts = splitParts(body: body, boundary: boundary), parts.count >= 2 else {
            return nil
        }

        guard let signature = signaturePayload(from: parts[1]) else { return nil }

        let signed = parts[0]
        var candidates = [normalizeToCRLF(signed)]
        // Zweite Fassung mit abschließendem CRLF, siehe Kopfkommentar.
        var withTrailing = candidates[0]
        withTrailing.append(contentsOf: [0x0D, 0x0A])
        candidates.append(withTrailing)

        return SignedEntity(signature: signature, signedDataCandidates: candidates)
    }

    /// Erkennt `multipart/encrypted` (RFC 3156) am Kopf der Nachricht.
    static func isEncrypted(_ raw: Data) -> Bool {
        let bytes = [UInt8](raw)
        guard let (headers, _) = splitHeadersAndBody(bytes),
              let contentType = headerValue("content-type", in: headers),
              let parsed = parseContentType(contentType)
        else { return false }
        return parsed.type == "multipart/encrypted"
            && (parsed.parameters["protocol"]?.lowercased().contains("pgp-encrypted") ?? true)
    }

    // MARK: – Zerlegen

    /// Teilt in Kopfblock und Rumpf. Toleriert CRLF und LF.
    static func splitHeadersAndBody(_ bytes: [UInt8]) -> (headers: String, bodyStart: Int)? {
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x0A {
                if index + 1 < bytes.count, bytes[index + 1] == 0x0A {
                    return (decode(bytes[0..<index]), index + 2)
                }
                if index + 2 < bytes.count, bytes[index + 1] == 0x0D, bytes[index + 2] == 0x0A {
                    return (decode(bytes[0..<index]), index + 3)
                }
            }
            index += 1
        }
        return nil
    }

    /// Wert eines Kopfzeilenfelds, case-insensitiv, mit Entfaltung.
    static func headerValue(_ name: String, in headerBlock: String) -> String? {
        // Swift sieht "\r\n" als *ein* Zeichen; `split(separator: "\n")` würde
        // CRLF-Zeilen deshalb nicht trennen. Erst vereinheitlichen.
        let normalized = headerBlock
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
        var currentName: String?
        var currentValue = ""
        var found: String?

        func flush() {
            guard let currentName, found == nil else { return }
            if currentName == name {
                found = currentValue.trimmingCharacters(in: .whitespaces)
            }
        }

        for line in normalized.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = String(line)
            if line.hasPrefix(" ") || line.hasPrefix("\t") {
                // Fortsetzungszeile
                currentValue += " " + line.trimmingCharacters(in: .whitespaces)
                continue
            }
            flush()
            guard let colon = line.firstIndex(of: ":") else {
                currentName = nil
                currentValue = ""
                continue
            }
            currentName = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            currentValue = String(line[line.index(after: colon)...])
        }
        flush()
        return found
    }

    /// `multipart/signed; protocol="…"; boundary="…"` → Typ und Parameter.
    static func parseContentType(_ value: String) -> (type: String, parameters: [String: String])? {
        let pieces = splitOutsideQuotes(value, separator: ";")
        guard let first = pieces.first else { return nil }
        let type = first.trimmingCharacters(in: .whitespaces).lowercased()
        guard !type.isEmpty else { return nil }

        var parameters: [String: String] = [:]
        for piece in pieces.dropFirst() {
            guard let equals = piece.firstIndex(of: "=") else { continue }
            let name = piece[..<equals].trimmingCharacters(in: .whitespaces).lowercased()
            var raw = piece[piece.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            if raw.hasPrefix("\""), raw.hasSuffix("\""), raw.count >= 2 {
                raw = String(raw.dropFirst().dropLast())
            }
            if !name.isEmpty { parameters[name] = raw }
        }
        return (type, parameters)
    }

    /// Zerlegt einen Multipart-Rumpf an seinen Grenzlinien. Liefert die
    /// Teil-Bytes ohne das Zeilenende vor der jeweils nächsten Grenze.
    static func splitParts(body: [UInt8], boundary: String) -> [[UInt8]]? {
        let delimiter = "--" + boundary
        var parts: [[UInt8]] = []
        var openStart: Int?
        var index = 0

        while index <= body.count {
            var lineEnd = index
            while lineEnd < body.count, body[lineEnd] != 0x0A { lineEnd += 1 }
            let hasNewline = lineEnd < body.count
            var contentEnd = lineEnd
            if contentEnd > index, body[contentEnd - 1] == 0x0D { contentEnd -= 1 }
            let text = decode(body[index..<contentEnd]).trimmingCharacters(in: .whitespaces)
            let nextLine = hasNewline ? lineEnd + 1 : lineEnd

            if text == delimiter || text == delimiter + "--" {
                if let start = openStart {
                    var end = index
                    // Das CRLF/LF vor der Grenze gehört zur Grenze.
                    if end > start, body[end - 1] == 0x0A {
                        end -= 1
                        if end > start, body[end - 1] == 0x0D { end -= 1 }
                    }
                    parts.append(Array(body[start..<end]))
                    openStart = nil
                }
                if text == delimiter + "--" { break }
                openStart = nextLine
                index = nextLine
                continue
            }

            index = nextLine
            if !hasNewline { break }
        }

        return parts.isEmpty ? nil : parts
    }

    /// Rumpf eines Signaturteils — armierter Text oder base64.
    private static func signaturePayload(from part: [UInt8]) -> Data? {
        guard let (headers, bodyStart) = splitHeadersAndBody(part) else { return nil }
        var payload = Data(part[bodyStart...])
        let encoding = headerValue("content-transfer-encoding", in: headers)?.lowercased()
        if encoding == "base64" {
            guard let decoded = Data(base64Encoded: payload,
                                     options: .ignoreUnknownCharacters) else { return nil }
            payload = decoded
        }
        return payload.isEmpty ? nil : payload
    }

    // MARK: – Hilfen

    private static func decode(_ bytes: ArraySlice<UInt8>) -> String {
        String(decoding: bytes, as: UTF8.self)
    }

    /// Einheitliche Zeilenenden, damit die Prüfung nicht an LF-only-Zustellung
    /// scheitert. Textteile in MIME sind zeilenorientiert; Binärteile mit
    /// echten CR/LF-Bytes kommen in signierten Einheiten nicht vor.
    private static func normalizeToCRLF(_ bytes: [UInt8]) -> Data {
        var output: [UInt8] = []
        output.reserveCapacity(bytes.count + bytes.count / 16)
        var index = 0
        while index < bytes.count {
            let byte = bytes[index]
            if byte == 0x0D {
                if index + 1 < bytes.count, bytes[index + 1] == 0x0A {
                    output.append(contentsOf: [0x0D, 0x0A])
                    index += 2
                    continue
                }
                // Einzelnes CR: als CRLF behandeln.
                output.append(contentsOf: [0x0D, 0x0A])
                index += 1
                continue
            }
            if byte == 0x0A {
                output.append(contentsOf: [0x0D, 0x0A])
                index += 1
                continue
            }
            output.append(byte)
            index += 1
        }
        return Data(output)
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
