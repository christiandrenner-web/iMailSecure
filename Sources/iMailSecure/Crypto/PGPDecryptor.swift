// PGPDecryptor.swift
//
// Leseseite von `multipart/encrypted` (RFC 3156): Der PGP-Block aus dem
// zweiten MIME-Teil wird mit einem der lokalen geheimen Schlüssel
// entschlüsselt. Die dabei gewonnene MIME-Einheit wird hier zerlegt — ohne
// Netzwerk, ohne dauerhaftes Speichern und ohne die Rohbytes in das
// Nachrichtenmodell zu schreiben.
//
// Wichtig: Es wird nie „irgendein" privater Schlüssel probiert und das Ergebnis
// als gültig ausgegeben. rpgp prüft beim Entschlüsseln den Session-Schlüssel;
// nur ein Treffer liefert Klartext. Danach wird, falls vorhanden, die innere
// Signatur mit demselben Prüfer bewertet wie bei einer nur signierten Mail.

import Foundation

// MARK: – Ergebnis

struct PGPDecryptedContent: Equatable {
    /// Klartext der inneren MIME-Einheit (Textteil, nicht HTML).
    var body: String
    var attachments: [EmailAttachment]
    /// Ergebnis der inneren Signaturprüfung; `.notSigned` bei reiner
    /// Verschlüsselung.
    var signatureStatus: PGPSignatureStatus
    /// Fingerprint des Schlüssels, mit dem der Block geöffnet wurde.
    var keyFingerprint: String?
}

enum PGPDecryptError: LocalizedError, Equatable {
    /// Die Nachricht trägt kein `multipart/encrypted`.
    case notEncrypted
    /// Der MIME-Aufbau oder der PGP-Block ist unbrauchbar.
    case malformedMessage
    /// Kein lokaler geheimer Schlüssel passt zu einem Empfänger.
    case noMatchingKey
    /// Kryptographischer Fehler (z. B. beschädigter Block).
    case failure(String?)

    var errorDescription: String? {
        switch self {
        case .notEncrypted:
            return String(localized: "Diese Nachricht ist nicht verschlüsselt.")
        case .malformedMessage:
            return String(localized: "Die verschlüsselte Nachricht ist beschädigt oder hat ein unbekanntes Format.")
        case .noMatchingKey:
            return String(localized: "Für diese Nachricht ist kein passender privater Schlüssel hinterlegt.")
        case .failure:
            return String(localized: "Die Nachricht konnte nicht entschlüsselt werden.")
        }
    }
}

// MARK: – Entschlüssler

enum PGPDecryptor {
    /// Ein Kandidat aus `PGPPrivateKeyStore`: Schlüssel, Passphrase und
    /// Fingerprint für die Anzeige. Der Store liefert beides getrennt.
    struct SecretCandidate {
        let key: Data
        let passphrase: String
        let fingerprint: String
    }

    /// Entschlüsselt die Rohbytes einer Nachricht.
    ///
    /// - Parameters:
    ///   - raw: vollständige RFC-822-Bytes aus `fetchRawMessage`
    ///   - secrets: alle lokalen geheimen Schlüssel
    ///   - senderEmail: für die Prüfung einer inneren Signatur
    ///   - publicKeys: Schlüsselbund für die innere Signaturprüfung
    static func decrypt(
        raw: Data,
        secrets: [SecretCandidate],
        senderEmail: String,
        publicKeys: [StoredPGPKey]
    ) -> Result<PGPDecryptedContent, PGPDecryptError> {
        guard PGPMIMEParser.isEncrypted(raw) else {
            return .failure(.notEncrypted)
        }
        guard let block = pgpBlock(in: raw) else {
            return .failure(.malformedMessage)
        }
        guard !secrets.isEmpty else {
            return .failure(.noMatchingKey)
        }

        var lastFailure: PGPDecryptError = .noMatchingKey
        for secret in secrets {
            let plain: Data
            do {
                plain = try PGP.decrypt(
                    block,
                    secretKey: secret.key,
                    passphrase: secret.passphrase
                )
            } catch let error as PGPError {
                // Falsche Passphrase oder fremder Schlüssel ist kein Ende:
                // Der nächste lokale Schlüssel könnte passen. Ein
                // beschädigter Block dagegen wird bei jedem Arrays versagen.
                if case .decryptionFailed(let detail) = error {
                    lastFailure = .failure(detail)
                }
                continue
            } catch {
                lastFailure = .failure(error.localizedDescription)
                continue
            }

            // Verschlüsselt wurde eine MIME-Einheit, nicht die ganze Mail.
            // Ist sie zusätzlich signiert, liegt eine multipart/signed-Einheit
            // ohne RFC-822-Kopf vor — genau das, was der Parser erwartet.
            let signed = PGPMIMEParser.signedEntity(in: plain)
            let content = signed?.signedDataCandidates.first ?? plain
            let decoded = decodeEntity(content)

            let status: PGPSignatureStatus
            if signed != nil {
                status = PGPSignatureVerifier.analyze(
                    raw: plain,
                    senderEmail: senderEmail,
                    keys: publicKeys
                )
            } else {
                status = .notSigned
            }

            return .success(PGPDecryptedContent(
                body: decoded.body,
                attachments: decoded.attachments,
                signatureStatus: status,
                keyFingerprint: secret.fingerprint
            ))
        }
        return .failure(lastFailure)
    }

    // MARK: – MIME-Aufbau

    /// Zieht aus `multipart/encrypted` den PGP-Block des zweiten Teils.
    private static func pgpBlock(in raw: Data) -> Data? {
        let bytes = [UInt8](raw)
        guard let (headers, bodyStart) = PGPMIMEParser.splitHeadersAndBody(bytes),
              let contentType = PGPMIMEParser.headerValue("content-type", in: headers),
              let parsed = PGPMIMEParser.parseContentType(contentType),
              parsed.type == "multipart/encrypted",
              let boundary = parsed.parameters["boundary"],
              let parts = PGPMIMEParser.splitParts(
                body: Array(bytes[bodyStart...]),
                boundary: boundary
              ),
              parts.count >= 2
        else { return nil }

        let payload = parts[1]
        guard let (partHeaders, partStart) = PGPMIMEParser.splitHeadersAndBody(payload) else {
            return nil
        }
        let encoding = PGPMIMEParser.headerValue(
            "content-transfer-encoding", in: partHeaders
        )
        let decoded = decodeTransfer(Data(payload[partStart...]), encoding: encoding)
        return armorOnly(decoded)
    }

    /// Die FFI verlangt, dass armierte Daten mit der Kopfzeile beginnen.
    /// MIME-Teile haben aber oft Leerzeilen oder eine menschliche Ankündigung
    /// davor. Bei binären Blöcken bleibt alles erhalten.
    private static func armorOnly(_ data: Data) -> Data? {
        let begin = "-----BEGIN PGP MESSAGE-----"
        let end = "-----END PGP MESSAGE-----"
        let text = String(decoding: data, as: UTF8.self)
        if let start = text.range(of: begin),
           let finish = text.range(of: end, range: start.upperBound..<text.endIndex) {
            return Data(text[start.lowerBound..<finish.upperBound].utf8)
        }
        // Binär: nur Zeilenenden am Rand entfernen, keine Bytes verändern.
        var bytes = [UInt8](data)
        while bytes.first == 0x0A || bytes.first == 0x0D { bytes.removeFirst() }
        while bytes.last == 0x0A || bytes.last == 0x0D { bytes.removeLast() }
        return bytes.isEmpty ? nil : Data(bytes)
    }

    // MARK: – Innere MIME-Einheit

    /// Zerlegt eine MIME-Einheit in Text und Anhänge. Genau die Fälle, die
    /// unsere eigenen Nachrichten erzeugen: `text/plain` und
    /// `multipart/mixed`. Quoted-printable wird für fremde Mails verstanden.
    private static func decodeEntity(
        _ data: Data,
        forceAttachment: Bool = false
    ) -> (body: String, attachments: [EmailAttachment]) {
        let bytes = [UInt8](data)
        guard let (headers, bodyStart) = PGPMIMEParser.splitHeadersAndBody(bytes),
              let contentTypeValue = PGPMIMEParser.headerValue("content-type", in: headers),
              let type = PGPMIMEParser.parseContentType(contentTypeValue)
        else {
            return (String(decoding: data, as: UTF8.self), [])
        }

        let payload = Data(bytes[bodyStart...])
        let encoding = PGPMIMEParser.headerValue("content-transfer-encoding", in: headers)

        if type.type.hasPrefix("multipart/"),
           let boundary = type.parameters["boundary"],
           let parts = PGPMIMEParser.splitParts(
             body: Array(payload),
             boundary: boundary
           ) {
            var body = ""
            var attachments: [EmailAttachment] = []
            for (index, part) in parts.enumerated() {
                // Der erste Teil ist der Nachrichtentext. Jeder weitere ist
                // ein Anhang — auch dann, wenn er text/plain ist. Ohne diese
                // Regel würde ein angehängtes .txt einfach im Text landen.
                let decoded = decodeEntity(Data(part), forceAttachment: index > 0)
                if index == 0, decoded.attachments.isEmpty {
                    body = decoded.body
                }
                attachments.append(contentsOf: decoded.attachments)
            }
            return (body, attachments)
        }

        let disposition = PGPMIMEParser.headerValue("content-disposition", in: headers)
        let declaredAttachment = disposition?.lowercased().hasPrefix("attachment") == true
        if !forceAttachment && !declaredAttachment, type.type.hasPrefix("text/") {
            let plain = decodeTransfer(payload, encoding: encoding)
            return (String(decoding: plain, as: UTF8.self), [])
        }

        let filename = parameter("filename", from: disposition)
            ?? parameter("name", from: contentTypeValue)
            ?? "Anhang"
        let attachment = EmailAttachment(
            filename: filename,
            mimeType: type.type,
            data: decodeTransfer(payload, encoding: encoding)
        )
        return ("", [attachment])
    }

    private static func parameter(_ name: String, from header: String?) -> String? {
        guard let header else { return nil }
        return PGPMIMEParser.parseContentType(header)?.parameters[name]
    }

    private static func decodeTransfer(_ data: Data, encoding: String?) -> Data {
        switch encoding?.lowercased().trimmingCharacters(in: .whitespaces) {
        case "base64":
            return Data(base64Encoded: data, options: .ignoreUnknownCharacters) ?? Data()
        case "quoted-printable":
            return decodeQuotedPrintable(data)
        default:
            return data
        }
    }

    private static func decodeQuotedPrintable(_ data: Data) -> Data {
        let bytes = [UInt8](data)
        var output: [UInt8] = []
        var index = 0
        while index < bytes.count {
            if bytes[index] == 0x3D { // '='
                if index + 2 < bytes.count,
                   let high = hex(bytes[index + 1]),
                   let low = hex(bytes[index + 2]) {
                    output.append(high << 4 | low)
                    index += 3
                    continue
                }
                // Weicher Zeilenumbruch: gehört nicht zum Text.
                if index + 1 < bytes.count, bytes[index + 1] == 0x0D {
                    index += 2
                    if index < bytes.count, bytes[index] == 0x0A { index += 1 }
                    continue
                }
                if index + 1 < bytes.count, bytes[index + 1] == 0x0A {
                    index += 2
                    continue
                }
            }
            output.append(bytes[index])
            index += 1
        }
        return Data(output)
    }

    private static func hex(_ byte: UInt8) -> UInt8? {
        switch byte {
        case 0x30...0x39: return byte - 0x30
        case 0x41...0x46: return byte - 0x41 + 10
        case 0x61...0x66: return byte - 0x61 + 10
        default: return nil
        }
    }
}
