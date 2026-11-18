// PGPMIMEBuilder.swift
//
// Baut die Roh-RFC-822-Nachricht für `multipart/signed` (RFC 3156). Der
// erste Teil wird als Bytefolge erzeugt und genau so signiert, wie er später
// auf dem Server liegt — inklusive seiner MIME-Kopfzeilen und mit CRLF als
// Zeilenende. Danach wird nur die Grenzlinie angehängt.
//
// Der Text wird base64-kodiert, damit die Nachricht auch dann rein ASCII ist,
// wenn der SMTP-Server kein 8BITMIME anbietet. Anhänge kommen in einen
// `multipart/mixed`-Teil und sind damit ebenfalls von der Signatur umfasst.
//
// Hier wird keine Kryptographie ausgeführt und nichts gesendet; die Klasse
// ist deshalb ohne Netzwerk und ohne Keychain testbar.

import Foundation

enum PGPMIMEBuilder {
    /// Die Einheit, über die die Signatur gilt: der erste MIME-Teil ohne das
    /// Zeilenende vor der Grenzlinie. Kein abschließendes CRLF — genau das
    /// erwartet der Leser in `PGPMIMEParser.signedEntity`.
    static func signedEntity(for draft: EmailDraft) -> Data {
        var part = ""

        if draft.attachments.isEmpty {
            part += textPart(draft.body)
        } else {
            let boundary = "imailsecure-mixed-\(UUID().uuidString)"
            part += "Content-Type: multipart/mixed; boundary=\"\(boundary)\"\r\n"
            part += "\r\n"
            part += "This is a multipart message in MIME format.\r\n"
            part += "--\(boundary)\r\n"
            part += textPart(draft.body)
            part += "\r\n"

            for attachment in draft.attachments {
                let filename = quoted(clean(attachment.filename))
                let mimeType = quoted(clean(
                    attachment.mimeType.isEmpty ? "application/octet-stream" : attachment.mimeType
                ))
                part += "--\(boundary)\r\n"
                part += "Content-Type: \(mimeType); name=\"\(filename)\"\r\n"
                part += "Content-Transfer-Encoding: base64\r\n"
                part += "Content-Disposition: attachment; filename=\"\(filename)\"\r\n"
                part += "\r\n"
                part += base64Lines(attachment.data)
                part += "\r\n"
            }
            part += "--\(boundary)--"
        }

        return Data(part.utf8)
    }

    /// Setzt die vollständige Nachricht aus dem signierten Teil und der
    /// armorierten Signatur zusammen. Die Reihenfolge ist wichtig: Erst der
    /// signierte Teil, dann genau ein CRLF, dann die Grenzlinie.
    static func message(
        draft: EmailDraft,
        account: EmailAccount,
        signedEntity: Data,
        signature: Data
    ) -> Data {
        let boundary = "imailsecure-signed-\(UUID().uuidString)"
        var raw = ""

        raw += "From: \(fromHeader(account: account))\r\n"
        raw += "To: \(addressList(draft.to))\r\n"
        if !draft.cc.isEmpty {
            raw += "Cc: \(addressList(draft.cc))\r\n"
        }
        // BCC gehört in den SMTP-Umschlag, nicht in die Nachricht. Sonst würden
        // andere Empfänger die Blindkopie lesen — und die Signatur würde sie
        // auch noch bestätigen.
        raw += "Subject: \(encodedWords(draft.subject))\r\n"
        raw += "Date: \(rfc5322Date())\r\n"
        raw += "Message-ID: <\(UUID().uuidString)@\(messageIDDomain(account.email))>\r\n"
        if draft.requestMDN {
            raw += "Disposition-Notification-To: \(clean(account.email))\r\n"
            raw += "Disposition-Notification-Options: X-MDNSent-Type=displayed; x-unsupported-parameter=true\r\n"
        }
        if draft.requestReceipt {
            raw += "Return-Receipt-To: \(clean(account.email))\r\n"
        }
        raw += "MIME-Version: 1.0\r\n"
        raw += "Content-Type: multipart/signed; micalg=pgp-sha256; "
        raw += "protocol=\"application/pgp-signature\"; boundary=\"\(boundary)\"\r\n"
        raw += "\r\n"
        raw += "This is an OpenPGP/MIME signed message (RFC 3156)\r\n"
        raw += "--\(boundary)\r\n"
        raw += String(decoding: signedEntity, as: UTF8.self)
        raw += "\r\n--\(boundary)\r\n"
        raw += "Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n"
        raw += "Content-Description: OpenPGP digital signature\r\n"
        raw += "Content-Disposition: attachment; filename=\"signature.asc\"\r\n"
        raw += "\r\n"
        raw += crlfArmor(signature)
        raw += "--\(boundary)--\r\n"

        return Data(raw.utf8)
    }

    // MARK: – MIME-Teile

    private static func textPart(_ body: String) -> String {
        var part = "Content-Type: text/plain; charset=utf-8\r\n"
        part += "Content-Transfer-Encoding: base64\r\n"
        part += "\r\n"
        part += base64Lines(Data(body.utf8))
        return part
    }

    /// base64 in Zeilen à 76 Zeichen, wie RFC 2045 es verlangt. Ohne
    /// abschließendes Zeilenende — die Grenzlinie bringt es mit.
    private static func base64Lines(_ data: Data) -> String {
        let encoded = data.base64EncodedString()
        var lines: [String] = []
        var index = encoded.startIndex
        while index < encoded.endIndex {
            let end = encoded.index(index, offsetBy: 76, limitedBy: encoded.endIndex)
                ?? encoded.endIndex
            lines.append(String(encoded[index..<end]))
            index = end
        }
        return lines.joined(separator: "\r\n")
    }

    // MARK: – Kopfzeilen

    private static func fromHeader(account: EmailAccount) -> String {
        let address = "<\(clean(account.email))>"
        let name = clean(account.displayName)
        if name.isEmpty { return address }
        return "\(encodedWords(name)) \(address)"
    }

    private static func addressList(_ addresses: [EmailAddress]) -> String {
        addresses
            .map { clean($0.address) }
            .filter { !$0.isEmpty }
            .joined(separator: ", ")
    }

    /// RFC 2047Base64-Wörter, höchstens 60 Zeichen breit. Die Aufteilung
    /// erfolgt an Unicode-Skalaren, damit kein UTF-8-Zeichen zerrissen wird.
    private static func encodedWords(_ value: String) -> String {
        let cleaned = clean(value)
        guard !cleaned.isEmpty else { return "" }
        var words: [String] = []
        var chunk = ""
        var chunkBytes = 0
        for scalar in cleaned.unicodeScalars {
            let scalarString = String(scalar)
            let bytes = scalarString.utf8.count
            if chunkBytes + bytes > 45, !chunk.isEmpty {
                words.append(encodedWord(chunk))
                chunk = ""
                chunkBytes = 0
            }
            chunk += scalarString
            chunkBytes += bytes
        }
        if !chunk.isEmpty { words.append(encodedWord(chunk)) }
        return words.joined(separator: "\r\n ")
    }

    private static func encodedWord(_ value: String) -> String {
        "=?UTF-8?B?\(Data(value.utf8).base64EncodedString())?="
    }

    private static func rfc5322Date() -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss Z"
        return formatter.string(from: Date())
    }

    private static func messageIDDomain(_ email: String) -> String {
        guard let at = email.lastIndex(of: "@") else { return "imailsecure.invalid" }
        let domain = String(email[email.index(after: at)...])
        return domain.isEmpty ? "imailsecure.invalid" : clean(domain)
    }

    /// Verhindert Header-Injection durch Texte aus dem composer. Ein
    /// Zeilenende darf hier nie aus Nutzereingaben stammen.
    private static func clean(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
            .replacingOccurrences(of: "\0", with: "")
            .trimmingCharacters(in: .whitespaces)
    }

    private static func quoted(_ value: String) -> String {
        value
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
    }

    /// Armor aus rpgp kann LF oder CRLF liefern. Für die Grenzlinie brauchen
    /// wir verlässlich CRLF und genau ein Zeilenende nach dem letzten Block.
    private static func crlfArmor(_ signature: Data) -> String {
        var text = String(decoding: signature, as: UTF8.self)
        text = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .replacingOccurrences(of: "\r", with: "\n")
            .replacingOccurrences(of: "\n", with: "\r\n")
        if !text.hasSuffix("\r\n") { text += "\r\n" }
        return text
    }
}
