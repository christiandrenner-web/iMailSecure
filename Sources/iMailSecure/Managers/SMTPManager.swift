// SMTPManager.swift
import Foundation
import Logging
import SwiftMail

enum SMTPError: LocalizedError {
    case noPassword
    case invalidPGPConfiguration
    var errorDescription: String? {
        switch self {
        case .noPassword:
            return String(localized: "error.smtp.noPassword",
                          defaultValue: "Kein Passwort gespeichert. Bitte Konto bearbeiten.")
        case .invalidPGPConfiguration:
            return String(localized: "Der PGP-Versand wurde falsch konfiguriert.")
        }
    }
}

final class SMTPManager {
    private let account: EmailAccount
    private let logger = Logger(label: "io.imailsecure.smtp")

    init(account: EmailAccount) { self.account = account }

    /// Versendet einen Entwurf. Mit Signatur oder Verschlüsselung wird die
    /// vollständige RFC-822-Nachricht selbst gebaut und über `sendRawMessage`
    /// übertragen — SwiftMail baut sie sonst neu zusammen, womit sowohl
    /// Signatur als auch PGP-Block hinfällig wären.
    func sendEmail(
        draft: EmailDraft,
        sign: Bool = false,
        encrypt: Bool = false
    ) async throws {
        guard let password = account.password else { throw SMTPError.noPassword }
        #if DEBUG
        logger.debug("Sende Mail via \(account.smtpHost)")
        #endif

        let sender = SwiftMail.EmailAddress(name: account.displayName, address: account.email)
        let to = draft.to.map { SwiftMail.EmailAddress(name: $0.name ?? "", address: $0.address) }
        let cc = draft.cc.map { SwiftMail.EmailAddress(name: $0.name ?? "", address: $0.address) }
        let bcc = draft.bcc.map { SwiftMail.EmailAddress(name: $0.name ?? "", address: $0.address) }

        if sign || encrypt {
            let raw = try pgpRawMessage(draft: draft, sign: sign, encrypt: encrypt)
            try await withServer(password: password) { server in
                try await server.sendRawMessage(raw, from: sender, to: to + cc + bcc)
            }
            logger.info("PGP-Mail versendet (signiert: \(sign), verschlüsselt: \(encrypt))")
            return
        }

        // Anhänge als SwiftMail.Attachment Array aufbauen
        let attachments: [SwiftMail.Attachment] = draft.attachments.map { att in
            SwiftMail.Attachment(
                filename: att.filename,
                mimeType: att.mimeType,
                data: att.data
            )
        }

        // Email mit allen Parametern auf einmal erstellen
        var email = Email(
            sender: sender,
            recipients: to,
            subject: draft.subject,
            textBody: draft.body,
            attachments: attachments
        )

        email.ccRecipients = cc
        // Blindkopien gehören in den SMTP-Umschlag, aber nicht in die Mail.
        email.bccRecipients = bcc

        // MDN-Header
        var extraHeaders: [String: String] = [:]
        if draft.requestMDN {
            extraHeaders["Disposition-Notification-To"] = account.email
            extraHeaders["Disposition-Notification-Options"] =
                "X-MDNSent-Type=displayed; x-unsupported-parameter=true"
        }
        if draft.requestReceipt {
            extraHeaders["Return-Receipt-To"] = account.email
        }
        if !extraHeaders.isEmpty { email.additionalHeaders = extraHeaders }

        try await withServer(password: password) { server in
            try await server.sendEmail(email)
        }
        logger.info("Mail versendet (\(draft.attachments.count) Anhänge)")
    }

    // MARK: – PGP-Rohnachricht

    /// Baut die Nachricht für den Rohversand. Bei `sign && encrypt` wird
    /// zuerst signiert und dann die signierte MIME-Einheit verschlüsselt
    /// (sign-then-encrypt nach RFC 3156). Der Empfänger kann nach dem
    /// Entschlüsseln also dieselbe Signaturprüfung wie bei einer nur
    /// signierten Mail benutzen.
    func pgpRawMessage(
        draft: EmailDraft,
        sign: Bool,
        encrypt: Bool
    ) throws -> Data {
        let entity = PGPMIMEBuilder.signedEntity(for: draft)
        var payload = entity

        if sign {
            guard let privateKey = PGPPrivateKeyStore.shared.key(forEmail: account.email) else {
                throw PGPPrivateKeyStoreError.notFound
            }
            let passphrase = try PGPPrivateKeyStore.shared.passphrase(forEmail: account.email)
            let signature = try PGP.signDetached(
                entity,
                secretKey: Data(privateKey.armored.utf8),
                passphrase: passphrase
            )
            if encrypt {
                // Kein RFC-822-Kopf: verschlüsselt wird die MIME-Einheit.
                payload = PGPMIMEBuilder.signedBlockForEncryption(
                    signedEntity: entity,
                    signature: signature
                )
            } else {
                return PGPMIMEBuilder.message(
                    draft: draft,
                    account: account,
                    signedEntity: entity,
                    signature: signature
                )
            }
        }

        guard encrypt else {
            // Nur signiert ist oben zurückgekehrt; ohne beides ruft man diese
            // Methode nicht auf.
            throw SMTPError.invalidPGPConfiguration
        }

        // Auch Blindkopien müssen einen Schlüssel haben: Sie erhalten dieselbe
        // Nachricht und sollen sie lesen können.
        let recipients = draft.to + draft.cc + draft.bcc
        var publicKeys: [Data] = []
        publicKeys.reserveCapacity(recipients.count)
        for recipient in recipients {
            guard let key = PGPKeyStore.shared.key(forEmail: recipient.address) else {
                throw PGPEncryptionError.missingKey(recipient.address)
            }
            publicKeys.append(Data(key.armored.utf8))
        }
        let encrypted = try PGP.encrypt(payload, publicKeys: publicKeys)
        return PGPMIMEBuilder.encryptedMessage(
            draft: draft,
            account: account,
            encryptedEntity: encrypted
        )
    }

    // MARK: – Verbindung

    /// N2: TOFU-Fingerabdruck-Pinning muss VOR dem Verbindungsaufbau laufen,
    /// sonst ist der Handshake bereits durch. Die TLS-Schicht prüft zusätzlich
    /// Kette und Hostname; bei erzwungenem STARTTLS ohne Angebot bricht der
    /// Aufbau ab. N1/N2 – die Transport-Policy kommt aus der Kontoeinstellung,
    /// nie aus dem Port.
    private func withServer<T>(
        password: String,
        body: (SMTPServer) async throws -> T
    ) async throws -> T {
        let server = SMTPServer(
            host: account.smtpHost,
            port: account.smtpPort,
            transportSecurity: account.smtpSecurity.mailTransportSecurity
        )
        try await CertificatePinner.shared.verifyAndPin(
            host: account.smtpHost,
            port: account.smtpPort
        )
        try await server.connect()
        do {
            let result = try await body(server)
            try await server.disconnect()
            return result
        } catch {
            try? await server.disconnect()
            throw error
        }
    }
}
