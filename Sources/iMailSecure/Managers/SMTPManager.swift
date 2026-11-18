// SMTPManager.swift
import Foundation
import Logging
import SwiftMail

enum SMTPError: LocalizedError {
    case noPassword
    var errorDescription: String? {
        String(localized: "error.smtp.noPassword",
               defaultValue: "Kein Passwort gespeichert. Bitte Konto bearbeiten.")
    }
}

final class SMTPManager {
    private let account: EmailAccount
    private let logger = Logger(label: "io.imailsecure.smtp")

    init(account: EmailAccount) { self.account = account }

    /// Versendet einen Entwurf. Mit `sign: true` wird vor dem Verbinden
    /// signiert und die vollständige RFC-822-Nachricht über `sendRawMessage`
    /// übertragen — SwiftMail baut in diesem Fall kein MIME neu zusammen,
    /// sonst wäre die Prüfsumme der Signatur hinfällig.
    func sendEmail(draft: EmailDraft, sign: Bool = false) async throws {
        guard let password = account.password else { throw SMTPError.noPassword }
        #if DEBUG
        logger.debug("Sende Mail via \(account.smtpHost)")
        #endif

        let sender = SwiftMail.EmailAddress(name: account.displayName, address: account.email)
        let to = draft.to.map { SwiftMail.EmailAddress(name: $0.name ?? "", address: $0.address) }
        let cc = draft.cc.map { SwiftMail.EmailAddress(name: $0.name ?? "", address: $0.address) }
        let bcc = draft.bcc.map { SwiftMail.EmailAddress(name: $0.name ?? "", address: $0.address) }

        if sign {
            guard let privateKey = PGPPrivateKeyStore.shared.key(forEmail: account.email) else {
                throw PGPPrivateKeyStoreError.notFound
            }
            let passphrase = try PGPPrivateKeyStore.shared.passphrase(forEmail: account.email)
            let entity = PGPMIMEBuilder.signedEntity(for: draft)
            let signature = try PGP.signDetached(
                entity,
                secretKey: Data(privateKey.armored.utf8),
                passphrase: passphrase
            )
            let raw = PGPMIMEBuilder.message(
                draft: draft,
                account: account,
                signedEntity: entity,
                signature: signature
            )

            try await withServer(password: password) { server in
                try await server.sendRawMessage(raw, from: sender, to: to + cc + bcc)
            }
            logger.info("Signierte Mail versendet")
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
