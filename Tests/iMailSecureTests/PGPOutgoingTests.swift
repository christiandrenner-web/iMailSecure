// PGPOutgoingTests.swift
//
// Gegenprobe zum ausgehenden Pfad: Die erzeugte Nachricht wird nicht nur
// angesehen, sondern mit genau dem Leser geprüft, der auch eingehende Mails
// bewertet. Damit ist sichergestellt, dass Sender und Empfänger dieselben
// Bytes signieren bzw. prüfen — der klassische PGP/MIME-Fehler.

import XCTest
@testable import iMailSecure

final class PGPOutgoingTests: XCTestCase {
    private let senderEmail = "signing@imailsecure.invalid"

    private var account: EmailAccount {
        EmailAccount(
            displayName: "Signatur Test",
            email: senderEmail,
            imapHost: "imap.example.com",
            imapPort: 993,
            smtpHost: "smtp.example.com",
            smtpPort: 587,
            username: senderEmail
        )
    }

    private func draft(subject: String = "Grüße aus der Testsuite") -> EmailDraft {
        var draft = EmailDraft()
        draft.toText = "empfaenger@example.org"
        draft.subject = subject
        draft.body = "Hallo,\n\nGrüße mit Umlauten: ü, ä, ß.\n"
        draft.requestMDN = true
        return draft
    }

    private func sign(_ entity: Data) throws -> Data {
        try PGP.signDetached(
            entity,
            secretKey: Data(PGPFixtures.privateKey.utf8),
            passphrase: PGPFixtures.privateKeyPassphrase
        )
    }

    private var publicKeyRecord: StoredPGPKey {
        StoredPGPKey(
            email: senderEmail,
            userID: "iMail Secure Signing <signing@imailsecure.invalid>",
            fingerprint: PGPFixtures.privateKeyFingerprint,
            armored: PGPFixtures.privateKeyPublicKey,
            addedAt: Date()
        )
    }

    private func signedMessage(_ draft: EmailDraft) throws -> Data {
        let entity = PGPMIMEBuilder.signedEntity(for: draft)
        let signature = try sign(entity)
        return PGPMIMEBuilder.message(
            draft: draft,
            account: account,
            signedEntity: entity,
            signature: signature
        )
    }

    // MARK: – Tests

    func testSignedMessageVerifiesWithTheIncomingParser() throws {
        let draft = draft()
        let entity = PGPMIMEBuilder.signedEntity(for: draft)
        let raw = try signedMessage(draft)

        let parsed = try XCTUnwrap(PGPMIMEParser.signedEntity(in: raw))
        XCTAssertTrue(
            parsed.signedDataCandidates.contains(entity),
            "Der Parser muss genau die signierten Bytes wiederfinden"
        )
        let status = PGPSignatureVerifier.analyze(
            raw: raw,
            senderEmail: senderEmail,
            keys: [publicKeyRecord]
        )
        guard case let .valid(key) = status else {
            return XCTFail("Signatur müsste gültig sein, war \(status)")
        }
        XCTAssertEqual(key.fingerprint, PGPFixtures.privateKeyFingerprint)
    }

    func testChangingTheBodyInvalidatesTheSignature() throws {
        let raw = try signedMessage(draft())
        let text = String(decoding: raw, as: UTF8.self)
        // Der Text liegt base64-kodiert in der Nachricht — ein Zeichen in der
        // Kodierung reicht, um die Prüfsumme zu zerstören.
        let encoded = Data("Hallo,\n\nGrüße mit Umlauten: ü, ä, ß.\n".utf8).base64EncodedString()
        let changed = encoded.first == "Q" ? "R" : "Q"
        let tampered = text.replacingOccurrences(
            of: encoded,
            with: changed + encoded.dropFirst()
        )
        XCTAssertNotEqual(tampered, text)

        let status = PGPSignatureVerifier.analyze(
            raw: Data(tampered.utf8),
            senderEmail: senderEmail,
            keys: [publicKeyRecord]
        )
        guard case .invalid = status else {
            return XCTFail("Veränderter Text muss als ungültig gelten, war \(status)")
        }
    }

    func testAttachmentsAreCoveredByTheSignature() throws {
        var withAttachment = draft()
        withAttachment.attachments = [
            EmailAttachment(
                filename: "notizen.txt",
                mimeType: "text/plain",
                data: Data("Geheimer Anhang".utf8)
            )
        ]
        let raw = try signedMessage(withAttachment)
        let text = String(decoding: raw, as: UTF8.self)
        XCTAssertTrue(text.contains("filename=\"notizen.txt\""))
        XCTAssertTrue(text.contains("Content-Type: multipart/mixed"))

        let valid = PGPSignatureVerifier.analyze(
            raw: raw,
            senderEmail: senderEmail,
            keys: [publicKeyRecord]
        )
        guard case .valid = valid else {
            return XCTFail("Signatur mit Anhang müsste gültig sein, war \(valid)")
        }

        let encoded = Data("Geheimer Anhang".utf8).base64EncodedString()
        let changed = encoded.first == "Q" ? "R" : "Q"
        let altered = text.replacingOccurrences(
            of: encoded,
            with: changed + encoded.dropFirst()
        )
        XCTAssertNotEqual(altered, text)
        let invalid = PGPSignatureVerifier.analyze(
            raw: Data(altered.utf8),
            senderEmail: senderEmail,
            keys: [publicKeyRecord]
        )
        guard case .invalid = invalid else {
            return XCTFail("Veränderter Anhang muss als ungültig gelten, war \(invalid)")
        }
    }

    func testHeaderInjectionFromTheComposerIsNeutralized() throws {
        let hostile = draft(
            subject: "Wichtig\r\nBcc: heimlich@example.invalid"
        )
        let raw = try signedMessage(hostile)
        let bytes = [UInt8](raw)
        let headers = try XCTUnwrap(PGPMIMEParser.splitHeadersAndBody(bytes)).headers

        XCTAssertNil(PGPMIMEParser.headerValue("bcc", in: headers))
        XCTAssertTrue(PGPMIMEParser.headerValue("subject", in: headers)?
            .contains("=?UTF-8?B?") == true)
    }

    func testAllLinesFitIntoSMTPLimits() throws {
        var longBody = draft()
        longBody.body = String(repeating: "Sehr langer Text mit Umlauten ü. ", count: 200)
        longBody.attachments = [
            EmailAttachment(
                filename: "daten.bin",
                mimeType: "application/octet-stream",
                data: Data((0..<4096).map { UInt8($0 % 251) })
            )
        ]
        let text = String(decoding: try signedMessage(longBody), as: UTF8.self)
        let lines = text
            .replacingOccurrences(of: "\r\n", with: "\n")
            .split(separator: "\n")
        XCTAssertTrue(lines.allSatisfy { $0.utf8.count <= 998 })
    }

    func testWrongPassphraseCannotProduceASignature() {
        XCTAssertThrowsError(
            try PGP.signDetached(
                Data("Test".utf8),
                secretKey: Data(PGPFixtures.privateKey.utf8),
                passphrase: "falsch"
            )
        ) { error in
            guard case PGPError.wrongPassphrase = error else {
                return XCTFail("erwartet wrongPassphrase, war \(error)")
            }
        }
    }
}
