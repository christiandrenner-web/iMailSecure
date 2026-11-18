// PGPDecryptorTests.swift
//
// Gegenprobe zur Leseseite: Eine Nachricht wird mit dem ausgehenden Pfad
// gebaut und dann ausschließlich über den Entschlüssler wieder gelesen. Damit
// sind MIME-Aufbau, Schlüsselwahl, Signaturprüfung und Anhänge in einem Zug
// abgedeckt.

import XCTest
@testable import iMailSecure

final class PGPDecryptorTests: XCTestCase {
    private let email = "signing@imailsecure.invalid"

    private var account: EmailAccount {
        EmailAccount(
            displayName: "Entschlüsselungs-Test",
            email: email,
            imapHost: "imap.example.com",
            imapPort: 993,
            smtpHost: "smtp.example.com",
            smtpPort: 587,
            username: email
        )
    }

    private var draft: EmailDraft {
        var draft = EmailDraft()
        draft.toText = email
        draft.subject = "Vertraulich"
        draft.body = "Geheimer Text mit Umlauten: ü, ä, ß.\nZweite Zeile."
        return draft
    }

    private var secret: PGPDecryptor.SecretCandidate {
        PGPDecryptor.SecretCandidate(
            key: Data(PGPFixtures.privateKey.utf8),
            passphrase: PGPFixtures.privateKeyPassphrase,
            fingerprint: PGPFixtures.privateKeyFingerprint
        )
    }

    private var publicKeyRecord: StoredPGPKey {
        StoredPGPKey(
            email: email,
            userID: "iMail Secure Signing <signing@imailsecure.invalid>",
            fingerprint: PGPFixtures.privateKeyFingerprint,
            armored: PGPFixtures.privateKeyPublicKey,
            addedAt: Date()
        )
    }

    private func encryptedRaw(
        draft: EmailDraft,
        sign: Bool
    ) throws -> Data {
        let entity = PGPMIMEBuilder.signedEntity(for: draft)
        var payload = entity
        if sign {
            let signature = try PGP.signDetached(
                entity,
                secretKey: Data(PGPFixtures.privateKey.utf8),
                passphrase: PGPFixtures.privateKeyPassphrase
            )
            payload = PGPMIMEBuilder.signedBlockForEncryption(
                signedEntity: entity,
                signature: signature
            )
        }
        let encrypted = try PGP.encrypt(
            payload,
            publicKeys: [Data(PGPFixtures.privateKeyPublicKey.utf8)]
        )
        return PGPMIMEBuilder.encryptedMessage(
            draft: draft,
            account: account,
            encryptedEntity: encrypted
        )
    }

    private func decrypt(_ raw: Data) -> Result<PGPDecryptedContent, PGPDecryptError> {
        PGPDecryptor.decrypt(
            raw: raw,
            secrets: [secret],
            senderEmail: email,
            publicKeys: [publicKeyRecord]
        )
    }

    // MARK: – Tests

    func testDecryptsEncryptedMessage() throws {
        let raw = try encryptedRaw(draft: draft, sign: false)
        let content = try XCTUnwrap(decrypt(raw).get())

        XCTAssertEqual(content.body, draft.body)
        XCTAssertTrue(content.attachments.isEmpty)
        XCTAssertEqual(content.signatureStatus, .notSigned)
        XCTAssertEqual(content.keyFingerprint, PGPFixtures.privateKeyFingerprint)
    }

    func testDecryptsSignedAndEncryptedMessage() throws {
        let raw = try encryptedRaw(draft: draft, sign: true)
        let content = try XCTUnwrap(decrypt(raw).get())

        XCTAssertEqual(content.body, draft.body)
        guard case .valid(let key) = content.signatureStatus else {
            return XCTFail("Innere Signatur müsste gültig sein, war \(content.signatureStatus)")
        }
        XCTAssertEqual(key.fingerprint, PGPFixtures.privateKeyFingerprint)
    }

    func testDecryptsAttachments() throws {
        var withAttachment = draft
        withAttachment.attachments = [
            EmailAttachment(
                filename: "geheim.txt",
                mimeType: "text/plain",
                data: Data("Anhangsinhalt".utf8)
            )
        ]
        let raw = try encryptedRaw(draft: withAttachment, sign: false)
        let content = try XCTUnwrap(decrypt(raw).get())

        XCTAssertFalse(content.body.isEmpty)
        XCTAssertEqual(content.attachments.count, 1)
        XCTAssertEqual(content.attachments[0].filename, "geheim.txt")
        XCTAssertEqual(content.attachments[0].mimeType, "text/plain")
        XCTAssertEqual(content.attachments[0].data, Data("Anhangsinhalt".utf8))
    }

    func testForeignKeyCannotDecrypt() throws {
        // Verschlüsselt an einen Schlüssel, dessen geheimer Teil nicht in den
        // Fixtures liegt — der lokale Schlüssel darf nicht lesen.
        let entity = PGPMIMEBuilder.signedEntity(for: draft)
        let encrypted = try PGP.encrypt(
            entity,
            publicKeys: [Data(PGPFixtures.publicKey.utf8)]
        )
        let raw = PGPMIMEBuilder.encryptedMessage(
            draft: draft,
            account: account,
            encryptedEntity: encrypted
        )
        XCTAssertThrowsError(try decrypt(raw).get())
    }

    func testPlainMessageIsNotEncrypted() {
        let raw = PGPMIMEBuilder.message(
            draft: draft,
            account: account,
            signedEntity: PGPMIMEBuilder.signedEntity(for: draft),
            signature: Data()
        )
        XCTAssertThrowsError(try decrypt(raw).get()) { error in
            guard case PGPDecryptError.notEncrypted = error else {
                return XCTFail("erwartet notEncrypted, war \(error)")
            }
        }
    }

    func testWithoutLocalKeyItReportsMissingKey() throws {
        let raw = try encryptedRaw(draft: draft, sign: false)
        let result = PGPDecryptor.decrypt(
            raw: raw,
            secrets: [],
            senderEmail: email,
            publicKeys: [publicKeyRecord]
        )
        XCTAssertThrowsError(try result.get()) { error in
            guard case PGPDecryptError.noMatchingKey = error else {
                return XCTFail("erwartet noMatchingKey, war \(error)")
            }
        }
    }
}
