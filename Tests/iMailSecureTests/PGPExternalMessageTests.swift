// PGPExternalMessageTests.swift
//
// Interoperabilitäts-Gegenprobe: Die Nachricht, beide Schlüssel und die
// Signatur stammen von GnuPG (siehe PGPExternalFixtures). iMail Secure ist
// hier nur Leser. Damit prüft der Test die Grenze zu einer anderen
// OpenPGP-Implementierung statt eines selbst erzeugten Rundlaufs.

import XCTest
@testable import iMailSecure

final class PGPExternalMessageTests: XCTestCase {

    func testDecryptsAndVerifiesMessageFromGnuPG() throws {
        let secret = PGPDecryptor.SecretCandidate(
            key: Data(PGPExternalFixtures.recipientSecretKey.utf8),
            passphrase: "",
            fingerprint: PGPExternalFixtures.recipientFingerprint
        )
        let senderKey = StoredPGPKey(
            email: PGPExternalFixtures.senderEmail,
            userID: "Externer Test <extern@gnupg.invalid>",
            fingerprint: PGPExternalFixtures.senderFingerprint,
            armored: PGPExternalFixtures.senderPublicKey,
            addedAt: Date()
        )

        let result = PGPDecryptor.decrypt(
            raw: Data(PGPExternalFixtures.signedEncryptedMessage.utf8),
            secrets: [secret],
            senderEmail: PGPExternalFixtures.senderEmail,
            publicKeys: [senderKey]
        )
        let content = try XCTUnwrap(result.get())

        XCTAssertEqual(content.body, PGPExternalFixtures.body)
        XCTAssertTrue(content.attachments.isEmpty)
        XCTAssertEqual(content.keyFingerprint, PGPExternalFixtures.recipientFingerprint)
        guard case .valid(let key) = content.signatureStatus else {
            return XCTFail("Innere Signatur müsste gültig sein, war \(content.signatureStatus)")
        }
        XCTAssertEqual(key.fingerprint, PGPExternalFixtures.senderFingerprint)
    }
}
