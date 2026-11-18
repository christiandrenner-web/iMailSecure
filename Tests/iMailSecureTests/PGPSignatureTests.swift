// PGPSignatureTests.swift
//
// Prüft das Lesen von PGP/MIME (RFC 3156): Zerlegen der Nachricht, Auswahl
// des Schlüssels über den Aussteller und die Unterscheidung von „gültig",
// „verändert" und „Schlüssel unbekannt". Die Nachrichten liegen als Fixture
// vor (Crypto/pgp-ffi/examples/make_fixtures.rs) und sind echt signiert.

import XCTest
import SwiftMail
@testable import iMailSecure

final class PGPSignatureTests: XCTestCase {
    private let sender = "test@imailsecure.invalid"

    private var testAccount: EmailAccount {
        EmailAccount(
            displayName: "Test",
            email: sender,
            imapHost: "imap.example.com",
            imapPort: 993,
            smtpHost: "smtp.example.com",
            smtpPort: 587,
            username: sender
        )
    }

    /// Baut eine Nachricht so, wie sie aus BODYSTRUCTURE kommt: flache
    /// Teil-Liste ohne Inhaltsdaten. Für die Erkennung reicht der Typ.
    private func message(with contentTypes: [String]) -> Message {
        let parts = contentTypes.enumerated().map { index, type in
            MessagePart(sectionString: "\(index + 1)", contentType: type)
        }
        let header = MessageInfo(
            sequenceNumber: SequenceNumber(1),
            uid: UID(1),
            subject: "Test",
            from: sender,
            parts: parts
        )
        return Message(header: header, parts: parts)
    }

    private func fixtureKey(email: String? = nil) -> StoredPGPKey {
        StoredPGPKey(
            email: email ?? sender,
            userID: "iMail Secure Test <test@imailsecure.invalid>",
            fingerprint: PGPFixtures.fingerprint,
            armored: PGPFixtures.publicKey,
            addedAt: Date(timeIntervalSince1970: 0)
        )
    }

    // MARK: – Zerlegen

    func testParsesSignedEntity() throws {
        let raw = Data(PGPFixtures.signedMessage.utf8)
        let entity = try XCTUnwrap(PGPMIMEParser.signedEntity(in: raw))
        let signature = String(decoding: entity.signature, as: UTF8.self)
        XCTAssertTrue(signature.contains("-----BEGIN PGP SIGNATURE-----"))
        XCTAssertEqual(entity.signedDataCandidates.count, 2)
        let signedText = String(decoding: entity.signedDataCandidates[0], as: UTF8.self)
        XCTAssertTrue(signedText.hasPrefix("Content-Type: text/plain"))
        XCTAssertTrue(signedText.hasSuffix("dieser Text ist signiert."))
    }

    func testUnsignedMessageIsNotSigned() {
        let raw = Data("""
        From: a@example.org
        Content-Type: text/plain

        Hallo.
        """.utf8)
        XCTAssertNil(PGPMIMEParser.signedEntity(in: raw))
        XCTAssertEqual(
            PGPSignatureVerifier.analyze(raw: raw, senderEmail: sender, keys: [fixtureKey()]),
            .notSigned
        )
    }

    func testEncryptedMessageIsRecognized() {
        let raw = Data("""
        From: a@example.org
        Content-Type: multipart/encrypted; protocol="application/pgp-encrypted"; boundary="b"

        --b
        Content-Type: application/pgp-encrypted

        Version: 1
        --b
        Content-Type: application/octet-stream

        -----BEGIN PGP MESSAGE-----
        -----END PGP MESSAGE-----
        --b--
        """.utf8)
        XCTAssertTrue(PGPMIMEParser.isEncrypted(raw))
        XCTAssertEqual(
            PGPSignatureVerifier.analyze(raw: raw, senderEmail: sender, keys: [fixtureKey()]),
            .encrypted
        )
    }

    // MARK: – Prüfen

    func testValidSignatureWithCRLF() {
        let raw = Data(PGPFixtures.signedMessageCRLF.utf8)
        let status = PGPSignatureVerifier.analyze(
            raw: raw, senderEmail: sender, keys: [fixtureKey()]
        )
        guard case .valid(let key) = status else {
            return XCTFail("erwartet gültig, war \(status)")
        }
        XCTAssertEqual(key.fingerprint, PGPFixtures.fingerprint)
    }

    func testValidSignatureWithBareLF() {
        // Schlecht zugestellte Nachricht mit LF statt CRLF: Die Prüfung darf
        // daran nicht scheitern, weil sich nur Zeilenenden unterscheiden.
        let raw = Data(PGPFixtures.signedMessage.utf8)
        let status = PGPSignatureVerifier.analyze(
            raw: raw, senderEmail: sender, keys: [fixtureKey()]
        )
        guard case .valid = status else {
            return XCTFail("erwartet gültig, war \(status)")
        }
    }

    func testTamperedMessageIsInvalid() {
        let raw = Data(PGPFixtures.tamperedSignedMessage.utf8)
        let status = PGPSignatureVerifier.analyze(
            raw: raw, senderEmail: sender, keys: [fixtureKey()]
        )
        XCTAssertEqual(status, .invalid)
    }

    func testUnknownKeyIsReportedWithIssuer() {
        let raw = Data(PGPFixtures.signedMessageCRLF.utf8)
        let status = PGPSignatureVerifier.analyze(raw: raw, senderEmail: sender, keys: [])
        guard case .unknownKey(let issuer, let email) = status else {
            return XCTFail("erwartet unknownKey, war \(status)")
        }
        XCTAssertEqual(email, sender)
        let issuerValue = try? XCTUnwrap(issuer)
        XCTAssertNotNil(issuerValue)
        // Der Aussteller ist Fingerprint oder dessen Key ID.
        XCTAssertTrue(PGPFixtures.fingerprint.hasSuffix(issuerValue ?? ""))
    }

    func testForeignKeyDoesNotVerifyEvenForSameAddress() {
        // Ein anderer Schlüssel, der unter derselben Adresse liegt: Der
        // Aussteller passt nicht, also wird gar nicht erst geprüft.
        let foreign = StoredPGPKey(
            email: sender,
            userID: "iMail Secure Fremdschlüssel <other@imailsecure.invalid>",
            fingerprint: "0000000000000000000000000000000000000000",
            armored: PGPFixtures.otherPublicKey,
            addedAt: Date(timeIntervalSince1970: 0)
        )
        let raw = Data(PGPFixtures.signedMessageCRLF.utf8)
        let status = PGPSignatureVerifier.analyze(
            raw: raw, senderEmail: sender, keys: [foreign]
        )
        guard case .unknownKey = status else {
            return XCTFail("erwartet unknownKey, war \(status)")
        }
    }

    func testIssuerMatchesFixtureFingerprint() throws {
        // Der Aussteller im Signaturpaket ist der Hinweis, welcher Schlüssel
        // zur Prüfung herangezogen wird. rpgp schreibt bei v4-Signaturen den
        // vollständigen Fingerprint hinein.
        let raw = Data(PGPFixtures.signedMessageCRLF.utf8)
        let entity = try XCTUnwrap(PGPMIMEParser.signedEntity(in: raw))
        let issuer = try XCTUnwrap(try PGP.signatureIssuer(in: entity.signature))
        XCTAssertEqual(issuer, PGPFixtures.fingerprint)
    }

    // MARK: – Erkennung beim Sync

    /// Nur erkannte PGP-Nachrichten lösen den zweiten Rohabruf aus. Falsch
    /// positiv wäre teuer und würde den Server unnötig belasten, falsch
    /// negativ würde die Signaturprüfung still wegfallen.
    @MainActor
    func testConvertRecognizesPGPMIMEParts() {
        let engine = MailSyncEngine(account: testAccount, mailStore: MailStore())

        let signed = message(with: ["text/plain", "application/pgp-signature"])
        XCTAssertEqual(engine.convert(signed)?.pgpState, .signed)

        let encrypted = message(with: ["application/pgp-encrypted", "application/octet-stream"])
        XCTAssertEqual(engine.convert(encrypted)?.pgpState, .encrypted)

        let plain = message(with: ["text/plain", "text/html"])
        XCTAssertEqual(engine.convert(plain)?.pgpState, PGPMessageState.none)
    }

    func testSMIMESignedMessageIsIgnored() {
        let raw = Data("""
        Content-Type: multipart/signed; protocol="application/pkcs7-signature"; boundary="b"

        --b
        Content-Type: text/plain

        Hallo.
        --b
        Content-Type: application/pkcs7-signature

        MIIB...
        --b--
        """.utf8)
        XCTAssertNil(PGPMIMEParser.signedEntity(in: raw))
    }

    // MARK: – Kopfzeilen

    func testContentTypeParsingHandlesQuotesAndCase() {
        let parsed = PGPMIMEParser.parseContentType(
            "Multipart/Signed; Protocol=\"application/pgp-signature\"; Boundary=\"a;b\""
        )
        XCTAssertEqual(parsed?.type, "multipart/signed")
        XCTAssertEqual(parsed?.parameters["protocol"], "application/pgp-signature")
        XCTAssertEqual(parsed?.parameters["boundary"], "a;b")
    }

    func testHeaderValueUnfoldsContinuationLines() {
        let headers = "Content-Type: multipart/signed;\r\n\tprotocol=\"application/pgp-signature\"\r\nSubject: x"
        let value = PGPMIMEParser.headerValue("content-type", in: headers)
        XCTAssertEqual(
            value,
            "multipart/signed; protocol=\"application/pgp-signature\""
        )
    }
}
