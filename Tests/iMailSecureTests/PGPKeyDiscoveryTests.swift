// PGPKeyDiscoveryTests.swift
//
// Kontrolliert den kontrollierten Schlüsselbezug: WKD-Adressen müssen
// exakt zur Spezifikation passen, Autocrypt-Header müssen gefaltetes
// Base64 lesen und dürfen Adressen nicht verwechseln. Hier wird bewusst
// kein Netzwerk benutzt.

import XCTest
import SwiftMail
@testable import iMailSecure

final class PGPKeyDiscoveryTests: XCTestCase {

    // MARK: – WKD

    /// Vektoren aus der WKD-Dokumentation (GnuPG-Wiki, Incenp, Metacode).
    func testWKDHashesMatchPublishedVectors() {
        let vectors: [String: String] = [
            "alice": "kei1q4tipxxu1yj79k9kfukdhfy631xe",
            "user": "nmxk159crbcuk3imqiw13gkjmfwd8mqj",
            "joe.doe": "iy9q119eutrkn8s1mk4r39qejnbu3n5q",
            "isabell": "mmuhurigesr7z8hzf6sh5cmfsnmiiyyr",
            "test-wkd": "4hg7tescnttreaouu4z1izeuuyibwww1",
            "bernhard.reiter": "it5sewh54rxz33fwmr8u6dy4bbz8itz4"
        ]
        for (local, expected) in vectors {
            XCTAssertEqual(WKDLookup.wkdHash(for: local), expected, "Hash für \(local)")
        }
    }

    func testWKDUrlsUseAdvancedFirstThenDirect() throws {
        let urls = try WKDLookup.urls(for: "Alice@Example.ORG")
        XCTAssertEqual(urls.count, 2)
        XCTAssertEqual(urls[0].method, .advanced)
        XCTAssertEqual(
            urls[0].url.absoluteString,
            "https://openpgpkey.example.org/.well-known/openpgpkey/example.org/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe?l=alice"
        )
        XCTAssertEqual(urls[1].method, .direct)
        XCTAssertEqual(
            urls[1].url.absoluteString,
            "https://example.org/.well-known/openpgpkey/hu/kei1q4tipxxu1yj79k9kfukdhfy631xe?l=alice"
        )
    }

    func testMalformedAddressesAreRejected() {
        for address in ["alice", "alice@", "@example.org", "a@b@c", "alice@exa mple.org",
                        "alice@../evil.example", "alice@example.org:8443", "ali/ce@example.org"] {
            XCTAssertThrowsError(try WKDLookup.splitAddress(address), "\(address)")
        }
    }

    func testLocalPartMayContainDotAndPlus() throws {
        let split = try WKDLookup.splitAddress("Joe.Doe+tag@Example.org")
        XCTAssertEqual(split.local, "joe.doe+tag")
        XCTAssertEqual(split.domain, "example.org")
    }

    // MARK: – Autocrypt

    private func foldedAutocryptHeader(address: String = "test@imailsecure.invalid") -> String {
        let encoded = Data(PGPFixtures.publicKey.utf8).base64EncodedString()
        let chunks = stride(from: 0, to: encoded.count, by: 60).map { offset in
            let start = encoded.index(encoded.startIndex, offsetBy: offset)
            let end = encoded.index(start, offsetBy: min(60, encoded.count - offset))
            return String(encoded[start..<end])
        }
        // So sieht der Wert aus, nachdem der IMAP-Parser entfaltet hat:
        // Leerzeichen an den Umbruchstellen.
        return "addr=\(address); prefer-encrypt=mutual; keydata=\(chunks.joined(separator: " \r\n "))"
    }

    func testAutocryptReadsFoldedBase64AndIgnoresOtherParameters() throws {
        let key = try XCTUnwrap(AutocryptHeader.parse(foldedAutocryptHeader()))
        XCTAssertEqual(key.address, "test@imailsecure.invalid")

        let info = try PGP.parsePublicKey(key.keyData)
        XCTAssertEqual(info.fingerprint, PGPFixtures.fingerprint)

        let armored = try PGP.armoredPublicKey(key.keyData)
        let repaired = try PGP.parsePublicKey(armored)
        XCTAssertEqual(repaired.fingerprint, info.fingerprint)
        XCTAssertTrue(String(decoding: armored, as: UTF8.self).hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
    }

    func testAutocryptAcceptsQuotedAddress() {
        let header = foldedAutocryptHeader(address: "\"test@imailsecure.invalid\"")
        XCTAssertEqual(AutocryptHeader.parse(header)?.address, "test@imailsecure.invalid")
    }

    func testAutocryptRejectsIncompleteOrBrokenHeaders() {
        XCTAssertNil(AutocryptHeader.parse("addr=test@imailsecure.invalid"))
        XCTAssertNil(AutocryptHeader.parse("keydata=QUJD"))
        XCTAssertNil(AutocryptHeader.parse("addr=keine-adresse; keydata=QUJD"))
        XCTAssertNil(AutocryptHeader.parse("addr=test@imailsecure.invalid; keydata=@@@"))
    }

    // MARK: – Hydration aus dem IMAP-Header

    @MainActor
    func testConvertCarriesAutocryptHeaderWithoutImporting() {
        let headerValue = foldedAutocryptHeader()
        let parts = [MessagePart(sectionString: "1", contentType: "text/plain")]
        let header = MessageInfo(
            sequenceNumber: SequenceNumber(1),
            uid: UID(1),
            subject: "Test",
            from: "test@imailsecure.invalid",
            parts: parts,
            additionalFields: ["autocrypt": headerValue]
        )
        let message = Message(header: header, parts: parts)
        let account = EmailAccount(
            displayName: "Test",
            email: "empfaenger@example.org",
            imapHost: "imap.example.org",
            imapPort: 993,
            smtpHost: "smtp.example.org",
            smtpPort: 587,
            username: "empfaenger@example.org"
        )
        let converted = MailSyncEngine(account: account, mailStore: MailStore()).convert(message)

        XCTAssertEqual(converted?.autocryptHeader, headerValue)
    }
}
