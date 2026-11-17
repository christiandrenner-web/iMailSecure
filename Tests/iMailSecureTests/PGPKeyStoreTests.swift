// PGPKeyStoreTests.swift
//
// Der Schlüsselbund liegt in der Keychain. Die Tests arbeiten mit Wegwerf-
// Adressen unter .invalid und räumen hinter sich auf, damit ein Lauf den
// nächsten nicht beeinflusst.

import XCTest
@testable import iMailSecure

final class PGPKeyStoreTests: XCTestCase {
    private let store = PGPKeyStore.shared
    private var createdEmails: [String] = []

    override func tearDown() {
        for email in createdEmails {
            try? store.remove(email: email)
        }
        createdEmails = []
        super.tearDown()
    }

    /// Der Fixture-Schlüssel gehört zu test@imailsecure.invalid.
    private var fixtureEmail: String { "test@imailsecure.invalid" }

    private func importFixture(email: String? = nil) throws -> StoredPGPKey {
        let address = email ?? fixtureEmail
        createdEmails.append(address)
        return try store.importKey(
            armored: Data(PGPFixtures.publicKey.utf8),
            email: address
        )
    }

    func testImportStoresKeyWithFingerprintAndUserID() throws {
        let record = try importFixture()
        XCTAssertEqual(record.fingerprint, PGPFixtures.fingerprint)
        XCTAssertEqual(record.userID, "iMail Secure Test <test@imailsecure.invalid>")
        XCTAssertEqual(record.formattedFingerprint.split(separator: " ").count, 10)

        let stored = store.key(forEmail: fixtureEmail.uppercased())
        XCTAssertEqual(stored?.fingerprint, PGPFixtures.fingerprint)
        XCTAssertEqual(stored?.armored, PGPFixtures.publicKey)
    }

    func testKeysAreSortedByAddress() throws {
        // Zwei echte Schlüssel mit unterschiedlichen Adressen, absichtlich in
        // umgekehrter Reihenfolge importiert: Die Liste muss trotzdem sortiert
        // sein. Eine Fixture unter fremder Adresse zu importieren geht nicht
        // mehr — genau das verhindert die Adressprüfung.
        createdEmails.append("test@imailsecure.invalid")
        createdEmails.append("other@imailsecure.invalid")
        _ = try store.importKey(
            armored: Data(PGPFixtures.publicKey.utf8),
            email: "test@imailsecure.invalid"
        )
        _ = try store.importKey(
            armored: Data(PGPFixtures.otherPublicKey.utf8),
            email: "other@imailsecure.invalid"
        )

        let emails = store.keys()
            .map(\.email)
            .filter { $0.hasSuffix("@imailsecure.invalid") }
        XCTAssertEqual(emails, emails.sorted())
        XCTAssertTrue(emails.contains("other@imailsecure.invalid"))
        XCTAssertTrue(emails.contains(fixtureEmail))
    }

    func testImportRejectsForeignAddress() {
        XCTAssertThrowsError(
            try store.importKey(
                armored: Data(PGPFixtures.publicKey.utf8),
                email: "jemand.anderes@imailsecure.invalid"
            )
        ) { error in
            guard case PGPKeyStoreError.emailMismatch(let keyEmail) = error else {
                return XCTFail("erwartet emailMismatch, war \(error)")
            }
            XCTAssertEqual(keyEmail, self.fixtureEmail)
        }
    }

    func testImportRejectsGarbage() {
        XCTAssertThrowsError(
            try store.importKey(armored: Data("kein Schlüssel".utf8), email: fixtureEmail)
        ) { error in
            guard case PGPError.invalidKey = error else {
                return XCTFail("erwartet invalidKey, war \(error)")
            }
        }
    }

    func testRemoveDeletesKey() throws {
        _ = try importFixture()
        try store.remove(email: fixtureEmail)
        XCTAssertNil(store.key(forEmail: fixtureEmail))
        XCTAssertFalse(store.hasKey(forEmail: fixtureEmail))
        XCTAssertThrowsError(try store.remove(email: fixtureEmail)) { error in
            guard case PGPKeyStoreError.notFound = error else {
                return XCTFail("erwartet notFound, war \(error)")
            }
        }
    }

    func testReimportReplacesKey() throws {
        _ = try importFixture()
        // Zweiter Import derselben Adresse ersetzt den Eintrag, statt zu doppeln.
        _ = try importFixture()
        let matches = store.keys().filter { $0.email == fixtureEmail }
        XCTAssertEqual(matches.count, 1)
    }
}
