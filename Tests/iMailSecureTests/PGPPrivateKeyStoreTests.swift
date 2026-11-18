// PGPPrivateKeyStoreTests.swift
//
// Der geheime Schlüssel liegt zusammen mit seiner Passphrase im Keychain.
// Die Tests benutzen Wegwerfschlüssel unter .invalid und räumen hinter sich
// auf. Geprüft wird auch, dass ein fehlgeschlagener Import nichts zurücklässt.

import XCTest
@testable import iMailSecure

final class PGPPrivateKeyStoreTests: XCTestCase {
    private let store = PGPPrivateKeyStore.shared
    private let email = "signing@imailsecure.invalid"

    override func tearDown() {
        try? store.remove(email: email)
        super.tearDown()
    }

    func testImportStoresKeyPassphraseAndIdentity() throws {
        let record = try store.importKey(
            armored: Data(PGPFixtures.privateKey.utf8),
            passphrase: PGPFixtures.privateKeyPassphrase,
            email: email
        )

        XCTAssertEqual(record.fingerprint, PGPFixtures.privateKeyFingerprint)
        XCTAssertEqual(record.email, email)
        let stored = store.key(forEmail: email.uppercased())
        XCTAssertEqual(stored?.armored, PGPFixtures.privateKey)
        XCTAssertEqual(try store.passphrase(forEmail: email), PGPFixtures.privateKeyPassphrase)
    }

    func testWrongPassphraseIsRejectedWithoutStoringAnything() {
        XCTAssertThrowsError(
            try store.importKey(
                armored: Data(PGPFixtures.privateKey.utf8),
                passphrase: "falsche-passphrase",
                email: email
            )
        ) { error in
            guard case PGPError.wrongPassphrase = error else {
                return XCTFail("erwartet wrongPassphrase, war \(error)")
            }
        }
        XCTAssertNil(store.key(forEmail: email))
        XCTAssertThrowsError(try store.passphrase(forEmail: email))
    }

    func testImportRejectsForeignAddress() {
        XCTAssertThrowsError(
            try store.importKey(
                armored: Data(PGPFixtures.privateKey.utf8),
                passphrase: PGPFixtures.privateKeyPassphrase,
                email: "jemand.anderes@imailsecure.invalid"
            )
        ) { error in
            guard case PGPPrivateKeyStoreError.emailMismatch = error else {
                return XCTFail("erwartet emailMismatch, war \(error)")
            }
        }
    }

    func testRemoveDeletesKeyAndPassphrase() throws {
        try store.importKey(
            armored: Data(PGPFixtures.privateKey.utf8),
            passphrase: PGPFixtures.privateKeyPassphrase,
            email: email
        )
        try store.remove(email: email)

        XCTAssertNil(store.key(forEmail: email))
        XCTAssertThrowsError(try store.passphrase(forEmail: email))
        XCTAssertThrowsError(try store.remove(email: email)) { error in
            guard case PGPPrivateKeyStoreError.notFound = error else {
                return XCTFail("erwartet notFound, war \(error)")
            }
        }
    }

    func testReimportReplacesKey() throws {
        try store.importKey(
            armored: Data(PGPFixtures.privateKey.utf8),
            passphrase: PGPFixtures.privateKeyPassphrase,
            email: email
        )
        try store.importKey(
            armored: Data(PGPFixtures.privateKey.utf8),
            passphrase: PGPFixtures.privateKeyPassphrase,
            email: email.uppercased()
        )
        XCTAssertEqual(store.keys().filter { $0.email == email }.count, 1)
    }
}
