// PGPTests.swift
//
// Prüft den Swift-Wrapper gegen die echte rpgp-FFI. Die Testdaten liegen in
// Fixtures/PGPFixtures.swift (erzeugt von Crypto/pgp-ffi/examples/make_fixtures.rs),
// damit hier keine Krypto nachgebaut wird. Was hier zählt: Bytes kommen
// unverändert durch, Rückgabecodes werden richtig übersetzt, und eine falsche
// Signatur bleibt von „nicht prüfbar“ unterscheidbar.

import XCTest
@testable import iMailSecure

final class PGPTests: XCTestCase {
    // MARK: – Schlüssel

    func testParsesArmoredKeyAndReportsFingerprint() throws {
        let key = try PGP.parsePublicKey(Data(PGPFixtures.publicKey.utf8))
        XCTAssertEqual(key.fingerprint, PGPFixtures.fingerprint)
        XCTAssertEqual(key.fingerprint.count, 40, "Ed25519-Schlüssel der Fixture ist v4")
    }

    func testFingerprintFormatting() throws {
        let key = try PGP.parsePublicKey(Data(PGPFixtures.publicKey.utf8))
        XCTAssertEqual(key.formattedFingerprint.split(separator: " ").count, 10)
        XCTAssertFalse(key.formattedFingerprint.contains("  "))
        XCTAssertEqual(key.shortIdentifier.count, 16)
        XCTAssertTrue(key.fingerprint.hasSuffix(key.shortIdentifier))
    }

    func testRejectsGarbage() {
        XCTAssertThrowsError(try PGP.parsePublicKey(Data("kein OpenPGP".utf8))) { error in
            guard case PGPError.invalidKey = error else {
                return XCTFail("erwartet invalidKey, war \(error)")
            }
        }
    }

    func testRejectsEmptyKey() {
        XCTAssertThrowsError(try PGP.parsePublicKey(Data())) { error in
            guard case PGPError.invalidKey(let detail) = error else {
                return XCTFail("erwartet invalidKey, war \(error)")
            }
            // Leere Daten erreichen Rust als gültiger Puffer der Länge 0 und
            // scheitern dort beim Parsen; die technische Meldung bleibt als
            // `failureReason` erhalten, die Anzeige nutzt errorDescription.
            XCTAssertNotNil(detail)
            XCTAssertEqual((error as? LocalizedError)?.errorDescription,
                           String(localized: "Das ist kein gültiger öffentlicher Schlüssel."))
        }
    }

    // MARK: – Signaturen

    func testVerifiesValidSignature() throws {
        let valid = try PGP.verifyDetached(
            signature: Data(PGPFixtures.signature.utf8),
            data: Data(PGPFixtures.payload.utf8),
            publicKey: Data(PGPFixtures.publicKey.utf8)
        )
        XCTAssertTrue(valid)
    }

    func testDetectsTamperedPayload() throws {
        let valid = try PGP.verifyDetached(
            signature: Data(PGPFixtures.signature.utf8),
            data: Data(PGPFixtures.tamperedPayload.utf8),
            publicKey: Data(PGPFixtures.publicKey.utf8)
        )
        XCTAssertFalse(valid, "veränderte Daten dürfen nicht als gültig gelten")
    }

    func testDifferentKeyDoesNotVerify() throws {
        // Signatur von Schlüssel A, Prüfung mit Schlüssel B: Das ist ein
        // reguläres „falsch“ (kein Fehler), weil beide Schlüssel lesbar sind.
        let valid = try PGP.verifyDetached(
            signature: Data(PGPFixtures.signature.utf8),
            data: Data(PGPFixtures.payload.utf8),
            publicKey: Data(PGPFixtures.otherPublicKey.utf8)
        )
        XCTAssertFalse(valid, "fremder Schlüssel darf keine gültige Signatur ergeben")
    }

    func testUnreadableSignatureIsAnError() {
        XCTAssertThrowsError(try PGP.verifyDetached(
            signature: Data("keine Signatur".utf8),
            data: Data(PGPFixtures.payload.utf8),
            publicKey: Data(PGPFixtures.publicKey.utf8)
        )) { error in
            guard case PGPError.unreadableSignature = error else {
                return XCTFail("erwartet unreadableSignature, war \(error)")
            }
        }
    }

    func testMissingKeyIsReportedAsInvalidKey() {
        XCTAssertThrowsError(try PGP.verifyDetached(
            signature: Data(PGPFixtures.signature.utf8),
            data: Data(PGPFixtures.payload.utf8),
            publicKey: Data("kein Schlüssel".utf8)
        )) { error in
            guard case PGPError.invalidKey = error else {
                return XCTFail("erwartet invalidKey, war \(error)")
            }
        }
    }

    // MARK: – Bibliothek

    func testVersionNamesRpgp() {
        XCTAssertTrue(PGP.version.contains("imailpgp"), PGP.version)
        XCTAssertTrue(PGP.version.contains("rpgp 0.21.1"), PGP.version)
    }
}
