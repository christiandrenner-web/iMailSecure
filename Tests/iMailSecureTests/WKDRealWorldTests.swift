// WKDRealWorldTests.swift
//
// Gegenprobe gegen echte WKD-Server. Opt-in, weil Netzwerk nötig ist:
//   IMAIL_NETWORK_TESTS=1 xcodebuild -scheme iMailSecure … test
//
// Die Adressen und Fingerprints stammen aus der öffentlichen Dokumentation
// der GnuPG-Wiki (WKD), nicht aus einem Keyserver.

import XCTest
@testable import iMailSecure

final class WKDRealWorldTests: XCTestCase {

    override func setUpWithError() throws {
        try XCTSkipUnless(
            ProcessInfo.processInfo.environment["IMAIL_NETWORK_TESTS"] == "1",
            "IMAIL_NETWORK_TESTS=1 nicht gesetzt"
        )
    }

    /// Die erweiterte Adresse existiert bei intevation.de nicht; die direkte
    /// Methode muss als Rückfall greifen und einen echten Schlüssel liefern.
    func testFallsBackToDirectMethodAndParsesRealKey() async throws {
        let result = try await WKDLookup.lookup(email: "bernhard.reiter@intevation.de")

        XCTAssertEqual(result.method, .direct)
        XCTAssertEqual(
            result.info.fingerprint,
            "BDD957F9C4FE0FDC583DCD6D2B7BA3BF9BC3A554"
        )
        XCTAssertEqual(result.email, "bernhard.reiter@intevation.de")
        XCTAssertTrue(
            String(data: result.armoredKey, encoding: .utf8)?
                .contains("BEGIN PGP PUBLIC KEY BLOCK") == true
        )
    }

    /// Posteo antwortet auf der erweiterten Adresse mit einem Netzwerkfehler
    /// und auf der direkten mit 404. Der Nutzer muss „kein Schlüssel“ sehen,
    /// nicht eine irreführende Netzwerkmeldung.
    func testUnknownAddressReportsNotFound() async throws {
        do {
            _ = try await WKDLookup.lookup(email: "does-not-exist-xyz@posteo.de")
            XCTFail("Für eine unbekannte Adresse darf kein Schlüssel kommen")
        } catch {
            guard case WKDError.notFound = error else {
                return XCTFail("erwartet notFound, war \(error)")
            }
        }
    }
}
