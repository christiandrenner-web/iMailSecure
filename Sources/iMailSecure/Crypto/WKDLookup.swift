// WKDLookup.swift
//
// Web Key Directory (WKD): Der öffentliche Schlüssel liegt beim Betreiber der
// Domain des Absenders. iMail Secure fragt ihn NUR ab, wenn der Nutzer das
// ausdrücklich verlangt — kein Hintergrund-Lookup, keine Abfrage bei einem
// Keyserver oder sonstigen Dritten.
//
// Die Anfrage geht ausschließlich an die eigene Domain der Adresse (zuerst
// openpgpkey.<domain>, dann <domain> selbst) und immer über HTTPS mit
// regulärer Zertifikatsprüfung. Ephemere Session: kein Cookie, kein Cache,
// kein persistentes Protokoll.

import CryptoKit
import Foundation

/// Was eine WKD-Abfrage geliefert hat. Der Schlüssel liegt bereits in der
/// Form vor, in der ihn der Schlüsselbund speichert.
struct WKDResult: Equatable, Sendable {
    enum Method: String, Sendable {
        case advanced
        case direct
    }

    let email: String
    let armoredKey: Data
    let info: PGPKeyInfo
    let method: Method
}

enum WKDError: LocalizedError, Equatable {
    /// Adresse lässt sich nicht in lokaler Teil und Domain zerlegen.
    case invalidAddress
    /// Weder die erweiterte noch die direkte WKD-Adresse hat einen Schlüssel.
    case notFound
    /// Server hat mit einem unerwarteten Status geantwortet.
    case httpStatus(Int)
    /// Antwort war leer oder unnötig groß.
    case noData
    case tooLarge
    /// Netzwerk- oder TLS-Fehler.
    case network(String)
    /// Antwort war kein OpenPGP-Schlüssel.
    case invalidKey(String?)

    var errorDescription: String? {
        switch self {
        case .invalidAddress:
            return String(localized: "Das ist keine gültige E-Mail-Adresse.")
        case .notFound:
            return String(localized: "Für diese Adresse veröffentlicht die Domain keinen Schlüssel per WKD.")
        case let .httpStatus(status):
            return String(
                format: String(localized: "Der WKD-Server antwortete mit Status %d."),
                status
            )
        case .noData:
            return String(localized: "Der WKD-Server lieferte keinen Schlüssel.")
        case .tooLarge:
            return String(localized: "Die Antwort des WKD-Servers ist ungewöhnlich groß und wurde verworfen.")
        case let .network(detail):
            return String(
                format: String(localized: "Die WKD-Abfrage schlug fehl: %@"),
                detail
            )
        case let .invalidKey(detail):
            if let detail, !detail.isEmpty {
                return String(
                    format: String(localized: "Von der Domain kam kein gültiger Schlüssel: %@"),
                    detail
                )
            }
            return String(localized: "Von der Domain kam kein gültiger Schlüssel.")
        }
    }
}

/// Ein WKD-Server darf den Client nicht zu einem anderen Host umleiten:
/// sonst würde entgegen der Zusage doch ein Dritter von der Adresse erfahren.
/// Die Umleitung wird verworfen; die Antwort gilt dann als Fehler.
private final class NoRedirectDelegate: NSObject, URLSessionDelegate {
    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest,
        completionHandler: (URLRequest?) -> Void
    ) {
        completionHandler(nil)
    }
}

enum WKDLookup {
    /// Adresse in lokalen Teil und Domain zerlegen. Der lokale Teil wird für
    /// den WKD-Hash kleingeschrieben (so verlangt es das Verfahren).
    static func splitAddress(_ input: String) throws -> (local: String, domain: String) {
        let parts = input
            .trimmingCharacters(in: .whitespacesAndNewlines)
            .lowercased()
            .split(separator: "@", omittingEmptySubsequences: false)
        guard parts.count == 2, !parts[0].isEmpty, !parts[1].isEmpty else {
            throw WKDError.invalidAddress
        }
        let local = String(parts[0])
        let domain = String(parts[1])
        // Domain darf nur Host-Zeichen enthalten; sonst wäre die URL
        // manipulierbar. Keine IP-Adressen, keine Ports, keine Pfade.
        let allowed = domain.allSatisfy { $0.isLetter || $0.isNumber || $0 == "." || $0 == "-" }
        guard allowed, domain.contains("."), !domain.hasPrefix("."), !domain.hasSuffix("."),
              !domain.contains(".."), !local.contains("/"), !local.contains("\\")
        else {
            throw WKDError.invalidAddress
        }
        return (local, domain)
    }

    /// Die 32 Zeichen des WKD-Hash: z-base32(SHA-1(lokaler Teil)).
    /// SHA-1 dient hier nur als feste Abbildung, nicht als Schutz — eine
    /// Kollision würde einen anderen Benutzer derselben Domain treffen.
    static func wkdHash(for localPart: String) -> String {
        let alphabet = Array("ybndrfg8ejkmcpqxot1uwisza345h769")
        let digest = Insecure.SHA1.hash(data: Data(localPart.utf8))
        var result = ""
        result.reserveCapacity(32)
        var buffer: UInt32 = 0
        var bits = 0
        for byte in digest {
            buffer = (buffer << 8) | UInt32(byte)
            bits += 8
            while bits >= 5 {
                bits -= 5
                result.append(alphabet[Int((buffer >> bits) & 0x1F)])
            }
        }
        return result
    }

    /// URLs in der Reihenfolge, wie sie ein WKD-Client probieren muss:
    /// erweiterte Methode zuerst, direkte als Rückfall.
    static func urls(for email: String) throws -> [(url: URL, method: WKDResult.Method)] {
        let (local, domain) = try splitAddress(email)
        let hash = wkdHash(for: local)

        func makeURL(_ string: String) throws -> URL {
            var components = URLComponents(string: string)
            components?.queryItems = [URLQueryItem(name: "l", value: local)]
            guard let url = components?.url, url.scheme == "https" else {
                throw WKDError.invalidAddress
            }
            return url
        }

        return [
            (
                try makeURL("https://openpgpkey.\(domain)/.well-known/openpgpkey/\(domain)/hu/\(hash)"),
                .advanced
            ),
            (
                try makeURL("https://\(domain)/.well-known/openpgpkey/hu/\(hash)"),
                .direct
            )
        ]
    }

    /// Führt die Abfrage aus. Der Schlüssel wird nur zurückgegeben, wenn er
    /// tatsächlich von der richtigen Domain kam und als OpenPGP-Schlüssel
    /// lesbar ist. Die Adressprüfung gegen die User-ID erfolgt beim Import
    /// im Schlüsselbund — nicht hier, damit die UI den Unterschied zwischen
    /// „Schlüssel gefunden\" und „Schlüssel passt nicht\" zeigen kann.
    static func lookup(email: String) async throws -> WKDResult {
        let candidates = try urls(for: email)
        let configuration = URLSessionConfiguration.ephemeral
        configuration.timeoutIntervalForRequest = 10
        configuration.timeoutIntervalForResource = 15
        configuration.urlCache = nil
        let session = URLSession(
            configuration: configuration,
            delegate: NoRedirectDelegate(),
            delegateQueue: nil
        )
        defer { session.finishTasksAndInvalidate() }

        var lastError: Error = WKDError.notFound
        var sawNotFound = false
        for candidate in candidates {
            var request = URLRequest(url: candidate.url)
            request.cachePolicy = .reloadIgnoringLocalAndRemoteCacheData
            request.httpMethod = "GET"

            do {
                let (data, response) = try await session.data(for: request)
                guard let http = response as? HTTPURLResponse else {
                    throw WKDError.network(String(localized: "Unbekannte Antwort."))
                }
                if http.statusCode == 404 {
                    // Erweiterte Adresse nicht vorhanden → direkt probieren.
                    // Merken: Wenn ein Server ausdrücklich „kein Schlüssel“
                    // meldet, ist das die treffendere Antwort als ein
                    // Netzwerkfehler auf der anderen Adresse (z. B. wenn es
                    // die openpgpkey-Subdomain gar nicht gibt).
                    sawNotFound = true
                    continue
                }
                guard (200..<300).contains(http.statusCode) else {
                    throw WKDError.httpStatus(http.statusCode)
                }
                guard !data.isEmpty else { throw WKDError.noData }
                guard data.count <= 1_000_000 else { throw WKDError.tooLarge }

                let armored = try PGP.armoredPublicKey(data)
                let info = try PGP.parsePublicKey(armored)
                return WKDResult(
                    email: PGPKeyStore.normalize(email),
                    armoredKey: armored,
                    info: info,
                    method: candidate.method
                )
            } catch let error as WKDError {
                // 404 ist oben schon behandelt. Alle anderen Fehler werden
                // gemerkt, aber die nächste Adresse wird trotzdem probiert —
                // z. B. wenn es den openpgpkey-Subdomain nicht gibt.
                lastError = error
            } catch {
                lastError = WKDError.network(error.localizedDescription)
            }
        }
        if sawNotFound { throw WKDError.notFound }
        throw lastError
    }
}
