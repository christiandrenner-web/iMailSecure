// PGPFixtures.swift — Testdaten, erzeugt mit
// `cargo run --example make_fixtures` in Crypto/pgp-ffi.
// Nicht von Hand ändern; siehe Crypto/README.md.
//
// Schlüssel und Signatur sind Wegwerfdaten (User-ID endet auf .invalid) und
// haben keinen Wert außerhalb der Tests.

enum PGPFixtures {
    /// Nutzdaten, über die `signature` gilt.
    static let payload = """
Hallo PGP,

Grüße aus der Testsuite – Zeile 3.
"""

    /// Armierter öffentlicher Schlüssel (Ed25519, SHA-256).
    static let publicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEavvFSBYJKwYBBAHaRw8BAQdACfiamQfRU3/mcOt+L3Ef0UZhRLkUo3NkeDZ+
qQeFksjNLGlNYWlsIFNlY3VyZSBUZXN0IDx0ZXN0QGltYWlsc2VjdXJlLmludmFs
aWQ+wocEExYIAC8FAmr7xUgWIQS4pv3M4n2m8HeXls+5mPUY1OTzLgIbAgIeAQEL
AhUIARYBJwIZAQAKCRC5mPUY1OTzLtszAP9/oiW0v3QG2tso7K0aEJhcDjnVN9hU
4jmxS0/7RYg2TgEApiQWml7L+mU+W9fRIk3h7lc6fB7Kk0YGO2JWmKqyLwHOOARq
+8VIEgorBgEEAZdVAQUBAQdAUT4+hd9SGYOJA+qjuhzRKcM6DF1iuSb8dxjchuvf
2DEDAQgHwngEGBYIACAFAmr7xUgCGwAWIQS4pv3M4n2m8HeXls+5mPUY1OTzLgAK
CRC5mPUY1OTzLr12AQCG5PXas9omnNIhSS4oB08nfZc++tUbQ3aglS3z7HlfOgD/
XYrVVnAPONVgP10bpV00Ou9qwIIBjaLljMUQGvrBBA4=
=DW+z
-----END PGP PUBLIC KEY BLOCK-----
"""

    /// Zweiter, unabhängiger öffentlicher Schlüssel. `signature` ist nicht
    /// von ihm erzeugt und darf mit ihm nicht als gültig gelten.
    static let otherPublicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEavvFSBYJKwYBBAHaRw8BAQdAa0/DgouIiHiQ8ZKXSOqATIocDVyP2oQBuQv+
4vFaIrTNOGlNYWlsIFNlY3VyZSBGcmVtZHNjaGzDvHNzZWwgPG90aGVyQGltYWls
c2VjdXJlLmludmFsaWQ+wocEExYIAC8FAmr7xUgWIQQcqEmXP9h5EhLAgV6UyHDl
Zzx5XAIbAgIeAQELAhUIARYBJwIZAQAKCRCUyHDlZzx5XPyzAP4rR0wfdUp4L8NW
VxGAqobol5OIPQDTTL3ZeZRiwjbr9wEA9xRbjTFBx/MuFu04c5CLajDHPPf+0fSF
KTi03ig+dArOOARq+8VIEgorBgEEAZdVAQUBAQdA8GpdF0+3Tk5NW4KaCMnobo3n
AcbKxJofaedgzKkqHToDAQgHwngEGBYIACAFAmr7xUgCGwAWIQQcqEmXP9h5EhLA
gV6UyHDlZzx5XAAKCRCUyHDlZzx5XISqAP4qLgWcWAOYEsWTzufUpaHDD84wrpZj
OxKUK7vt8fhA2gD/UXsXT+5dvMakGqS3cooLBr1ieB61cxbympbz3u5pkQ8=
=thsH
-----END PGP PUBLIC KEY BLOCK-----
"""

    /// Armierte abgetrennte Signatur über `payload`.
    static let signature = """
-----BEGIN PGP SIGNATURE-----

wnUEABYIAB0WIQS4pv3M4n2m8HeXls+5mPUY1OTzLgUCavvFSAAKCRC5mPUY1OTz
LnDFAP9f9Nl0bNJyAzYVekRYlf5RwDeJIh+Wgi2bDAO6lrjmFgEA7VQjddgSm2tZ
eGOMhe9iymjSsADLY1uRoWeZDmjRGQc=
=Py5f
-----END PGP SIGNATURE-----
"""

    /// Vollständige PGP/MIME-Nachricht (RFC 3156): erster Teil signiert,
    /// zweiter Teil die Signatur. Hier mit LF; `signedMessageCRLF` liefert
    /// dieselbe Nachricht so, wie sie über SMTP läuft.
    static let signedMessage = """
From: iMail Secure Test <test@imailsecure.invalid>
To: empfaenger@imailsecure.invalid
Subject: Signierte Testnachricht
Date: Tue, 17 Nov 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="imailsecure-test-boundary"

This is an OpenPGP/MIME signed message (RFC 3156)
--imailsecure-test-boundary
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Hallo PGP/MIME,

dieser Text ist signiert.
--imailsecure-test-boundary
Content-Type: application/pgp-signature; name="signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="signature.asc"

-----BEGIN PGP SIGNATURE-----

wnUEABYIAB0WIQS4pv3M4n2m8HeXls+5mPUY1OTzLgUCavvFSAAKCRC5mPUY1OTz
Lt+tAQD3jDgisexXQM843sv9IolvzEatK66M7wxLwpDazb9y+wEA3UOV+rM5HBs2
H8Efdqe3Lp5g5yhqympvBejDe/VbSAU=
=WkWr
-----END PGP SIGNATURE-----
--imailsecure-test-boundary--
"""

    /// Dieselbe Nachricht mit CRLF-Zeilenenden.
    static var signedMessageCRLF: String {
        signedMessage.replacingOccurrences(of: "\n", with: "\r\n")
    }

    /// Dieselbe Nachricht, ein Wort im Text verändert — die Signatur muss
    /// dann als ungültig erkannt werden.
    static let tamperedSignedMessage = """
From: iMail Secure Test <test@imailsecure.invalid>
To: empfaenger@imailsecure.invalid
Subject: Signierte Testnachricht
Date: Tue, 17 Nov 2026 10:00:00 +0000
MIME-Version: 1.0
Content-Type: multipart/signed; micalg=pgp-sha256; protocol="application/pgp-signature"; boundary="imailsecure-test-boundary"

This is an OpenPGP/MIME signed message (RFC 3156)
--imailsecure-test-boundary
Content-Type: text/plain; charset=utf-8
Content-Transfer-Encoding: 8bit

Hallo PGP/MIME,

dieser Text wurde verändert.
--imailsecure-test-boundary
Content-Type: application/pgp-signature; name="signature.asc"
Content-Description: OpenPGP digital signature
Content-Disposition: attachment; filename="signature.asc"

-----BEGIN PGP SIGNATURE-----

wnUEABYIAB0WIQS4pv3M4n2m8HeXls+5mPUY1OTzLgUCavvFSAAKCRC5mPUY1OTz
Lt+tAQD3jDgisexXQM843sv9IolvzEatK66M7wxLwpDazb9y+wEA3UOV+rM5HBs2
H8Efdqe3Lp5g5yhqympvBejDe/VbSAU=
=WkWr
-----END PGP SIGNATURE-----
--imailsecure-test-boundary--
"""

    /// Fingerprint des primären Schlüssels, Großbuchstaben-Hex.
    static let fingerprint = "B8A6FDCCE27DA6F0779796CFB998F518D4E4F32E"

    /// Dieselben Nutzdaten, ein Zeichen verändert — die Signatur muss dann
    /// ungültig sein.
    static var tamperedPayload: String {
        var copy = payload
        copy.replaceSubrange(copy.startIndex...copy.startIndex, with: "X")
        return copy
    }
}
