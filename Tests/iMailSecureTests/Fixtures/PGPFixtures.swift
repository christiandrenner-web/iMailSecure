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

xjMEavu9GxYJKwYBBAHaRw8BAQdAj6x9pL7Ql53Z1OwuB+Z7ggBslkd3kNqzXtUr
58xuJ9PNLGlNYWlsIFNlY3VyZSBUZXN0IDx0ZXN0QGltYWlsc2VjdXJlLmludmFs
aWQ+wocEExYIAC8FAmr7vRsWIQRoIdCoLwQOY7DhyywlenVqQnacDQIbAgIeAQEL
AhUIARYBJwIZAQAKCRAlenVqQnacDbTrAQCHlUV7OqJAiGYRaUM2A6Nj0U7dkIil
53vXkGHHmrcGTwEAnpuRsP6S1yF7fK1aYh/nfvggdfkEwKc5ctrvZrjAIQ3OOARq
+70bEgorBgEEAZdVAQUBAQdAqiJFZVYj4+qVEgxIwsZrXKALSn9oVjtZxLomopsw
sQIDAQgHwngEGBYIACAFAmr7vRsCGwAWIQRoIdCoLwQOY7DhyywlenVqQnacDQAK
CRAlenVqQnacDZbmAQDvm2EwSwW5oxUl6isXlKyf2ayCHNHg3zzNgdP+p2W7dwD9
GR5sLK5tZFOMToeuqzjUuoRQ9/FVOBSQX4ygsMHedAc=
=AErd
-----END PGP PUBLIC KEY BLOCK-----
"""

    /// Zweiter, unabhängiger öffentlicher Schlüssel. `signature` ist nicht
    /// von ihm erzeugt und darf mit ihm nicht als gültig gelten.
    static let otherPublicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEavu9GxYJKwYBBAHaRw8BAQdAW/UrNolQZFZdqQReGDMUbGQWF8kpsHghyK5l
RNwDKjvNOGlNYWlsIFNlY3VyZSBGcmVtZHNjaGzDvHNzZWwgPG90aGVyQGltYWls
c2VjdXJlLmludmFsaWQ+wocEExYIAC8FAmr7vRsWIQSYMkiRTiJiWqKuD0zBFUJB
cDBMaAIbAgIeAQELAhUIARYBJwIZAQAKCRDBFUJBcDBMaCVKAPwIfmJy60gP6nPX
xHDWeCS5HjdNsRV4p40mRID+l6hyMwEA09fwSRR2GsFxwwLEv0HfZr82B2SJ1HRH
5GtOX8lMjg/OOARq+70bEgorBgEEAZdVAQUBAQdAKtZvInLzD96YQsnWuBCW2lFK
VDT6jg8CM9Y+M2NlUFcDAQgHwngEGBYIACAFAmr7vRsCGwAWIQSYMkiRTiJiWqKu
D0zBFUJBcDBMaAAKCRDBFUJBcDBMaE0KAQCoyuoFAVlwT9j/gBEDTsDQGmq3DfTP
Vtq2u9WNRHuqRAD/Y6LqC+ca5buM2Tf+u4lx6fH4/RK1p9XLnDfBMwOnOw0=
=KG5A
-----END PGP PUBLIC KEY BLOCK-----
"""

    /// Armierte abgetrennte Signatur über `payload`.
    static let signature = """
-----BEGIN PGP SIGNATURE-----

wnUEABYIAB0WIQRoIdCoLwQOY7DhyywlenVqQnacDQUCavu9GwAKCRAlenVqQnac
DToPAP9UGkSqK0RVD8ctj8D+g8DIBGzsvtzIlESOu+EcfL8GdgEAxsRigdazzlUa
pSBfOYPN7WDYQyjpEhF8AhkTqzdPnAI=
=7cli
-----END PGP SIGNATURE-----
"""

    /// Fingerprint des primären Schlüssels, Großbuchstaben-Hex.
    static let fingerprint = "6821D0A82F040E63B0E1CB2C257A756A42769C0D"

    /// Dieselben Nutzdaten, ein Zeichen verändert — die Signatur muss dann
    /// ungültig sein.
    static var tamperedPayload: String {
        var copy = payload
        copy.replaceSubrange(copy.startIndex...copy.startIndex, with: "X")
        return copy
    }
}
