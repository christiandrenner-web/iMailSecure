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

xjMEav2AyBYJKwYBBAHaRw8BAQdAQUBU1axscveB1euqHeNWNLLtSHJzy0QZbpQM
fXcmFIHNLGlNYWlsIFNlY3VyZSBUZXN0IDx0ZXN0QGltYWlsc2VjdXJlLmludmFs
aWQ+wocEExYIAC8FAmr9gMgWIQR7plMAN6j6uay/GSm4QAGwBFlC+QIbAgIeAQEL
AhUIARYBJwIZAQAKCRC4QAGwBFlC+R8WAP9M0lXV3sZpabb7FNWoldAorAslD7aA
7Da2TEBvRKnUfAD+KA/VnPkmnshaJGqqu/SImkrcVMRtubopegKF2AzLKwvOOARq
/YDIEgorBgEEAZdVAQUBAQdAzGz4HozZsy6lz00fs0AUF8FunAU/O5iXGhoTeM8Y
e30DAQgHwngEGBYIACAFAmr9gMgCGwAWIQR7plMAN6j6uay/GSm4QAGwBFlC+QAK
CRC4QAGwBFlC+ZpZAP9Wn4UetRgk4JygEAeWFEPfmVZRzifIGomZt110MOmuNgD/
baMfMkbO+zEmq5HRfAGQhS4HSPwcEarJtoH6Zq7DDQI=
=7Va1
-----END PGP PUBLIC KEY BLOCK-----
"""

    /// Zweiter, unabhängiger öffentlicher Schlüssel. `signature` ist nicht
    /// von ihm erzeugt und darf mit ihm nicht als gültig gelten.
    static let otherPublicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEav2AyBYJKwYBBAHaRw8BAQdAX1jGaOpGcWogY4vfVuU7ENIXa2n/Itrqqe9f
qBxdzI/NOGlNYWlsIFNlY3VyZSBGcmVtZHNjaGzDvHNzZWwgPG90aGVyQGltYWls
c2VjdXJlLmludmFsaWQ+wocEExYIAC8FAmr9gMgWIQRZCNHEt5a/olvnrFwuFuBB
/+gfxAIbAgIeAQELAhUIARYBJwIZAQAKCRAuFuBB/+gfxOjdAP9bgmBpYaajMxAG
a+qe/FXJktMI3nmYobhtw8SZ2nj53gEA+9gX+tHUHIX92vQhSeXY/1HIxDX+y9WQ
x3LGr6dcIgrOOARq/YDIEgorBgEEAZdVAQUBAQdAloFC6rGRTiWFj6dnaad2trYT
H5Wa/IPRSaG2mQBGEE4DAQgHwngEGBYIACAFAmr9gMgCGwAWIQRZCNHEt5a/olvn
rFwuFuBB/+gfxAAKCRAuFuBB/+gfxLaXAQDk49zFyOaT5AnVKpb4wR6f9yKF/SMJ
4p+epZcFlHo+ggEAhUrNWRg86qNd1HNuL5Fnx1wiLs/N2ARY0hYABMf+PgM=
=kGEB
-----END PGP PUBLIC KEY BLOCK-----
"""

    /// Armierte abgetrennte Signatur über `payload`.
    static let signature = """
-----BEGIN PGP SIGNATURE-----

wnUEABYIAB0WIQR7plMAN6j6uay/GSm4QAGwBFlC+QUCav2AyAAKCRC4QAGwBFlC
+fhaAP9Ajb1aqB2d5WKYB7onFwwyrGxt5Sc5T7B8cul4s3QFogD/RpLAAGM/mnDB
mHTGXRgd/nIpIpPEF/UtHLrW/rhIpQA=
=wEnr
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

wnUEABYIAB0WIQR7plMAN6j6uay/GSm4QAGwBFlC+QUCav2AyAAKCRC4QAGwBFlC
+XWYAQC1xV/dzD3HwI8KnlBV0XJ9424Wk7AK0sqsZnZdcIsdVAD/YsPhwmLZOLVp
IKS73zS6PfQLpu1efVEA9uGyp/pVhg0=
=uzYH
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

wnUEABYIAB0WIQR7plMAN6j6uay/GSm4QAGwBFlC+QUCav2AyAAKCRC4QAGwBFlC
+XWYAQC1xV/dzD3HwI8KnlBV0XJ9424Wk7AK0sqsZnZdcIsdVAD/YsPhwmLZOLVp
IKS73zS6PfQLpu1efVEA9uGyp/pVhg0=
=uzYH
-----END PGP SIGNATURE-----
--imailsecure-test-boundary--
"""

    /// Fingerprint des primären Schlüssels, Großbuchstaben-Hex.
    static let fingerprint = "7BA6530037A8FAB9ACBF1929B84001B0045942F9"

    /// Passphrasegeschützter geheimer Schlüssel für den ausgehenden Pfad.
    static let privateKey = """
-----BEGIN PGP PRIVATE KEY BLOCK-----

xYYEav2AyBYJKwYBBAHaRw8BAQdAUXzrL0+8CPxkakYtdkUwHRw/i6oFH1GUeFcK
hePS3OL+CQMIdgqVP8LxjMvgRygOqCzQozZqQvZn64GR35kEsGxiRtSEi1sEiJ4u
0dPr9T5vRtZUv2QmRypwukcSAEbAD6/GSuEToSW5ayxzm4MthHt0Ss0yaU1haWwg
U2VjdXJlIFNpZ25pbmcgPHNpZ25pbmdAaW1haWxzZWN1cmUuaW52YWxpZD7ChwQT
FggALwUCav2AyBYhBOq4tqze1GZimYZD3iIyLcGbQ8a2AhsCAh4BAQsCFQgBFgEn
AhkBAAoJECIyLcGbQ8a2MqcA/35wlKBSdytcNy2EqBsyNNBCLbDJneIVuFhoD36z
pU4pAP4q6vl0Fdwfhrl0eBE3XVS0pISgakv9GqRVG7wFEz+EAsddBGr9gMgSCisG
AQQBl1UBBQEBB0ByFuYnQfva35To7lcmqQVcyi0krWkAgGTicLCAE+CbQAMBCAcA
AP925DOGxQIbHc490PXX/5jQbwd8WVJG38soeKwjveA6qBGawngEGBYIACAFAmr9
gMgCGwAWIQTquLas3tRmYpmGQ94iMi3Bm0PGtgAKCRAiMi3Bm0PGtpWqAP4yYLAO
Wew4rIKBWFNkM0qrgNnai71CMPpurkaMT3oO3QEA+q/UTbpTLcjCIumWHkBonlsj
dWPhMvVifYmE91Y8rwk=
=aVXc
-----END PGP PRIVATE KEY BLOCK-----
"""

    /// Passphrase zum geheimen Schlüssel. Nur Testdaten.
    static let privateKeyPassphrase = "test-passphrase"

    /// Öffentlicher Gegenstand zum geheimen Schlüssel.
    static let privateKeyPublicKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

xjMEav2AyBYJKwYBBAHaRw8BAQdAUXzrL0+8CPxkakYtdkUwHRw/i6oFH1GUeFcK
hePS3OLNMmlNYWlsIFNlY3VyZSBTaWduaW5nIDxzaWduaW5nQGltYWlsc2VjdXJl
LmludmFsaWQ+wocEExYIAC8FAmr9gMgWIQTquLas3tRmYpmGQ94iMi3Bm0PGtgIb
AgIeAQELAhUIARYBJwIZAQAKCRAiMi3Bm0PGtjKnAP9+cJSgUncrXDcthKgbMjTQ
Qi2wyZ3iFbhYaA9+s6VOKQD+Kur5dBXcH4a5dHgRN11UtKSEoGpL/RqkVRu8BRM/
hALOOARq/YDIEgorBgEEAZdVAQUBAQdAchbmJ0H72t+U6O5XJqkFXMotJK1pAIBk
4nCwgBPgm0ADAQgHwngEGBYIACAFAmr9gMgCGwAWIQTquLas3tRmYpmGQ94iMi3B
m0PGtgAKCRAiMi3Bm0PGtpWqAP4yYLAOWew4rIKBWFNkM0qrgNnai71CMPpurkaM
T3oO3QEA+q/UTbpTLcjCIumWHkBonlsjdWPhMvVifYmE91Y8rwk=
=0QYR
-----END PGP PUBLIC KEY BLOCK-----
"""

    /// Fingerprint des geheimen Schlüssels.
    static let privateKeyFingerprint = "EAB8B6ACDED46662998643DE22322DC19B43C6B6"

    /// Dieselben Nutzdaten, ein Zeichen verändert — die Signatur muss dann
    /// ungültig sein.
    static var tamperedPayload: String {
        var copy = payload
        copy.replaceSubrange(copy.startIndex...copy.startIndex, with: "X")
        return copy
    }
}
