# PGP-FFI (Crypto/pgp-ffi)

C-Schnittstelle zu [rpgp](https://github.com/rpgp/rpgp) für iMail Secure.
Rust-Code wird als statische Bibliothek für Gerät und Simulator gebaut und als
`PGPKit.xcframework` in die App eingebunden. Swift ruft ausschließlich die
Funktionen aus `include/imailpgp.h` auf — kein Rust-Typ überschreitet die
Grenze.

## Warum rpgp und nicht Sequoia

| | rpgp (`pgp` 0.21.1) | Sequoia |
|---|---|---|
| Lizenz | MIT **oder** Apache-2.0 | LGPL-2.0-or-later |
| App-Store-Verträglichkeit | unkritisch | statisches Linken verlangt Relink-Möglichkeit |
| Abhängigkeiten | pures Rust | Nettle/GMP (C) oder experimentelles RustCrypto-Backend |
| Verbreitung | produktiv in Delta Chat | GnuPG-nah, sehr verbreitet |

Bei einer kommerziellen App mit PolyForm-Noncommercial-Lizenz ist die
Lizenzfrage entscheidend: Apache-2.0 stellt keine Bedingungen an das
Gesamtwerk, LGPL schon. Deshalb rpgp.

`default-features = false` schaltet BZip2 ab. Das würde `bzip2-sys` (C)
nachziehen und müsste für iOS cross-compiled werden. Nachrichten mit
BZip2-Kompression werden abgelehnt statt zu crashen; das ist bei Mail selten.

## Bauen

```bash
rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios
Tools/build-pgp-ios.sh          # Release
Tools/build-pgp-ios.sh --debug  # schneller, größer
```

Ergebnis: `Crypto/build/PGPKit.xcframework` mit drei Slices: Gerät, Simulator
(arm64 + x86_64) und macOS (arm64 + x86_64), inkl. `module.modulemap`, damit
Swift `import imailpgp` kann. Das Verzeichnis ist Build-Artefakt und nicht
eingecheckt; `Cargo.lock` und `rust-toolchain.toml` sind eingecheckt, damit der
Build reproduzierbar bleibt.

## Tests

```bash
cd Crypto/pgp-ffi && cargo test --release
```

Deckt ab: Schlüsselerzeugung (auch passphrasegeschützt), abgetrennte Signatur
(gültig, manipuliert, leere Nutzdaten), Passphrase-Prüfung, armierte Schlüssel
und Signaturen, Parsen von Müll, Fingerprint, User-ID, Signaturaussteller und
Armierung, Verschlüsselung (ein und mehrere Empfänger, Session-Schlüssel,
Subkey-Wahl) und Entschlüsselung (armoriert und binär, Manipulation, fremder
Schlüssel, Passphrase). 13 Rust-Tests sind grün. Die Kryptographie ist
plattformunabhängig; der iOS-Build wird
zusätzlich mit `Crypto/pgp-ffi/smoke.c` gegen die Simulator-Slice geprüft
(ABI, Symbole, Rückgabewerte):

```bash
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
clang -target arm64-apple-ios18.0-simulator -isysroot "$SDK" \
  -ICrypto/pgp-ffi/include Crypto/pgp-ffi/smoke.c \
  Crypto/build/libimailpgp-simulator.a -o /tmp/imailpgp-smoke
xcrun simctl spawn booted /tmp/imailpgp-smoke
```

Die Swift-Seite prüft `PGPTests.swift`, `PGPKeyStoreTests.swift`,
`PGPSignatureTests.swift`, `PGPKeyDiscoveryTests.swift`, `PGPOutgoingTests.swift`,
`PGPPrivateKeyStoreTests.swift`, `PGPDecryptorTests.swift`,
`PGPExternalMessageTests.swift` und `WKDRealWorldTests.swift` gegen dieselbe
Bibliothek (194 Unit-Tests gesamt, 6 opt-in-Tests übersprungen: 4 StoreKit,
2 WKD-Netzwerk). Die Netzwerk-Tests laufen mit
`IMAIL_NETWORK_TESTS=1 xcodebuild … test`. Die selbst erzeugten Testdaten
liegen in `Tests/iMailSecureTests/Fixtures/PGPFixtures.swift` und werden
erzeugt mit:

```bash
cd Crypto/pgp-ffi && cargo run --release --example make_fixtures
```

## Stand

| Funktion | Status |
|---|---|
| `imailpgp_version`, `imailpgp_last_error` | fertig |
| `imailpgp_parse_public_key` | fertig |
| `imailpgp_verify_detached` | fertig |
| `imailpgp_primary_fingerprint` | fertig |
| `imailpgp_primary_user_id` | fertig |
| `imailpgp_signature_issuer` | fertig |
| `imailpgp_armor_public_key` | fertig |
| `imailpgp_secret_key_info` (Passphrase, Fingerprint, User-ID) | fertig |
| `imailpgp_sign_detached` (SHA-256, armoriert) | fertig |
| `imailpgp_encrypt` (AES-256, mehrere Empfänger) | fertig |
| `imailpgp_decrypt` (eigener Fehlercode `-5`) | fertig |
| Swift-Wrapper `PGP.swift` (sign, encrypt, decrypt) | fertig |
| Schlüsselbund `PGPKeyStore` (Keychain) + Import-UI | fertig |
| Eingehende Signaturprüfung (`PGPSignature.swift`) | fertig |
| WKD (`WKDLookup.swift`) und Autocrypt (`AutocryptHeader.swift`) | fertig |
| Geheime Schlüssel `PGPPrivateKeyStore` + Import-UI | fertig |
| Signieren ausgehend (`PGPMIMEBuilder`, `multipart/signed`) | fertig |
| Verschlüsseln ausgehend (`PGPMIMEBuilder`, `multipart/encrypted`) | fertig |
| Entschlüsseln eingehend (`PGPDecryptor`, Klartext nie gespeichert) | fertig |
| Passphrase-Schutz des geheimen Schlüssels (Keychain `ThisDeviceOnly`) | fertig |

Die Secure Enclave speichert nur P-256-Schlüssel; OpenPGP-Schlüssel bleiben
deshalb im Keychain mit `ThisDeviceOnly`-Zugriff und ohne iCloud-Synchronisation.

WKD und Autocrypt liefern Binärschlüssel, der Bund speichert armierte Texte.
`imailpgp_armor_public_key` macht die Umwandlung in Rust — Swift baut keine
OpenPGP-Pakete. WKD-Abfragen laufen nur auf ausdrücklichen Knopfdruck,
ausschließlich per HTTPS an die Domain der Adresse (erweiterte Methode, dann
direkt), ohne Redirects, ohne Cache und ohne Cookies. Ein Autocrypt-Header
wird nur aus dem Kopf der geöffneten Nachricht gelesen. Beide Wege zeigen
zuerst den Fingerprint; ein Import erfolgt nie still und nur, wenn die
User-ID zur Adresse passt.

## Ausgehendes Signieren

`PGPMIMEBuilder` erzeugt `multipart/signed` nach RFC 3156. Der erste MIME-Teil
wird als Rohbytes gebaut und genau so signiert, wie er auf dem Server liegt —
mit CRLF als Zeilenende und ohne das Zeilenende vor der Grenzlinie. Die
Signatur ist SHA-256 (`micalg=pgp-sha256`), Text und Anhänge sind base64 in
Zeilen à 76 Zeichen kodiert; die Nachricht bleibt damit rein ASCII und läuft
auch über Server ohne 8BITMIME. BCC steht nur im SMTP-Umschlag, nie im Header.
`SMTPManager` benutzt für signierte Mail `sendRawMessage`, damit SwiftMail den
signierten Teil nicht neu zusammenstellt und die Prüfsumme ungültig wird.

Der Schalter „Digital signieren" im Verfassen-Fenster erscheint nur, wenn für
das Konto ein privater Schlüssel hinterlegt ist. Ohne Schlüssel bleibt der
Versand unsigniert. `PGPOutgoingTests` prüft den Rundlauf durch den
eingehenden Parser, Manipulation von Text und Anhang, Header-Injection und
die SMTP-Zeilengrenzen.

Fehler werden als negative Int32 gemeldet, nie als Panic über die Grenze:
Jede Funktion fängt Panics ab und legt eine thread-lokale Meldung in
`imailpgp_last_error` ab.

## Ver- und Entschlüsselung

`PGPMIMEBuilder` baut `multipart/encrypted` nach RFC 3156. AES-256 ist fest
verdrahtet; mehrere Empfänger teilen einen Session-Schlüssel, damit die Mail
nur einmal verschlüsselt wird. Verschlüsselt wird an den
Verschlüsselungs-Subkey (ECDH), nicht an den primären Signaturschlüssel. Der
Schlüsselbund wird als `[UInt32 little-endian Länge][Schlüsselbytes]…` an die
FFI übergeben. Fehlt für auch nur einen Empfänger — BCC eingeschlossen — ein
öffentlicher Schlüssel, bricht der Versand mit `PGPEncryptionError.missingKey`
ab; es geht keine halb verschlüsselte Mail raus.

Sind Signieren und Verschlüsseln beide aktiv, gilt sign-then-encrypt: Der
`multipart/signed`-Block wird ohne RFC-822-Kopf als Ganzes verschlüsselt. Der
Empfänger entschlüsselt mit `PGPDecryptor` aus den rohen MIME-Bytes, die
`MailSyncEngine` ohne `\Seen` holt, prüft die innere Signatur mit demselben
Verifier und sieht Text, Anhänge und Status im Banner. Der Klartext wird nie
gespeichert — die Anzeige ist bei jedem Öffnen eine frische Prüfung.

`PGPDecryptorTests` prüft den Rundlauf durch den eingehenden Parser:
verschlüsselt, signiert plus verschlüsselt, Anhänge (auch `text/plain`),
fremder Schlüssel, Klartext-Mail und fehlender lokaler Schlüssel.

## Gegenproben gegen andere Implementierungen

Ein Rundlauf innerhalb derselben Bibliothek beweist keine Interoperabilität.
Deshalb gibt es echte Gegenproben:

- `PGPExternalMessageTests` verarbeitet eine Nachricht, die vollständig von
  **GnuPG 2.5** stammt — beide Wegwerfschlüssel, die Signatur und die
  Verschlüsselung (Fixture in `Fixtures/PGPExternalFixtures.swift`). Sie wurde
  zusätzlich über Gmail SMTP versendet und per IMAP zurückgeholt; der
  Entschlüssler verarbeitete genau die zurückgeholten Rohbytes. Umgekehrt
  verifiziert GnuPG die von rpgp erzeugte Fixture-Signatur, sofern die Payload
  ohne abschließendes `\n` übergeben wird (Swift-Multiline-Strings haben kein
  abschließendes Zeilenende).
- `WKDRealWorldTests` (opt-in) fragt echte Server ab:
  `bernhard.reiter@intevation.de` liefert über die direkte Methode den
  Fingerprint `BDD957F9C4FE0FDC583DCD6D2B7BA3BF9BC3A554`; eine unbekannte
  Posteo-Adresse muss `notFound` ergeben.

**Dabei gefunden und behoben:** GnuPG 2.4+ verschlüsselt mit AEAD-Paket Typ 20
(OCB), das rpgp standardmäßig ablehnt. `imailpgp_decrypt` aktiviert gezielt
`DecryptionOptions::new().enable_gnupg_aead()` über einen `TheRing`; OCB prüft
die Integrität. Das alte, manipulierbare SED-Paket (Typ 9) bleibt abgelehnt.
Außerdem merkt sich `WKDLookup` ein explizites 404, damit ein Netzwerkfehler
auf der erweiterten Adresse die treffendere „kein Schlüssel"-Meldung der
direkten Adresse nicht überschreibt.

## Einbindung in Xcode

1. `Tools/build-pgp-ios.sh` ausführen (Artefakt ist nicht eingecheckt).
2. `project.yml` bindet `Crypto/build/PGPKit.xcframework` in beide
   App-Targets ein, `embed: false` (statische Bibliothek).
3. `Sources/iMailSecure/Crypto/PGP.swift` reicht `Data` per `withUnsafeBytes`
   durch und übersetzt die Int32-Codes in `PGPError`.

Die statische Geräte-Bibliothek ist vor dem Linken ~46 MB; im App-Binary bleibt
davon nur, was tatsächlich referenziert wird. Die gemessene Differenz steht in
`STATE.md`.
