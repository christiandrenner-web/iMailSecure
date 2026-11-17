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

Ergebnis: `Crypto/build/PGPKit.xcframework` (Gerät + Simulator, inkl.
`module.modulemap`, damit Swift `import imailpgp` kann). Das Verzeichnis ist
Build-Artefakt und nicht eingecheckt; `Cargo.lock` und `rust-toolchain.toml`
sind eingecheckt, damit der Build reproduzierbar bleibt.

## Tests

```bash
cd Crypto/pgp-ffi && cargo test --release
```

Deckt ab: Schlüsselerzeugung, abgetrennte Signatur (gültig, manipuliert,
leere Nutzdaten), Parsen von Schlüssel und Müll, Fingerprint. Die Kryptographie ist
plattformunabhängig; der iOS-Build wird zusätzlich mit
`Crypto/pgp-ffi/smoke.c` gegen die Simulator-Slice geprüft (ABI, Symbole,
Rückgabewerte):

```bash
SDK=$(xcrun --sdk iphonesimulator --show-sdk-path)
clang -target arm64-apple-ios18.0-simulator -isysroot "$SDK" \
  -ICrypto/pgp-ffi/include Crypto/pgp-ffi/smoke.c \
  Crypto/build/libimailpgp-simulator.a -o /tmp/imailpgp-smoke
xcrun simctl spawn booted /tmp/imailpgp-smoke
```

## Stand

| Funktion | Status |
|---|---|
| `imailpgp_version`, `imailpgp_last_error` | fertig |
| `imailpgp_parse_public_key` | fertig |
| `imailpgp_verify_detached` | fertig |
| `imailpgp_primary_fingerprint` | fertig |
| Signieren ausgehend | offen |
| Ent-/Verschlüsseln (`MessageBuilder`, `Message`) | offen |
| Schlüsselbund, Passphrase-Schutz (Secure Enclave) | offen |

Fehler werden als negative Int32 gemeldet, nie als Panic über die Grenze:
Jede Funktion fängt Panics ab und legt eine thread-lokale Meldung in
`imailpgp_last_error` ab.

## Einbindung in Xcode (nächster Schritt)

1. `Tools/build-pgp-ios.sh` ausführen (oder als Build-Phase, wenn der
   XCFramework-Weg zu langsam ist).
2. In `project.yml` unter `targets.iMailSecure` als Framework einbinden,
   `embed: false` (statisch).
3. Dünnen Swift-Wrapper `Sources/iMailSecure/Crypto/PGP.swift` schreiben, der
   `Data` in `withUnsafeBytes` übergibt und die Int32-Codes in Swift-Fehler
   übersetzt.

Die statische Geräte-Bibliothek ist vor dem Linken ~46 MB; nach
Dead-Code-Stripping bleibt ein Bruchteil davon im App-Binary. Der tatsächliche
Zuwachs wird gemessen, sobald das Framework im Target hängt — nicht geschätzt.
