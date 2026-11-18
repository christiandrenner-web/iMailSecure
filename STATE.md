# STATE — iMail Secure
Stand: 2026-11-18 · Branch: `main` · Letzter Code-Commit: `104380f` · Build: **SUCCEEDED** (iOS + macOS) · Tests: **191 Unit-Tests (4 übersprungen) + 3 UI-Tests grün** · PGP: FFI, Schlüsselbund, Signaturprüfung, Ver-/Entschlüsselung, WKD/Autocrypt, 13 Rust- und 69 Swift-Tests grün

## Ziel
App-Store-fähige Version: echte IMAP-Ordner, Datenschutz nach D2, Free/Pro ohne
beschnittene Schutzfunktionen. Keine offenen Code-Fehler bekannt.

## PGP und Push — Entscheidungen (2026-11-17)
- **Krypto: rpgp** (crates.io `pgp` 0.21.1, Apache-2.0/MIT) statt Sequoia
  (LGPL, statisches Linken wäre relink-pflichtig). Reines Rust, `default-features
  = false` schaltet BZip2 ab (kein C-Cross-Build); BZip2-komprimierte Nachrichten
  werden abgelehnt statt zu crashen. Fixiert per `=0.21.1` + `Cargo.lock`.
- **Roh-MIME:** `IMAPServer+Fetch.fetchRawMessage(identifier:)` liefert die
  vollständigen RFC822-Bytes ohne `\Seen`. Signaturprüfung braucht deshalb keine
  MIME-Rekonstruktion aus `Message` — das war der kritische Punkt für PGP/MIME.
- **Push: selbst betriebener Relay** (Docker auf NAS/VPS des Nutzers). Ein
  gehosteter Relay müsste IMAP-Zugangsdaten halten; „Zero-Knowledge-Relay“ ist
  bei IMAP nicht möglich. Zielumgebung (Domain, Server) noch offen.
- **Lizenz der FFI:** Apache-2.0/MIT wie rpgp, kein Lizenzkonflikt mit PolyForm
  Noncommercial; Quellcode liegt mit im Repo.

## Offen (max. 5, nach Schwere)
| # | Datei:Zeile | Symptom | Soll | Status |
|---|---|---|---|---|
| 1 | `Tests/iMailSecureTests/StoreKitPurchaseTests.swift` | Kaufpfad im Simulator nicht automatisch prüfbar: `xcodebuild` übergibt die StoreKit-Testkonfiguration nicht, `storekitd` fragt die Produktions-API | einmal in Xcode (Run mit `iMailSecure.storekit`) oder im Sandbox-Konto kaufen; Tests sind bis dahin per `IMAIL_STOREKIT_TESTS=1` opt-in | blockiert (Umgebung) |
| 2 | `imailsecure-site/terms.html` | Nutzungsbedingungen sind Entwurf, nicht anwaltlich geprüft; eigener EULA-Text für App Store Connect fehlt | juristisch prüfen, EULA erstellen, in Connect hinterlegen | Entwurf veröffentlicht |
| 3 | App Store Connect | Produkte, Abo-Gruppe, 7-Tage-Offer und eigene EULA fehlen | mit Apple-Developer-Account anlegen | offen |
| 4 | `imailsecure-site/*.html` | Website-Rechtstexte nur auf Deutsch | ES/FR/RU/TR ergänzen, wenn die Store-Einträge live gehen | offen |
| 5 | Push-Relay | Zielumgebung ungeklärt (Domain, NAS oder VPS, Docker), APNs-Key fehlt | mit Nutzer festlegen, dann Relay entwerfen (IMAP-IDLE-Worker, APNs, QR-Registrierung) | offen |

## Offene Entscheidungen
- S5 OAuth 2.0 · S6 Entwürfe speichern
- C1 PGP: entschieden (rpgp). S/MIME bleibt offen
- L1 Lizenz: entschieden (PolyForm Noncommercial 1.0.0), juristische Prüfung steht aus

## Zuletzt erledigt
- 2026-11-18 PGP-Verschlüsselung und Entschlüsselung: Neue FFI `imailpgp_encrypt`
  (AES-256 fest verdrahtet, mehrere Empfänger über einen Session-Schlüssel,
  Schlüsselbund `[UInt32 LE][Bytes]`) und `imailpgp_decrypt` (armoriert oder
  binär, eigener Status `IMAILPGP_DECRYPT_ERROR`). Verschlüsselt wird an den
  Verschlüsselungs-Subkey, nicht an den primären Signaturschlüssel. `PGPMIMEBuilder`
  baut `multipart/encrypted`; bei beiden Schaltern sign-then-encrypt. Fehlt auch
  nur einem Empfänger (inkl. BCC) der Schlüssel, bricht der Versand ab. Der
  Empfänger entschlüsselt mit `PGPDecryptor` aus dem Roh-MIME, prüft die innere
  Signatur mit demselben Verifier und sieht Text, Anhänge und Status im Banner;
  der Klartext wird nicht gespeichert. 14 neue Übersetzungen (331 Einträge),
  13 Rust-, 7 Swift-Tests, C-Smoke erweitert. 191 Unit-Tests grün
- 2026-11-18 Ausgehendes PGP-Signieren: Der Nutzer importiert seinen eigenen
  geheimen Schlüssel in `PGPPrivateKeyStore` — Keychain
  (`WhenUnlockedThisDeviceOnly`, kein iCloud-Sync), Schlüssel und Passphrase in
  getrennten Einträgen. Die FFI prüft die Passphrase vor dem Speichern und
  liefert Fingerprint und User-ID aus rpgp; die Import-UI zeigt beides erst als
  Vorschau. Neue FFI-Funktionen `imailpgp_secret_key_info` und
  `imailpgp_sign_detached` (SHA-256 fest verdrahtet, `micalg=pgp-sha256`),
  neuer Status `IMAILPGP_WRONG_PASSWORD -4`. `PGPMIMEBuilder` erzeugt
  `multipart/signed` mit CRLF-Rohbytes; Text und Anhänge sind base64-kodiert,
  damit die Nachricht auch ohne 8BITMIME rein ASCII bleibt. Signiert werden
  genau die Bytes, die der erste MIME-Teil später auf dem Server hat — die
  Gegenprobe läuft durch denselben Parser wie die eingehende Prüfung. BCC
  steht nur im SMTP-Umschlag, nie im Header; Zeilenlimits und Header-Injection
  sind in Tests abgedeckt. Der Schalter im Verfassen-Fenster erscheint nur,
  wenn für dieses Konto wirklich ein privater Schlüssel liegt; ohne Schlüssel
  bleibt der Versand unsigniert. 22 neue Übersetzungen (312 Einträge), 11 neue
  Swift- und 2 neue Rust-Tests, C-Smoke-Test um die neuen Symbole erweitert.
  Geprüft: 178 Unit-Tests (4 StoreKit opt-in), 10 Rust-Tests, iOS- und
  macOS-Build grün
- 2026-11-18 Kontrollierter Schlüsselbezug: WKD und Autocrypt, beides nur
  auf ausdrückliche Nutzeraktion — keine Hintergrundabfrage, kein Keyserver,
  keine stillen Importe. `WKDLookup` berechnet den Hash gemäß Spezifikation
  (z-base32(SHA-1(lokaler Teil))), probt zuerst `openpgpkey.<domain>` und dann
  die direkte Adresse, ausschließlich über HTTPS mit regulärer
  Zertifikatsprüfung; Umleitungen werden verworfen, damit nie ein Dritter
  von der Adresse erfährt. Ephemere Session ohne Cache und Cookies.
  `AutocryptHeader` liest `addr` und gefaltetes Base64 aus dem Kopf der
  geöffneten Nachricht; der Rohtext wird nicht über die Nachricht hinaus
  gespeichert. Neue Ansicht `PGPKeyLookupView`: Vorschau von Adresse,
  User-ID und Fingerprint, Übernahme erst nach Prüfung der Adresse gegen die
  User-ID — danach landet der Schlüssel im gewohnten Keychain-Schlüsselbund.
  Erweiterung der FFI um `imailpgp_armor_public_key`, weil WKD und Autocrypt
  Binärschlüssel liefern, der Bund aber armierte Texte speichert. 24 neue
  Texte im String Catalog (290 Einträge). Geprüft: 8 Rust-, 8 neue Swift-
  Tests (167 gesamt), iOS- und macOS-Build grün
- 2026-11-18 Eingehende PGP-Signaturprüfung: `MailSyncEngine` erkennt
  `multipart/signed` und `multipart/encrypted` an den MIME-Teilen; die
  Detailansicht lädt beim Öffnen einer signierten Mail die Rohbytes per
  `fetchRawMessage` (setzt kein `\Seen`) und zeigt ein Banner: gültig mit
  Fingerprint, ungültig, Schlüssel nicht hinterlegt (mit Aussteller) oder
  Prüfung nicht möglich. Verschlüsselte Mails werden ehrlich als solche
  markiert, nicht entschlüsselt.
  Neue Datei `Crypto/PGPSignature.swift`: RFC-3156-Parser, Prüfung über die
  Rohbytes des ersten Teils, Schlüsselwahl über den Signaturaussteller
  (`imailpgp_signature_issuer`, Fingerprint oder Key ID), Toleranz für
  CRLF/LF und das umstrittene abschließende Zeilenende. Keine Speicherung
  des Roh-MIME, keine stillen Netzwerkabfragen außer dem einen Abruf beim
  Öffnen. 13 neue Swift-Tests mit echt signierten Fixtures (CRLF, LF,
  manipuliert, fremder Schlüssel, S/MIME, Erkennung im Sync); 7 Rust-Tests,
  159 Unit-Tests gesamt (4 StoreKit opt-in), iOS- und macOS-Build grün
- 2026-11-17 PGP-Schlüsselbund: `PGPKeyStore` legt importierte öffentliche
  Schlüssel als JSON im Keychain ab (`io.imailsecure.pgpkeys`,
  `AfterFirstUnlockThisDeviceOnly`, kein iCloud-Sync), ein Eintrag pro
  normalisierter Adresse; erneuter Import ersetzt. Die FFI liefert jetzt auch
  die primäre User-ID (`imailpgp_primary_user_id`), der Wrapper führt sie in
  `PGPKeyInfo.userID`. Beim Import wird die Adresse aus der User-ID gegen die
  eingegebene geprüft und bei Abweichung abgelehnt (`emailMismatch`) — ein
  falsch zugeordneter Vertrauensanker wäre schlimmer als kein Schlüssel.
  Neue Ansichten `PGPKeysView`/`PGPKeyImportView` (Liste, Import per
  Einfügen, Löschen mit Rückfrage), Einstieg in den Einstellungen. 17 neue
  Texte im String Catalog, sechs Sprachen (253 Einträge). Geprüft: 6 Rust-
  und 16 Swift-Tests grün (146 gesamt, 4 StoreKit opt-in)
- 2026-11-17 PGP im App-Target: `PGPKit.xcframework` hängt als statische
  Bibliothek in iOS- und macOS-Target (`embed: false`), `import imailpgp`
  funktioniert ohne Brücken-Header. Swift-Wrapper
  `Sources/iMailSecure/Crypto/PGP.swift` (Schlüssel parsen, Fingerprint
  formatieren, abgetrennte Signatur prüfen) übersetzt die Int32-Codes in
  `PGPError`; „Signatur falsch“ bleibt von „nicht prüfbar“ unterscheidbar.
  Der Build-Skript baut jetzt auch beide Mac-Slices, das XCFramework hat drei
  Slices. Geprüft: 10 neue Swift-Tests grün (140 gesamt, 4 StoreKit opt-in),
  iOS- und macOS-Build grün, Release-Größendifferenz gemessen statt geschätzt:
  +876 KB Binary (45.191.032 → 46.067.704 Byte, Simulator arm64, Release,
  App-Bundle bleibt bei 44 MB). `swift build` war schon vorher kaputt
  (`Package.swift` nutzte `.v18`/`.v15` bei Tools 5.9); jetzt behoben und
  grün. `Tools/check-pgp-artifact.sh` bricht `xcodegen generate` mit klarer
  Meldung ab, wenn das Artefakt fehlt

- 2026-11-17 PGP-Fundament gelegt: `Crypto/pgp-ffi` bindet rpgp über eine
  C-Schnittstelle ein (`imailpgp.h`: Version, letzte Fehlermeldung, Schlüssel
  parsen, abgetrennte Signatur prüfen, Fingerprint). Panics werden an der
  Grenze abgefangen und als negative Int32 gemeldet, nie als Absturz.
  `Tools/build-pgp-ios.sh` baut Gerät, beide Simulator-Slices und beide
  Mac-Slices und erzeugt `Crypto/build/PGPKit.xcframework` (232 MB inkl.
  aller Slices, Geräte-Lib 46 MB vor Dead-Code-Stripping). Geprüft: 5 Host-Tests
  (`cargo test --release`, u. a. gültige/manipulierte Signatur und leere
  Nutzdaten) plus C-Smoke-Test gegen die Simulator-Slice im laufenden
  Simulator (ABI, Symbole, Fehlerpfade). Rust auf `1.100.0` gepinnt
  (`rust-toolchain.toml`), `Cargo.lock` eingecheckt, Build-Verzeichnisse in
  `.gitignore`. Ein abgebrochener Sequoia-Entwurf (`PGPBridge/`) ist entfernt —
  er widersprach der Entscheidung und hatte keinen Code

- 2026-11-14 Gesamtlauf grün: 130 Unit-Tests (4 StoreKit-Tests opt-in, übersprungen)
  und 3 UI-Tests (`FolderManagementUITests` ×2, `ScreenshotUITests`) auf dem
  iPad-Simulator. Vorher fielen drei Unit-Tests auf Türkisch um, weil der
  Screenshot-Lauf die Systemsprache des Simulators umstellt — die Test-Action
  pinnt jetzt `de`/`DE` (`project.yml`), unabhängig von der Gerätesprache.
  Ein UI-Lauf direkt nach dem Sprachwechsel scheiterte einmal mit „Ordner
  wurden nicht geladen“/leerem Posteingang; die beiden Läufe danach waren grün.
  Beobachten, ob das wieder auftritt (verdächtig: Zustand direkt nach
  Simulator-Neustart, nicht der Code)
- 2026-11-14 Screenshot-Satz geprüft: In `es-ES` und `tr` war das iPhone-Motiv
  „Nachricht“ pixelgleich mit dem Posteingang — der Tipp auf die Zeile hatte
  nicht navigiert, der Test fotografierte stillschweigend weiter. Behoben:
  Detailansicht hat den Anker `detail.root`, `openNewestMessage` tippt bei
  Bedarf erneut, und der Screenshot-Test schlägt fehl, statt eine Dublette
  abzulegen. Beide Sprachen neu aufgenommen, alle 48 Bilder unterscheiden
  sich jetzt paarweise (geprüft über Helligkeit und Pixelvergleich)
- 2026-11-13 Screenshots für sechs Sprachen und zwei Geräteklassen erzeugt
  (`fastlane screenshots`, 48 Bilder). Demo-Postfach und eigene Ordner werden
  je Sprache neu angelegt; Systemsprache der Simulatoren wird mitgesetzt,
  damit das iPad-Datum zur Sprache passt
- 2026-11-13 Schreib-Knopf erscheint nur noch im Posteingang — in den
  Einstellungen verdeckte er Formulare und Fußnoten
- 2026-11-13 Simulator-Durchklick: `FolderManagementUITests` bestehen —
  Ordner anlegen, umbenennen, löschen (serverseitig geprüft) und Free-Gate
  öffnet die Paywall. Neues UI-Test-Target `iMailSecureUITests`
- 2026-11-13 Screenshot-Pipeline: `fastlane snapshot` (Snapfile: 6 Sprachen ×
  iPhone 17 Pro Max / iPad Pro 13"), vier Motive je Sprache und Gerät,
  Demo-Mails im Testkonto, Pro über `-imaailTier pro` (nur `#if DEBUG`)
- 2026-11-13 Erkenntnis dokumentiert: `xcodebuild` schreibt
  `StoreKitConfigurationFileReference` nicht in die Test-Action/den
  `xctestrun`; `SKTestSession` liefert im iOS-26-Simulator `notEntitled`.
  `StoreKitPurchaseTests` sind deshalb opt-in (`IMAIL_STOREKIT_TESTS=1`)
- 2026-11-13 Lifetime-Produkt repariert: `isPro` und Kontolimit gelten jetzt auch für
  `Tier.lifetime` (`isEffectivelyPro`) — vorher blieb die Paywall offen und Pro war
  gesperrt. Tests für Lifetime ergänzt, 126 grün
- 2026-11-13 Paywall: „pro Monat/Jahr" erscheint nicht mehr beim Einmalkauf,
  Abo-Hinweis nur bei Abo-Produkten, eigener Lifetime-Hinweis; türkische
  Übersetzung `period.lifetime` war verstümmelt (Devanagari) und ist korrigiert
- 2026-11-13 Preise an den neuen Stand angeglichen (2,99 €/Monat, 24,99 €/Jahr,
  39,99 € Lifetime) in Store-Beschreibungen, App-Store-Guide, Audit-Notizen
- 2026-11-13 StoreKit-Konfiguration: Lifetime familienfreigabefähig, Produktnamen
  und -beschreibungen für alle sechs Sprachen
- 2026-11-12 Gmail-End-to-End bestanden (`mailprivacy.imail@gmail.com`, App-Passwort):
  TLS 1.2, Login, 9 Ordner, 5 Nachrichten, Anlegen/Umbenennen/Löschen mit Umlaut,
  APPEND, MOVE in `[Gmail]/Papierkorb`, UID EXPUNGE, keine Testordner zurück
- 2026-11-12 SMTP-Versand real bestätigt (`Tools/IMAPProbe --smtp`, 587 STARTTLS)
- 2026-11-12 Fehler gefunden und behoben: `[Gmail]/Wichtig` (\Important) wurde als
  „Markiert" erkannt; neue Rolle `.important` („Wichtig") statt Namens-Fallback
  auf `flagged`, 121 Tests grün
- 2026-11-12 Oberfläche in sechs Sprachen: `Localizable.xcstrings` (233 Einträge,
  Quellsprache Deutsch) und `InfoPlist.xcstrings` (Face-ID-Text, Anzeigename).
  Alle Modell- und Fehlertexte laufen über `String(localized:)`; Build enthält
  `de/en/es/fr/ru/tr.lproj`, 121 Tests grün
- 2026-11-12 `fastlane/metadata/` für de-DE, en-US, es-ES, fr-FR, ru, tr angelegt
  (Name, Untertitel, Keywords, Beschreibung, Promotional Text, Release Notes, URLs)
  plus `review_information/notes.txt`; Längenlimits geprüft
- 2026-11-12 GitHub-Repo `Fair-iMail` → `iMailSecure` umbenannt (alte URL leitet
  per 301 weiter), Quellcode-Link in App und Website angepasst
- 2026-11-12 Echter IMAP-Test gegen `imap.gmx.net` bestanden (Tools/IMAPProbe):
  Ordner, Rollen, Umbenennen, MOVE, UID EXPUNGE. Dabei zwei Fehler gefunden und
  behoben: modified UTF-7 in Ordnernamen und doppelte Systemordner bei GMX
- 2026-11-12 `terms.html` entworfen und veröffentlicht (AGB, Abo, Widerruf, Lizenz);
  Entwurf gekennzeichnet, anwaltliche Prüfung offen
- 2026-11-12 GitHub veröffentlicht: `iMailSecure` + `imailsecure-site`, Pages live,
  Kontaktadresse `chr.renner@mein.gmx` eingesetzt (`cd00da4`, `240bf3d`)
- 2026-11-11 `2db25c1` SwiftMail 1.16.0, Ordner umbenennen/löschen (109 Tests)
- 2026-11-11 `c41fa69` `defaultRequestMDN` wirkt jetzt in `ComposeViewModel` (103 Tests)
- 2026-11-03 `68e246b` IMAP-Ordner, Papierkorb, gemeinsamer Posteingang
- 2026-11-02 `52f2d99` Free/Pro (StoreKit 2), Apple-Trial, Multi-Account-Fix

## Nächster Schritt
1. Signaturprüfung an echten Konten gegenprobe: Eine signierte Mail von GMX
   oder Gmail öffnen und das Banner mit einem externen Verifier vergleichen.
2. WKD gegen einen echten Anbieter testen (z. B. eine Adresse bei Posteo),
   inklusive Rückfall von der erweiterten auf die direkte Methode.
3. Ausgehende Verschlüsselung: jetzt umgesetzt (siehe „Zuletzt erledigt").
4. Entschlüsselung von `multipart/encrypted`: jetzt umgesetzt; Rohbytes werden
   beim Öffnen geholt, nie gespeichert. Offen: Gegenprobe mit einer echten
   fremdsignierten Mail.
5. Push-Relay: Zielumgebung mit dem Nutzer festlegen (Domain, NAS oder VPS),
   dann IMAP-IDLE-Worker, APNs-Provider, Geräteregistrierung per QR und
   Docker-Deployment entwerfen.
6. Unverändert offen: Screenshots hochladen (`fastlane deliver`), Kaufpfad
   einmal in Xcode durchklicken, `terms.html` juristisch prüfen und EULA
   erstellen lassen, App-Store-Produkte anlegen, Website-Rechtstexte
   ES/FR/RU/TR ergänzen.
