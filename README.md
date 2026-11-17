# iMail Secure

Datenschutzfreundlicher E-Mail-Client für **iOS 18+** und **macOS 15+** (geplant)  
**Lizenz:** Dual Licensing — [PolyForm Noncommercial 1.0.0](LICENSE-NONCOMMERCIAL.md) (Privat, kostenlos) + [iMail Secure Commercial License](LICENSE-COMMERCIAL.md) (Unternehmen, entgeltlich)  
**Details:** [LICENSE.md](LICENSE.md) · [LICENSING.md](LICENSING.md)

---

## Features

- Vollständige IMAP/SMTP-Unterstützung (SwiftMail), ausschließlich TLS ≥ 1.2
- TOFU-Zertifikat-Pinning (SHA-256) für IMAP und SMTP
- Lesebestätigungen nach RFC 8098 (MDN)
- Empfangsbestätigungen (Return-Receipt-To)
- Passwörter ausschließlich im iOS/macOS-Keychain (`ThisDeviceOnly`)
- Tracking-Parameter-Entfernung in Links, Bestätigung vor externem Öffnen
- Kein Tracking, keine Werbung, keine Analyse- oder Tracking-SDKs, keine Telemetrie
- HTML nur auf Knopfdruck: Text ist Standard, HTML wird ohne Netzwerkzugriff gerendert
- Externe Inhalte blockiert — Freigabe nur pro Mail oder pro Absender-Adresse, jederzeit widerrufbar
- **iOS 18+**, **macOS 15+** (geplant), SwiftUI / SwiftUI für macOS
- Native Swift-Codebasis, gemeinsame Modelle & Services (iOS & macOS)

---

## Projektstruktur

```
iMailSecure/
├── AGENTS.md                 Datenschutz-Leitsätze + Arbeitsregeln (verbindlich)
├── CLAUDE.md                 Claude-spezifische Hinweise (verweist auf AGENTS.md)
├── AUDIT_NOTES.md            Security-Audit N1…C1 mit Status
├── LICENSING.md              Lizenz-/App-Store-Analyse
├── MONETIZATION.md           Free/Pro, Abo und StoreKit 2
├── LICENSE.md                Dual-Licensing-Übersicht
├── LICENSE-NONCOMMERCIAL.md  PolyForm Noncommercial 1.0.0 (Volltext)
├── LICENSE-COMMERCIAL.md     iMail Secure Commercial License (Volltext)
├── CLA.md                    Contributor License Agreement
├── Sources/iMailSecure/
│   ├── App/                  iMailSecureApp.swift, ContentView.swift
│   ├── Models/               EmailAccount, EmailMessage, EmailDraft, MDNNotification,
│   │                         MailFolder, Entitlement
│   ├── Managers/             AccountStore, MailStore, MailSyncEngine, SMTPManager,
│   │                         KeychainManager, CertificatePinner, RemoteContentPolicy,
│   │                         SubscriptionManager
│   ├── Services/             EmailHeaderBuilder, MDNProcessor, CoreDataService
│   ├── Crypto/               PGP.swift (Swift-Wrapper um die rpgp-FFI)
│   └── Views/                InboxView, FolderListView, MessageDetailView, ComposeView,
│                             SettingsView, PaywallView, …
├── Crypto/                   PGP-FFI (Rust/rpgp) + Bauanleitung + Testfixtures
├── Tools/                    Hilfsskripte, u. a. build-pgp-ios.sh
├── Tests/iMailSecureTests/   Unit Tests (iOS & macOS)
├── project.yml               XcodeGen-Quelle (verbindlich, Multi-Target: iOS + macOS)
└── Package.swift             SwiftPM-Definition (gleiche Pins wie project.yml)
```

---

## Setup

### Voraussetzungen

- macOS mit Xcode 16 oder neuer (getestet mit Xcode 27.1, Swift 6.4)
- iOS 18 SDK / macOS 15 SDK
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- Für OpenPGP (rpgp): Rust über [rustup](https://rustup.rs) — Details in
  [Crypto/README.md](Crypto/README.md)

### Projekt öffnen

```bash
cd ~/XCODE/iMailSecure   # oder dein lokaler Projektordner
Tools/build-pgp-ios.sh   # einmalig: baut Crypto/build/PGPKit.xcframework
xcodegen generate
open iMailSecure.xcodeproj
```

`iMailSecure.xcodeproj` ist **generiert**. Änderungen an Targets, Dateien oder Paketen
gehören in `project.yml`, danach `xcodegen generate` erneut ausführen. Ohne das
PGP-Artefakt scheitert `xcodegen generate` — es ist bewusst nicht eingecheckt.

### Bauen und testen

```bash
# iOS
xcodebuild -scheme iMailSecure \
  -destination 'platform=iOS Simulator,name=iPad Pro 13-inch (M5)' build

xcodebuild -scheme iMailSecure \
  -destination 'platform=iOS Simulator,name=iPad Pro 13-inch (M5)' test

# macOS (geplant)
xcodebuild -scheme iMailSecure-macOS \
  -destination 'platform=macOS' build
```

---

## Datenschutz-Leitsätze

Verbindlich dokumentiert in [AGENTS.md](AGENTS.md). Kurzfassung:

1. Keine Telemetrie, keine Analytics-, Crash- oder Werbe-SDKs
2. Kein Klartext, kein TLS-Downgrade — fail-closed
3. Remote-Inhalte standardmäßig blockiert
4. Keine Mail-Inhalte in Logs
5. Secrets nur im Keychain (`ThisDeviceOnly`), Kontodaten mit Dateischutz
6. Keine Daten an Dritte, keine Keyserver-Abfragen ohne Nutzeraktion
7. Tracking-Parameter entfernen, Ziele im Klartext bestätigen
8. Anhänge: Pfad-Sanitizing, eigener UUID-Ordner, FileProtection, Cleanup
9. Fehler nicht verschlucken
10. Schalter müssen wirken — UI-Toggle ohne Konsument ist ein Bug
11. Datenschutz ist nie kostenpflichtig — Pro verkauft Bequemlichkeit, nicht Sicherheit

---

## App Store Checklist

- [x] Datenschutz-Manifest (`PrivacyInfo.xcprivacy`, `NSPrivacyTracking = false`)
- [x] Passwörter nur im Keychain (kein UserDefaults, kein NSLog)
- [x] Keine externen Tracker
- [x] `NSAllowsArbitraryLoads = false` (ATS aktiv)
- [x] **Datenschutzerklärung erreichbar** — GitHub Pages aktiv, geprüft 2026-11-12:  
      https://christiandrenner-web.github.io/imailsecure-site/privacy.html
- [x] **Support-Adresse funktionsfähig** — `license@imailsecure.app` (iCloud+ Custom Domain)
- [ ] Code Signing: Apple Developer Account
- [ ] Provisioning Profile und Bundle ID: `io.imailsecure.app` (iOS) / `io.imailsecure.app.macos` (macOS)
- [ ] Icons in Assets.xcassets (1024×1024, macOS: 1024×1024 + Icons für Dock/Menu)
- [ ] Screenshots für alle unterstützten Geräte (iPhone, iPad, Mac)
- [ ] TestFlight-Beta vor Einreichung (iOS & macOS)
- [x] Lizenzentscheidung L1 getroffen: **Dual Licensing** (PolyForm Noncommercial + Commercial License)
- [ ] **Eigene EULA in App Store Connect hinterlegen** (sonst gilt Apples Standard-EULA)

---

## Lizenz

**Dual Licensing** (entschieden am 2026-11-14):

### Nicht-kommerziell (Privat, kostenlos)
- **PolyForm Noncommercial 1.0.0** → [LICENSE-NONCOMMERCIAL.md](LICENSE-NONCOMMERCIAL.md)
- Quellcode einsehbar und nachprüfbar
- **Keine** kommerzielle Nutzung durch Dritte

### Kommerziell (Unternehmen, Behörden, Freiberufler — entgeltlich)
- **iMail Secure Commercial License** → [LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)
- Modelle: Pro Seat (Abo), Enterprise Flat, Lifetime Seat, Revenue Share
- Preise: 2,99 €/Monat, 299 €/Jahr (Flat), 39,90 € Lifetime, 15 % Revenue Share

### Wichtige Hinweise
- **Kein Open Source** — die Bezeichnung „Open Source“ ist **untersagt**
- Korrekt: „Source-Available“, „Dual Licensed“, „Quellcode einsehbar“
- Weiterverbreitung nur unter Beachtung der jeweiligen Lizenz (Attribution Pflicht)
- Marke **„iMail Secure“** ist geschützt (DPMA, Klassen 9, 42) — Nutzung nur mit Erlaubnis
- Beiträge nur unter [CLA.md](CLA.md) — räumt kommerzielle Verwertung & Relizenzierung ein

Details zur Lizenzentscheidung, App-Store-Auswirkungen und Alternativen: [LICENSING.md](LICENSING.md)