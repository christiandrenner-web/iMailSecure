# MONETIZATION.md — Free, Pro, Enterprise & Commercial Licensing (iMail Secure)

**Stand:** 2026-11-15 · **Status:** Dual Licensing finalisiert, App Store Produkte teilweise offen

*Keine Rechtsberatung. Preise, AGB, EULA und Commercial License vor dem Livegang prüfen lassen.*

---

## Kurzfassung

| Frage | Antwort |
|---|---|
| **Lizenzmodell** | **Dual Licensing** — Noncommercial (Privat, kostenlos) + Commercial (Firmen, entgeltlich) |
| **App Store (iOS/macOS)** | Free Tier + Pro-Abo (StoreKit 2) + Lifetime (Non-Consumable) |
| **Direktvertrieb (B2B)** | Enterprise Flat (299 €/Jahr), Revenue Share (15 % Netto-Umsatz) |
| **Testphase** | **7 Tage gratis** über Apples Introductory Offer (App Store) |
| **Preise (App Store)** | 2,99 €/Monat, 24,99 €/Jahr, **39,90 € Lifetime** (Apple-Kleinstunternehmer: 15 % Provision) |
| **Preise (Direkt)** | Enterprise Flat 299 €/Jahr (unbegrenzt Nutzer), Revenue Share 15 % |
| **Pro-Inhalt (App Store)** | Mehrere Konten, alle Server-Ordner, eigene Ordner anlegen/umbenennen/löschen, gemeinsamer Posteingang |
| **Nie Pro** | Datenschutzfunktionen (Leitsatz 11 `AGENTS.md`) — **auch in Commercial License** |
| **Technik** | StoreKit 2 (App Store) + License Key (Direkt) — **kein Backend**, keine Drittanbieter-SDKs |
| **Datenweitergabe** | Keine an Entwickler; Zahlungsdaten: Apple (App Store) / Stripe/LemonSqueezy (Direkt) |

---

## 1. Dual Licensing — Zwei Vertriebswege

### 1.1 App Store (B2C / KMU < 10 Seats)
- **Free Tier:** 1 Konto, alle Datenschutz-Features, Systemordner
- **Pro Seat (Abo):** 2,99 €/Monat oder 24,99 €/Jahr pro Nutzer
- **Lifetime Seat:** 39,90 € einmalig pro Nutzer
- **Introductory Offer:** 7 Tage gratis (Apple-gemanagt)
- **Family Sharing:** Ja (bis 5 Familienmitglieder)
- **Plattformen:** iOS 18+ & macOS 15+ (universal purchase geplant)

### 1.2 Direktvertrieb (B2B / Enterprise / Reseller)
| Modell | Zielgruppe | Preis | Vertrieb |
|---|---|---|---|
| **Enterprise Flat** | Unternehmen, Behörden, Teams | 299 €/Jahr (unbegrenzt Nutzer *einer* Org) | License Key per E-Mail (`license@imailsecure.app`) |
| **Revenue Share** | SaaS-Anbieter, Hosting, MSP | 15 % Netto-Umsatz | Einzelvertrag + Reporting |
| **Pro Seat (Direkt)** | Firmen ohne App Store (z. B. MDM) | 29,90 €/Jahr/Nutzer | License Key + Volume Discount |

**Volume Discount (Direkt):** Ab 10 Seats 10 %, ab 50 Seats 20 %.

---

## 2. Free vs. Pro vs. Enterprise (Feature-Matrix)

| Feature | Free | Pro (App Store) | Enterprise (Direkt) |
|---|---|---|---|
| Konten | 1 | Unbegrenzt | Unbegrenzt |
| Server-Ordner | Posteingang + System | Alle + eigene | Alle + eigene |
| Eigene Ordner anlegen | ❌ | ✅ | ✅ |
| Gemeinsamer Posteingang | ❌ | ✅ | ✅ |
| Datenschutz-Features (Pinning, HTML-Blocker, etc.) | ✅ | ✅ | ✅ |
| Support | Community (GitHub Issues) | E-Mail (`support@`) | Priority E-Mail + SLA (optional) |
| Updates | Automatisch (App Store) | Automatisch | Automatisch (App Store) oder manuell |
| Lizenzverwaltung | Apple ID | Apple ID | Eigenes License Key Portal (geplant) |

**Wichtig:** Datenschutz-Features sind **niemals** hinter Paywall (Leitsatz 11 `AGENTS.md`).

---

## 3. Technische Umsetzung

### 3.1 App Store (StoreKit 2)
```swift
// Sources/iMailSecure/Models/Entitlement.swift
enum Tier: String, Codable { case free, pro, enterprise }

struct Entitlement {
    static let proMonthly = "io.imailsecure.pro.monthly"
    static let proYearly  = "io.imailsecure.pro.yearly"
    static let lifetime   = "io.imailsecure.pro.lifetime"
    static let enterprise = "io.imailsecure.enterprise.yearly" // zukünftig
}
```
- `SubscriptionManager`: StoreKit 2 Listener, `Transaction.currentEntitlements` Prüfung on-device
- **Kein Backend** — Apple signiert Transaktionen
- Paywall lädt Produkte **erst bei Bedarf** (kein Netzwerk bei App-Start)
- Offline-Fallback: letzter bekannter Status im Keychain (`fail-closed` → `free`)

### 3.2 Direktvertrieb (License Key)
- **Enterprise / Revenue Share:** separater License Key (AES-256 signiert, Ed25519)
- Key enthält: Tier, Organisation, Gültigkeit, Seat-Limit, Features
- Prüfung: `LicenseValidator.verify(key:)` → lokal, kein Netzwerk
- Key-Verwaltung: initial manuell per E-Mail, später Self-Service-Portal (geplant)

### 3.3 Code-Gates (zentral in `Entitlement.swift`)
```swift
extension Entitlement {
    func canUse(_ feature: Feature) -> Bool { ... }
    var maxAccounts: Int { tier == .free ? 1 : Int.max }
}
```
| Datei | Gate |
|---|---|
| `SettingsView` | „Konto hinzufügen“ → Paywall bei Limit |
| `AccountSetupView.saveAccount()` | Zweite Sicherung |
| `FolderListView` | Gemeinsamer Posteingang / eigene Ordner → Paywall |
| `MainTabView` | Multi-Account: Versand-Konto wählen |

---

## 4. Verhalten bei Lizenzende / Downgrade

| Szenario | Verhalten |
|---|---|
| Abo läuft aus (App Store) | Zusatzkonten **lesbar**, **nicht mehr syncbar** — keine Datenlöschung |
| Lifetime / Enterprise endet | Gleich — Daten bleiben, Sync stoppt |
| Revenue Share Vertrag ende | Gleich — Daten bleiben, Sync stoppt |
| Key ungültig / widerrufen | 14 Tage Grace Period (Read-Only), dann `free` Tier |

**Regel:** Lizenzende = **keine Datenvernichtung**. Export-Funktion (EML, JSON) immer verfügbar.

---

## 5. App Store Pflichten (Guideline 3.1.2, 5.2, 5.3)

| Pflicht | Status | Hinweis |
|---|---|---|
| Produkte anlegen (Monthly, Yearly, Lifetime) | 🔴 Offen | App Store Connect |
| Introductory Offer (7 Tage) | 🔴 Offen | App Store Connect |
| Family Sharing (Abo-Gruppe + Lifetime) | 🔴 Offen | App Store Connect |
| **Eigene EULA hinterlegen** | 🔴 **Kritisch** | Text aus `LICENSE-COMMERCIAL.md` + Noncommercial-Hinweis |
| `terms.html` (Nutzungsbedingungen) verlinken | 🟡 Entwurf online | Anwaltsprüfung offen |
| „Käufe wiederherstellen“ | ✅ Implementiert | Settings + Paywall |
| Preise/Laufzeit/Auto-Renew sichtbar | ✅ Via StoreKit | Paywall liest aus StoreKit |
| Apple-Kleinstunternehmer (15 %) | 🟡 Geplant | < 1 Mio. USD/Jahr |
| Datenschutzerklärung: Apple-Zahlung | 🟡 Offen | Ergänzen |
| **Universal Purchase (iOS + macOS)** | 🟡 Geplant | Same Bundle ID Suffix |

---

## 6. B2B-Vertrieb (Direkt) — Prozess

1. **Anfrage** an `license@imailsecure.app`
2. **Angebot** innerhalb 2 Werktage (PDF, Preise, Laufzeit, SLA optional)
3. **Vertragsschluss** per E-Mail-Bestätigung oder DocuSign/Signatur.it
4. **License Key** Generierung (Skript) → Versand per E-Mail
5. **Rechnung** (Stripe/LemonSqueezy oder manuell) — USt. nach § 19 UStG (Kleinunternehmer) oder Regelbesteuerung
6. **Support** per E-Mail, SLA nur bei Enterprise-Flat (optional)

**Revenue Share:** Monatliches Reporting (Netto-Umsatz × 15 %) → Rechnung.

---

## 7. Preise — Begründung & Anpassung

| Modell | Preis | Begründung |
|---|---|---|
| Pro Monthly | 2,99 € | Psychologische Schwelle < 3 €, konkurrenzfähig (Spark, Edison, etc.) |
| Pro Yearly | 24,99 € | ~30 % Rabatt, Cashflow-Vorteil |
| Lifetime | 39,90 € | ~13 × Monthly — „No-Brainer“ für Power-User |
| Enterprise Flat | 299 €/Jahr | < 10 Seats = günstiger als Pro, > 10 = deutliche Ersparnis |
| Revenue Share | 15 % | Standard für Embedded/White-Label-ähnliche Nutzung |

**Preisanpassung:** 60 Tage Vorankündigung, Bestandsabo läuft zu alten Konditionen weiter.

---

## 8. Offen (Stand 2026-11-15)

- [ ] Produkte + Introductory Offer + Lifetime in App Store Connect anlegen
- [ ] Family Sharing aktivieren
- [ ] **EULA in App Store Connect** hinterlegen (Text finalisieren)
- [ ] Steuer- & Bankdaten in App Store Connect
- [ ] Apple-Kleinstunternehmer beantragen
- [ ] `license@imailsecure.app` (iCloud+ Custom Domain) einrichten
- [ ] `imailsecure.app` Domain registrieren
- [ ] License Key Generator für Enterprise/Revenue Share bauen (Swift, CLI)
- [ ] Self-Service-Portal (später, nach erstem B2B-Kunden)
- [ ] Universal Purchase (iOS + macOS) konfigurieren