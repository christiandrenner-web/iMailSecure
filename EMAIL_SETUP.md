# E-Mail-Setup für iMail Secure

**Stand:** 2026-11-15  
**Ziel:** Professionelle E-Mail-Adressen unter `imailsecure.app` (oder Alternative) für Lizenz, Support, Datenschutz, Impressum.

---

## 1. Domain registrieren

| Domain | Status | Kosten/Jahr | Anbieter-Empfehlung |
|---|---|---|---|
| `imailsecure.app` | **bevorzugt** (kurz, .app = HTTPS erzwungen) | ~20 € | Namecheap, Porkbun, Netcup, IONOS |
| `imailsecure.de` | Alternative für DACH-Fokus | ~12 € | DENIC-Mitglieder (Netcup, etc.) |
| `fairimail.io` | **nicht empfohlen** (Verwechslung mit Ordnername) | ~30 € | — |

**Empfehlung:** `imailsecure.app` bei **Porkbun** oder **Namecheap** registrieren (günstig, kostenlose WHOIS-Privacy, gute API).

---

## 2. E-Mail-Hosting: iCloud+ Custom Domain (günstigste Variante)

### Kosten
- **iCloud+ 50 GB:** 0,99 €/Monat = **~12 €/Jahr**
- Enthält: Custom Domain, Hide My Email, Private Relay, 50 GB Speicher

### Setup (in 10 Min)
1. **iCloud+ abonnieren** (Einstellungen → Dein Name → iCloud → Speicher verwalten → Plan ändern → 50 GB)
2. **Custom Domain einrichten:**
   - Einstellungen → Dein Name → iCloud → iCloud Mail → Custom Domain
   - Domain `imailsecure.app` hinzufügen
   - DNS-Einträge beim Registrar setzen (Porkbun/Namecheap: „iCloud“ Vorlage oder manuell):
     - `MX` → `mx01.mail.icloud.com` (Priority 10)
     - `MX` → `mx02.mail.icloud.com` (Priority 20)
     - `TXT` → `apple-domain-verification=...` (Apple generiert)
     - `CNAME` → `sig1._domainkey.imailsecure.app` → `sig1.dkim.icloud.com`
     - `CNAME` → `sig2._domainkey.imailsecure.app` → `sig2.dkim.icloud.com`
3. **E-Mail-Adressen anlegen:**
   - `license@imailsecure.app` — Lizenzanfragen, Enterprise, Revenue Share
   - `support@imailsecure.app` — Nutzer-Support, Bug-Reports
   - `privacy@imailsecure.app` — Datenschutzanfragen (DSGVO Art. 13)
   - `legal@imailsecure.app` — Impressum, Abmahnungen, Rechtsfragen
   - `hello@imailsecure.app` — Allgemeiner Kontakt (optional)
4. **Standard-Absender festlegen:** `license@` oder `support@`

### Vorteile
- **Kein separater Mailserver** — Apple betreibt Infrastruktur
- **DSGVO-konform** (EU-Rechenzentren, AVV abschließbar)
- **Ende-zu-Ende-verschlüsselt** (bei aktiviertem Advanced Data Protection)
- **Keine zusätzlichen Kosten** über iCloud+ hinaus
- **Einfach** — keine SPF/DKIM/DMARC manuell pflegen

### Nachteile
- **Kein Webmail** (nur Mail.app / iCloud.com)
- **Keine Shared Mailbox** (Team-Zugriff nur über Weiterleitung/Regeln)
- **Limit:** 5 Custom Domains, 3 Adressen pro Domain (reicht für Start)

---

## 3. Alternative: Mailbox.org (professioneller, Team-fähig)

### Kosten
- **Light (1 Mailbox):** 1 €/Monat = **12 €/Jahr**
- **Standard (3 Mailboxen, 2 GB):** 3 €/Monat = **36 €/Jahr**
- **Professional (25 Mailboxen, 10 GB):** 9 €/Monat = **108 €/Jahr**

### Setup
1. Domain bei Mailbox.org aufschalten (Nameserver umstellen oder MX-only)
2. Postfächer anlegen: `license@`, `support@`, `privacy@`, `legal@`
3. **Team-Features:** Shared Mailbox, Kalender, Drive, Tasks inklusive
4. **DSGVO:** AVV online abschließbar, Server in Deutschland

### Vorteile gegenüber iCloud+
- **Webmail** (Roundcube)
- **Team-Postfächer** (gemeinsamer Zugriff auf `support@`)
- **Catch-All** möglich
- **Bessere Filter/Regeln** (Sieve)
- **Kein Apple-Zwang**

---

## 4. Alternative: Netcup (Webhosting + Mail, sehr günstig)

### Kosten
- **Webhosting 1000 SE:** ~3,50 €/Monat = **42 €/Jahr** (inkl. Domain .de)
- Enthält: Unbegrenzt E-Mail-Postfächer, Webspace, SSL, PHP, MariaDB

### Vorteile
- **Vollwertiges Hosting** (kann auch Website `imailsecure.app` hosten)
- **Unbegrenzt Postfächer**
- **Sehr günstig** bei deutscher Firma (DSGVO)

### Nachteile
- **Selbst verwalten** (SPF/DKIM/DMARC, Mailserver-Config)
- **Kein Webmail-Default** (Roundcube nachinstallieren oder SOGo)
- **Mehr Aufwand** für Einmal-Setup

---

## 5. Empfehlung & Entscheidung

| Szenario | Empfehlung |
|---|---|
| **Solo-Dev, minimales Budget, schnell** | **iCloud+ Custom Domain** (12 €/Jahr, 10 Min Setup) |
| **Team geplant, Shared Support-Postfach** | **Mailbox.org Standard** (36 €/Jahr) |
| **Website + Mail selbst hosten** | **Netcup Webhosting** (42 €/Jahr) |

**Mein Vorschlag:** **Starte mit iCloud+** (0,99 €/Monat, kündbar monatlich).  
Wenn Team-Support nötig → Upgrade auf Mailbox.org.

---

## 6. DNS-Einträge Quick-Reference (iCloud+)

| Typ | Host | Wert | Priorität |
|---|---|---|---|
| MX | @ | mx01.mail.icloud.com | 10 |
| MX | @ | mx02.mail.icloud.com | 20 |
| TXT | @ | apple-domain-verification=XXXXXXXXXX | — |
| CNAME | sig1._domainkey | sig1.dkim.icloud.com | — |
| CNAME | sig2._domainkey | sig2.dkim.icloud.com | — |
| TXT | @ | v=spf1 include:icloud.com ~all | — |

*(DMARC wird von Apple automatisch verwaltet)*

---

## 7. Integration ins Projekt

Nach Einrichtung der E-Mails in folgenden Dateien eintragen:

| Datei | Felder |
|---|---|
| `README.md` | Support-Adresse, Lizenz-Kontakt |
| `LICENSING.md` | `license@imailsecure.app` |
| `MONETIZATION.md` | `license@imailsecure.app` |
| `Info.plist` / `Info-macOS.plist` | `NSPrivacyContactInfo` (optional) |
| `terms.html` (Website) | Impressum, Kontakt |
| `privacy.html` (Website) | Datenschutz-Kontakt (`privacy@`) |
| `SettingsView.swift` | Impressum/Lizenz-Links in App |

---

## 8. Checkliste Launch-Ready

- [ ] Domain `imailsecure.app` registriert
- [ ] iCloud+ 50 GB aktiviert (0,99 €/Monat)
- [ ] Custom Domain `imailsecure.app` in iCloud+ verifiziert
- [ ] Postfächer angelegt: `license@`, `support@`, `privacy@`, `legal@`
- [ ] DNS-Einträge beim Registrar gesetzt + propagiert (dig/txt prüfen)
- [ ] Test-Mail an `license@` → Antwort in Mail.app / iCloud.com
- [ ] E-Mail-Adressen in alle Projektdokumente eingetragen
- [ ] App Store Connect: Support-URL = `https://imailsecure.app/support`
- [ ] App Store Connect: Datenschutz-URL = `https://imailsecure.app/privacy`
- [ ] App Store Connect: EULA-Text hinterlegt (aus `LICENSE-COMMERCIAL.md`)

---

## 9. Kostenübersicht (Jahr 1)

| Posten | Kosten |
|---|---|
| Domain `imailsecure.app` | ~20 € |
| iCloud+ 50 GB (12 Monate) | 12 € |
| DPMA Marke Klasse 9 | 190 € |
| DPMA Marke Klasse 42 (später) | +100 € |
| **Gesamt Minimum** | **~222 €** |
| + Mailbox.org statt iCloud+ | +24 € |
| + Anwalts-Check (1–2 h) | +300–500 € |

**Gesamt mit Anwalt & Marke (beide Klassen): ~622–822 €** — für einen rechtssicheren Launch.