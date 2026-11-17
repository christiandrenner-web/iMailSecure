# LICENSING.md — Lizenz, App Store und Monetarisierung (iMail Secure)

**Stand:** 2026-11-15 · **Status:** entschieden — **Dual Licensing**  
- Nicht-kommerziell: **PolyForm Noncommercial 1.0.0** (`LICENSE-NONCOMMERCIAL.md`)  
- Kommerziell: **iMail Secure Commercial License** (`LICENSE-COMMERCIAL.md`)  
- Übersicht: `LICENSE.md`

*Keine Rechtsberatung — das ist eine technische und organisatorische Einschätzung.  
Vor einer kommerziellen Veröffentlichung sollte ein Anwalt für IT-Recht drüberschauen.*

---

## Kurzfassung

| Frage | Antwort |
|---|---|
| **Welches Lizenzmodell?** | **Dual Licensing** — zwei Lizenzen, Nutzer wählt passende |
| **Nicht-kommerziell (Privat)** | PolyForm Noncommercial 1.0.0 — kostenlos, Quellcode einsehbar |
| **Kommerziell (Firmen, Behörden)** | iMail Secure Commercial License — entgeltlich (Pro Seat, Enterprise, Lifetime, Revenue Share) |
| **Ist das „Open Source“?** | **Nein.** Nicht OSI-zertifiziert — Bezeichnung **darf nicht** verwendet werden. |
| **Ist der Quellcode einsehbar?** | Ja — *Source-Available*. Einsehbar ≠ freie Verwertung. |
| **Dürfen andere die App kommerziell nutzen/verkaufen?** | **Nur mit gekaufter Commercial License.** Ohne: nein. |
| **Darfst du selbst Geld damit verdienen?** | **Ja** — als Rechteinhaber bist du an keine der Lizenzen gebunden. |
| **Ist das App-Store-tauglich?** | **Ja** — keine Copyleft-Pflicht, kein GPL-Konflikt. Eigene EULA in App Store Connect zwingend. |
| **Fremde Beiträge?** | Nur mit `CLA.md` (räumt kommerzielle Verwertung + Relizenzierung ein). |

---

## 1. Was die Lizenzen erlauben und verbieten

### 1.1 Nicht-kommerziell (PolyForm Noncommercial 1.0.0)

**Erlaubt** (für Privatpersonen, nicht-kommerziell):
- die App benutzen
- den Quellcode lesen, prüfen, verändern, eigene Versionen bauen
- Kopien weitergeben, solange Lizenztext und Copyright-Hinweis mitkommen

**Verboten:**
- **jede kommerzielle Nutzung** durch Lizenznehmer (Verkauf, Bezahl-Angebote, Werbe-Finanzierung, Einsatz im Unternehmen zu Geschäftszwecken)
- Weiterverbreitung ohne Lizenztext

**Nicht betroffen:** Du als Rechteinhaber. Du darfst die App kommerziell vertreiben (App Store, In-App-Käufe, Enterprise-Lizenzen). Du lizenzierst, du nimmst die Lizenz nicht in Anspruch.

---

### 1.2 Kommerziell (iMail Secure Commercial License)

**Erlaubt** (nach Lizenzkauf):
- Nutzung im geschäftlichen/behördlichen Kontext (Pro Seat, Enterprise Flat, Lifetime, Revenue Share)
- Interne Verteilung an Mitarbeiter (Enterprise) oder lizenzierte Nutzer (Pro Seat)
- Einbindung in eigene Dienstleistungen (Revenue Share: 15 % Netto-Umsatz)
- Updates/Upgrades während Laufzeit (Abo) oder lebenslang (Lifetime)

**Verboten:**
- Weitervertrieb / Sublicensing an Dritte (kein White-Label, kein Reselling)
- Quellcode-Offenlegung (außer technisch zwingend für eigenen Build)
- Reverse Engineering (soweit nicht § 69e UrhG)
- Markennutzung („iMail Secure“, Logo) ohne Erlaubnis
- Entfernung von Copyright/Lizenz-Hinweisen

**Pflicht (Attribution):** Bei jeder Verteilung (auch intern):  
`© 2026 Christian Renner – iMail Secure` + Link zu `https://imailsecure.app/license-commercial`

---

## 2. Warum nicht GPL (Bestätigung der früheren Entscheidung)

Die GPLv3-Option (mit §7 App-Store-Ausnahme) wurde **endgültig verworfen**, weil:

| Punkt | GPLv3 | Dual Licensing (jetzt) |
|---|---|---|
| Quellcode bei *jeder* Weitergabe | **Pflicht** (auch App Store) | **Keine Pflicht** |
| Kommerzielle Forks durch Dritte | **Erlaubt** (müssen GPL bleiben) | **Verboten** ohne Commercial License |
| Konflikt mit Apple DRM/ToS | Vorhanden (§7-Ausnahme nötig) | **Kein Konflikt** |
| „Code bleibt kontrolliert“ | Nicht möglich | **Volle Kontrolle** behalten |
| Einnahmen von Firmen | Nicht direkt möglich | **Direkt über Commercial License** |

**Fazit:** GPL erzwingt Veröffentlichung und erlaubt kommerzielle Forks — genau das, was vermieden werden soll. Dual Licensing gibt maximale Kontrolle bei minimalem rechtlichen Risiko.

---

## 3. App Store: Eigene EULA hinterlegen (kritisch!)

Apple wendet ohne eigenes EULA den **Apple Standard End User License Agreement** an. Der kennt **keine** Nicht-kommerziell-Beschränkung.

→ **Zwingend:** In **App Store Connect → App-Informationen → Lizenzvereinbarung** eine eigene EULA hinterlegen.

**Inhalt der EULA:**
- Verweis auf Dual Licensing
- Nicht-kommerziell: PolyForm Noncommercial 1.0.0 (Text oder Link zu `LICENSE-NONCOMMERCIAL.md`)
- Kommerziell: iMail Secure Commercial License (Link zu `LICENSE-COMMERCIAL.md` / `https://imailsecure.app/license-commercial`)
- Hinweis: „Ohne gültige Commercial License ist jegliche geschäftliche Nutzung untersagt.“

Ohne diesen Schritt ist die Lizenz gegenüber App-Store-Nutzern **faktisch wirkungslos**.

---

## 4. Außendarstellung & Kommunikation

**Verboten:** „Open Source“, „quelloffen“, „FOSS“, „freie Software“  
**Erlaubt & ehrlich:**
- „Der Quellcode ist einsehbar und nachprüfbar.“
- „Source-Available, Dual Licensed.“
- „Kein Open Source, aber überprüfbar — keine Telemetrie, kein Tracking.“
- „Kommerzielle Nutzung erfordert Lizenzkauf.“

**Projektname in aller Öffentlichkeit:** **ausschließlich „iMail Secure“**  
Der Ordnername „Fair-iMail“ ist **intern**, taucht nirgendwo in Doku, UI, Website, App Store, Commits auf.

---

## 5. Abhängigkeiten (geprüft, unverändert kompatibel)

| Bibliothek | Lizenz | Kompatibel mit Dual Licensing? |
|---|---|---|
| SwiftMail (Cocoanetics) | BSD-3-Clause | ✅ Ja — permissiv, nur Hinweispflicht |
| swift-log (Apple) | Apache-2.0 | ✅ Ja — permissiv, Patentklausel unproblematisch |
| rpgp (`pgp` 0.21.1, eigene FFI in `Crypto/pgp-ffi`) | MIT **oder** Apache-2.0 | ✅ Ja — permissiv, statisch gelinkt, keine Relink-Pflicht. **Bewusst nicht Sequoia** (LGPL): statisches Linken wäre an Bedingungen geknüpft |

Keine Copyleft-Abhängigkeit → keine virale Veröffentlichungsplicht.

**Wichtig für die Außendarstellung:** „keine Drittanbieter-SDKs“ meint
Bibliotheken, die Daten sammeln oder nach außen funken. Eingebunden sind
technische Bibliotheken (SwiftMail, rpgp) — beide laufen lokal, übertragen
nichts und sind quelloffen nachprüfbar. Formulierung deshalb: „keine
Analyse-, Werbe- oder Tracking-SDKs“.

---

## 6. Änderungen am 2026-11-15 (Dual Licensing Finalisierung)

- `LICENSE` → **ersetzt** durch `LICENSE.md` (Dual-Licensing-Übersicht)
- `LICENSE-NONCOMMERCIAL.md` → **neu** (PolyForm Noncommercial 1.0.0 Volltext)
- `LICENSE-COMMERCIAL.md` → **neu** (eigene Commercial License mit 4 Modellen)
- `LICENSE-EXCEPTION` → **bleibt gelöscht** (war nur für GPL nötig)
- `CLA.md` → **bereits kompatibel** (räumt kommerzielle Verwertung + Relizenzierung ein)
- `README.md`, `AGENTS.md`, `MONETIZATION.md`, `CLAUDE.md`, `project.yml` → **angepasst** (Dual Licensing, iMail Secure, macOS)
- `SettingsView.swift` / UI → **anzupassen** (Lizenz-Hinweis auf Dual Licensing)

---

## 7. Offene To-Dos (Stand 2026-11-15)

| # | Aufgabe | Status | Kosten |
|---|---------|--------|--------|
| 1 | **Marke „iMail Secure“ anmelden** (DPMA, Kl. 9+42) | 🔴 Offen | ~190–290 € (s. unten) |
| 2 | **Domain `imailsecure.app` registrieren** | 🔴 Offen | ~20 €/Jahr |
| 3 | **iCloud+ Custom Domain** `license@imailsecure.app` einrichten | 🔴 Offen | 0,99 €/Monat (iCloud+ 50 GB) |
| 4 | **Eigene EULA in App Store Connect** hinterlegen | 🔴 Offen | 0 € (Text aus `LICENSE-COMMERCIAL.md`) |
| 5 | **KI-Prüfung** `LICENSE-COMMERCIAL.md` (Claude + ChatGPT) | 🔄 In Arbeit | 0 € |
| 6 | **Optional: Anwalts-Check** (1–2 h, nur Commercial License) | 🟡 Geplant | ~300–500 € |
| 7 | **macOS Target** in `project.yml` vorbereiten | 🟡 Geplant | Dev-Zeit |
| 8 | **OAuth 2.0** für Gmail/Outlook (App-Passwörter Minimum) | 🔴 Offen | Dev-Zeit |

---

## 8. Markenschutz — günstigste Varianten (DACH)

| Variante | Kosten | Schutzumfang | Empfehlung |
|---|---|---|---|
| **DPMA Nationale Marke (Klasse 9 + 42)** | **190 €** (1 Klasse) + **100 €** (2. Klasse) = **290 €** | Deutschland, 10 Jahre verlängerbar | **Standard, sicherster Schutz** |
| **DPMA Nur Klasse 9** (Software) | **190 €** | Nur Software, keine Dienstleistungen | **Minimum** — wenn Budget extrem knapp |
| **EUIPO Unionsmarke** (EU-weit, 1 Klasse) | ~850 € | 27 EU-Staaten | Zu teuer für Start |
| **Madrid-System (IR-Marken)** | Ab ~653 CHF (Basis) + Ländergebühren | International (DE, TR, US, RU, ES möglich) | **Für mittelfristige Expansion** (TR, RU, ES, US) — später |
| **Gebrauchsmuster** | ~40 € | Nur technische Lehre, keine Marke | **Nicht geeignet** (schützt nicht den Namen) |
| **Keine Anmeldung, nur ®-Verbot beachten** | 0 € | Kein Rechtsschutz | **Hohes Risiko** (Klonen, Abmahnungen) |

**Empfehlung für DACH-Start:**
1. **DPMA Klasse 9 (Software)** = **190 €** — absolutes Minimum
2. **Sobald Cashflow positiv:** Klasse 42 (SaaS, Hosting, Support) nachmelden = +100 €
3. **Für Expansion (TR, RU, ES, US):** Später Madrid-System über DPMA (Basis DE-Marke) — spart Neuprüfung

**Wichtig:** Marke **vor** App-Store-Submission anmelden (Prioritätsnachweis). Anmeldung online über **DPMAregister** (https://register.dpma.de) — dauert ~15 Min, Zahlung per Kreditkarte/SEPA.

---

## 9. Kontaktadresse / Impressum

**Professionelle E-Mail (iCloud+ Custom Domain):**
- Domain: `imailsecure.app` (oder `fairimail.io` falls frei)
- iCloud+ 50 GB = 0,99 €/Monat → Custom Domain + `license@`, `support@`, `privacy@`
- Alternative: **Mailbox.org** (1 €/Monat, Custom Domain, DSGVO-konform, deutsch)

**Impressumspflicht (TMG § 5 / DDG):**  
Name, Anschrift, Kontakt (E-Mail), Vertretungsberechtigter, Handelsregister (falls Eintragung), USt-IdNr. (falls umsatzsteuerpflichtig) — auf Website & in App (Settings → Impressum).

---

## 10. Internationalisierung ( mittelfristig)

| Markt | Sprache | Rechtliches | Priorität |
|---|---|---|---|
| **DACH** | Deutsch | BGB, DSGVO, TMG, MarkenG | **1. Sofort** |
| **Türkei** | Türkisch | Türkisches Markenrecht, KVKK (DSGVO-Pendant) | 2. Nach DACH-Erfolg |
| **Englisch (UK/US/Global)** | Englisch | UK/US Markenrecht, CCPA/State Laws | 2. Parallel möglich |
| **Russland** | Russisch | Russisches Markenrecht, Lokalisierungspflicht | 3. Später (Sanktionen prüfen) |
| **Spanisch (ES/LATAM)** | Spanisch | EU/ES Markenrecht, LGPD (Brasilien) | 3. Später |

**Vorbereitung jetzt:**
- Alle Nutzertexte in `.strings` / `String Catalog` (Xcode) auslagern
- `Localizable.xcstrings` für DE, EN, TR, RU, ES vorbereiten
- Rechtstexte (EULA, Privacy, Commercial License) **nur DE + EN** initial — Übersetzungen nach Anwaltsprüfung
- Marke: DE-Marke als Basis für spätere IR-Marken (Madrid) nutzen