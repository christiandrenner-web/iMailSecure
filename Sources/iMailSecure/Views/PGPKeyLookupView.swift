// PGPKeyLookupView.swift
//
// Schlüssel aus zwei Quellen ansehen und ausdrücklich übernehmen:
//   • WKD-Abfrage beim Betreiber der Absenderdomain (nur auf Knopfdruck)
//   • Autocrypt-Header der gerade geöffneten Nachricht
//
// Beide Wege enden in einer Vorschau mit Fingerprint. Es wird nichts
// automatisch importiert und nichts automatisch nachgeladen.

import SwiftUI

/// Ein gefundener Schlüssel, noch nicht im Schlüsselbund.
struct PGPKeyCandidate: Identifiable, Equatable {
    enum Source: String, Sendable {
        case wkd
        case autocrypt
    }

    let email: String
    let armoredKey: Data
    let info: PGPKeyInfo
    let source: Source

    var id: String { "\(source.rawValue)-\(info.fingerprint)" }

    var sourceLabel: String {
        switch source {
        case .wkd:
            return String(localized: "Web Key Directory")
        case .autocrypt:
            return String(localized: "Autocrypt-Header dieser Nachricht")
        }
    }
}

struct PGPKeyLookupView: View {
    let initialEmail: String?
    let autocryptHeader: String?
    let onImported: (StoredPGPKey) -> Void

    @Environment(\.dismiss) private var dismiss
    @State private var email: String
    @State private var candidate: PGPKeyCandidate?
    @State private var errorMessage: String?
    @State private var isSearching = false

    init(
        initialEmail: String? = nil,
        autocryptHeader: String? = nil,
        onImported: @escaping (StoredPGPKey) -> Void
    ) {
        self.initialEmail = initialEmail
        self.autocryptHeader = autocryptHeader
        self.onImported = onImported
        _email = State(initialValue: initialEmail ?? "")
    }

    var body: some View {
        NavigationStack {
            Form {
                if autocryptHeader != nil {
                    Section {
                        Text("Diese Nachricht enthält einen Autocrypt-Header. Der Schlüssel stammt aus dem Kopf der Nachricht, nicht von einem Server.")
                        Button("Autocrypt-Schlüssel anzeigen") {
                            prepareAutocrypt()
                        }
                    } footer: {
                        Text("Auch ein Autocrypt-Header ist nur ein Hinweis. Vergleiche den Fingerprint über einen zweiten Weg.")
                    }
                }

                Section {
                    TextField("name@example.org", text: $email)
                        #if os(iOS)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        #endif
                        .autocorrectionDisabled()
                    Button {
                        Task { await searchWKD() }
                    } label: {
                        HStack {
                            Text("Schlüssel per WKD suchen")
                            if isSearching {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(isSearching || email.trimmingCharacters(in: .whitespaces).isEmpty)
                } header: {
                    Text("Web Key Directory")
                } footer: {
                    Text("Die Abfrage geht ausschließlich an die Domain der Adresse und nur, wenn du sie hier startest. Es wird kein Keyserver und kein anderer Dritter gefragt.")
                }

                if let candidate {
                    Section {
                        Label(candidate.sourceLabel, systemImage: "key")
                        Text(candidate.email)
                            .font(.subheadline.bold())
                        if let userID = candidate.info.userID {
                            Text(userID)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                        }
                        Text(candidate.info.formattedFingerprint)
                            .font(.system(.caption2, design: .monospaced))
                            .textSelection(.enabled)

                        Button("Schlüssel übernehmen") {
                            adopt(candidate)
                        }
                    } header: {
                        Text("Gefundener Schlüssel")
                    } footer: {
                        Text("Erst nach der Übernahme wird der Schlüssel für die Signaturprüfung verwendet. Er liegt dann nur auf diesem Gerät.")
                    }
                }

                if let errorMessage {
                    Section {
                        Text(errorMessage)
                            .foregroundStyle(.red)
                            .font(.callout)
                    }
                }
            }
            .navigationTitle("Schlüssel suchen")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Fertig") { dismiss() }
                }
            }
            .onAppear {
                if autocryptHeader != nil { prepareAutocrypt() }
            }
        }
    }

    // MARK: – Aktionen

    @MainActor
    private func searchWKD() async {
        errorMessage = nil
        candidate = nil
        isSearching = true
        defer { isSearching = false }
        do {
            let result = try await WKDLookup.lookup(email: email)
            candidate = PGPKeyCandidate(
                email: result.email,
                armoredKey: result.armoredKey,
                info: result.info,
                source: .wkd
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func prepareAutocrypt() {
        errorMessage = nil
        guard let autocryptHeader else { return }
        guard let parsed = AutocryptHeader.parse(autocryptHeader) else {
            errorMessage = String(localized: "Der Autocrypt-Header enthält keinen lesbaren Schlüssel.")
            return
        }
        do {
            let info = try PGP.parsePublicKey(parsed.keyData)
            let armored = try PGP.armoredPublicKey(parsed.keyData)
            candidate = PGPKeyCandidate(
                email: parsed.address,
                armoredKey: armored,
                info: info,
                source: .autocrypt
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func adopt(_ candidate: PGPKeyCandidate) {
        errorMessage = nil
        if let keyEmail = PGPKeyStore.email(in: candidate.info.userID),
           keyEmail != PGPKeyStore.normalize(candidate.email) {
            errorMessage = String(
                format: String(localized: "Der Schlüssel gehört zu %@, nicht zu %@."),
                keyEmail,
                candidate.email
            )
            return
        }
        do {
            let stored = try PGPKeyStore.shared.importKey(
                armored: candidate.armoredKey,
                email: candidate.email
            )
            onImported(stored)
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
