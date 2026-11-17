// PGPKeysView.swift
//
// Verwaltung der importierten öffentlichen Schlüssel. Bewusst schlicht: keine
// Keyserver-Abfrage, kein automatischer Tausch. Was hier steht, hat der Nutzer
// selbst hinzugefügt und kann es jederzeit wieder entfernen.

import SwiftUI

struct PGPKeysView: View {
    @State private var keys: [StoredPGPKey] = []
    @State private var showImport = false
    @State private var pendingDeletion: StoredPGPKey?
    @State private var actionError: String?

    var body: some View {
        List {
            Section {
                if keys.isEmpty {
                    Text("Noch keine Schlüssel hinterlegt.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(keys) { key in
                        keyRow(key)
                    }
                    .onDelete { indexSet in
                        if let index = indexSet.first {
                            pendingDeletion = keys[index]
                        }
                    }
                }
            } footer: {
                Text("Schlüssel liegen nur auf diesem Gerät. Der Fingerprint ist der Vertrauensanker: Vergleiche ihn über einen zweiten Weg mit dem, den dir dein Gegenüber nennt.")
            }
        }
        .navigationTitle("OpenPGP")
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showImport = true
                } label: {
                    Label("Schlüssel hinzufügen", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $showImport) {
            PGPKeyImportView { reload() }
        }
        .confirmationDialog(
            "Schlüssel löschen?",
            isPresented: Binding(
                get: { pendingDeletion != nil },
                set: { if !$0 { pendingDeletion = nil } }
            ),
            titleVisibility: .visible,
            presenting: pendingDeletion
        ) { key in
            Button("Löschen", role: .destructive) {
                do {
                    try PGPKeyStore.shared.remove(email: key.email)
                    reload()
                } catch {
                    actionError = error.localizedDescription
                }
                pendingDeletion = nil
            }
            Button("Abbrechen", role: .cancel) { pendingDeletion = nil }
        } message: { key in
            Text("Nachrichten dieses Absenders lassen sich danach nicht mehr prüfen, bis du den Schlüssel erneut hinzufügst. (\(key.email))")
        }
        .alert(
            "Das hat nicht geklappt",
            isPresented: Binding(
                get: { actionError != nil },
                set: { if !$0 { actionError = nil } }
            )
        ) {
            Button("OK", role: .cancel) { actionError = nil }
        } message: {
            Text(actionError ?? "")
        }
        .onAppear(perform: reload)
    }

    private func keyRow(_ key: StoredPGPKey) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(key.email)
                .font(.subheadline.bold())
            if let userID = key.userID {
                Text(userID)
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Text(key.formattedFingerprint)
                .font(.system(.caption2, design: .monospaced))
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
        .padding(.vertical, 2)
    }

    private func reload() {
        keys = PGPKeyStore.shared.keys()
    }
}

// MARK: – Import

struct PGPKeyImportView: View {
    @Environment(\.dismiss) private var dismiss

    /// Wird nach erfolgreichem Import aufgerufen, damit die Liste neu lädt.
    let onImported: () -> Void

    @State private var armored = ""
    @State private var email = ""
    @State private var errorMessage: String?
    @State private var isImporting = false

    private var canImport: Bool {
        !armored.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && !isImporting
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $armored)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 180)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                } header: {
                    Text("Armierten Schlüssel einfügen")
                } footer: {
                    Text("Beginnt mit „-----BEGIN PGP PUBLIC KEY BLOCK-----“. Aus Dateien oder aus dem Schlüsseltext deines Gegenübers.")
                }

                Section {
                    TextField("name@example.org", text: $email)
                        #if os(iOS)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        #endif
                        .autocorrectionDisabled()
                } header: {
                    Text("E-Mail-Adresse")
                } footer: {
                    Text("Leer lassen, wenn der Schlüssel die Adresse selbst enthält.")
                }

                if let errorMessage {
                    Section {
                        Text(errorMessage)
                            .foregroundStyle(.red)
                            .font(.callout)
                    }
                }

                Section {
                    Button {
                        importKey()
                    } label: {
                        HStack {
                            Text("Importieren")
                            if isImporting {
                                Spacer()
                                ProgressView()
                            }
                        }
                    }
                    .disabled(!canImport)
                }
            }
            .navigationTitle("Schlüssel hinzufügen")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Abbrechen") { dismiss() }
                }
            }
        }
    }

    private func importKey() {
        errorMessage = nil
        isImporting = true
        defer { isImporting = false }

        // Zeilenenden normalisieren: TextEditoren unter macOS liefern CRLF.
        let normalized = armored.replacingOccurrences(of: "\r\n", with: "\n")
        let data = Data(normalized.utf8)

        do {
            let info = try PGP.parsePublicKey(data)
            let typed = PGPKeyStore.normalize(email)
            let address: String
            if typed.isEmpty {
                guard let derived = PGPKeyStore.email(in: info.userID) else {
                    errorMessage = String(localized: "Bitte gib eine E-Mail-Adresse an; der Schlüssel enthält keine.")
                    return
                }
                address = derived
            } else {
                address = typed
            }

            try PGPKeyStore.shared.importKey(armored: data, email: address)
            onImported()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
