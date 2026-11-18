// PGPPrivateKeysView.swift
//
// Verwaltung der geheimen Schlüssel. Der Import ist bewusst zweistufig:
// erst Adresse, User-ID und Fingerprint anzeigen, dann erst speichern. Ein
// falsch zugeordneter Signaturschlüssel würde Mails unter fremder Identität
// signieren.
//
// Es gibt hier keine Schlüsselerzeugung und keine Passphrase-Vergessen-Funktion.
// Der Nutzer bringt seinen Schlüssel mit; die Passphrase bleibt im Keychain
// dieses Geräts.

import SwiftUI

struct PGPPrivateKeysView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var keys: [StoredPGPPrivateKey] = []
    @State private var showImport = false
    @State private var pendingDeletion: StoredPGPPrivateKey?
    @State private var actionError: String?

    var body: some View {
        List {
            Section {
                if keys.isEmpty {
                    Text("Noch kein privater Schlüssel hinterlegt.")
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(keys) { key in
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
                    }
                    .onDelete { indexSet in
                        if let index = indexSet.first {
                            pendingDeletion = keys[index]
                        }
                    }
                }
            } footer: {
                Text("Der geheime Schlüssel und seine Passphrase liegen nur auf diesem Gerät und werden nicht synchronisiert. Die App kann damit Mail signieren, sobald du es im Verfassen-Fenster aktivierst.")
            }

            if let actionError {
                Section {
                    Text(actionError)
                        .foregroundStyle(.red)
                        .font(.callout)
                }
            }
        }
        .navigationTitle("Private Schlüssel")
        .inlineNavigationTitle()
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button {
                    showImport = true
                } label: {
                    Label("Privaten Schlüssel hinzufügen", systemImage: "plus")
                }
            }
        }
        .sheet(isPresented: $showImport) {
            PGPPrivateKeyImportView { reload() }
        }
        .alert("Privaten Schlüssel entfernen?", isPresented: Binding(
            get: { pendingDeletion != nil },
            set: { if !$0 { pendingDeletion = nil } }
        )) {
            Button("Abbrechen", role: .cancel) { pendingDeletion = nil }
            Button("Entfernen", role: .destructive) {
                if let pendingDeletion { delete(pendingDeletion) }
            }
        } message: {
            if let pendingDeletion {
                Text("Der Schlüssel für \(pendingDeletion.email) und die zugehörige Passphrase werden von diesem Gerät gelöscht.")
            }
        }
        .onAppear { reload() }
    }

    private func reload() {
        keys = PGPPrivateKeyStore.shared.keys()
    }

    private func delete(_ key: StoredPGPPrivateKey) {
        actionError = nil
        do {
            try PGPPrivateKeyStore.shared.remove(email: key.email)
            reload()
        } catch {
            actionError = error.localizedDescription
        }
        pendingDeletion = nil
    }
}

// MARK: – Import

private struct PGPPrivateKeyImportView: View {
    @Environment(\.dismiss) private var dismiss

    private struct Candidate {
        let armored: Data
        let passphrase: String
        let email: String
        let info: PGPKeyInfo
    }

    let onImported: () -> Void

    @State private var armored = ""
    @State private var passphrase = ""
    @State private var email = ""
    @State private var candidate: Candidate?
    @State private var errorMessage: String?

    private var canCheck: Bool {
        !armored.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !passphrase.isEmpty
    }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextEditor(text: $armored)
                        .font(.system(.caption, design: .monospaced))
                        .frame(minHeight: 160)
                        .autocorrectionDisabled()
                        #if os(iOS)
                        .textInputAutocapitalization(.never)
                        #endif
                } header: {
                    Text("Armierten geheimen Schlüssel einfügen")
                } footer: {
                    Text("Beginnt mit „-----BEGIN PGP PRIVATE KEY BLOCK-----“. Der Schlüssel bleibt auf diesem Gerät.")
                }

                Section {
                    SecureField("Passphrase", text: $passphrase)
                    TextField("name@example.org", text: $email)
                        #if os(iOS)
                        .keyboardType(.emailAddress)
                        .textInputAutocapitalization(.never)
                        #endif
                        .autocorrectionDisabled()
                } footer: {
                    Text("Leer lassen, wenn der Schlüssel die Adresse selbst enthält.")
                }

                Section {
                    Button("Schlüssel prüfen") { check() }
                        .disabled(!canCheck)
                }

                if let candidate {
                    Section {
                        Label("Geheimer Schlüssel", systemImage: "key.fill")
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
                        Button("Importieren") { importKey(candidate) }
                    } header: {
                        Text("Vorschau")
                    } footer: {
                        Text("Vergleiche den Fingerprint mit deinem Schlüsselbund, bevor du den Schlüssel hier speicherst.")
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
            .navigationTitle("Privaten Schlüssel hinzufügen")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Abbrechen") { dismiss() }
                }
            }
        }
    }

    private func check() {
        errorMessage = nil
        candidate = nil
        let normalized = armored.replacingOccurrences(of: "\r\n", with: "\n")
        let data = Data(normalized.utf8)
        do {
            let info = try PGP.secretKeyInfo(data, passphrase: passphrase)
            let typed = PGPKeyStore.normalize(email)
            let address = typed.isEmpty ? PGPKeyStore.email(in: info.userID) : typed
            guard let address, !address.isEmpty else {
                errorMessage = String(localized: "Bitte gib eine E-Mail-Adresse an; der Schlüssel enthält keine.")
                return
            }
            candidate = Candidate(
                armored: data,
                passphrase: passphrase,
                email: address,
                info: info
            )
        } catch {
            errorMessage = error.localizedDescription
        }
    }

    private func importKey(_ candidate: Candidate) {
        errorMessage = nil
        do {
            try PGPPrivateKeyStore.shared.importKey(
                armored: candidate.armored,
                passphrase: candidate.passphrase,
                email: candidate.email
            )
            onImported()
            dismiss()
        } catch {
            errorMessage = error.localizedDescription
        }
    }
}
