// ComposeView.swift
import SwiftUI
import UniformTypeIdentifiers

struct ComposeView: View {
    @ObservedObject var viewModel: ComposeViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var showFilePicker  = false
    @State private var showImagePicker = false

    var body: some View {
        NavigationStack {
            Form {
                // Empfänger
                Section("Empfänger") {
                    TextField("An", text: $viewModel.draft.toText)
                        .platformKeyboardType(.emailAddress)
                        .autocorrectionDisabled()
                        .platformNoAutocapitalization()
                    TextField("CC", text: $viewModel.draft.ccText)
                        .platformKeyboardType(.emailAddress)
                        .autocorrectionDisabled()
                        .platformNoAutocapitalization()
                    TextField("BCC", text: $viewModel.draft.bccText)
                        .platformKeyboardType(.emailAddress)
                        .autocorrectionDisabled()
                        .platformNoAutocapitalization()
                }

                // Betreff
                Section("Betreff") {
                    TextField("Betreff", text: $viewModel.draft.subject)
                }

                // Nachricht
                Section("Nachricht") {
                    TextEditor(text: $viewModel.draft.body)
                        .frame(minHeight: 160)
                }

                // Anhänge
                if !viewModel.draft.attachments.isEmpty {
                    Section("Anhänge (\(viewModel.draft.attachments.count))") {
                        ForEach(viewModel.draft.attachments) { att in
                            HStack {
                                Image(systemName: mimeIcon(att.mimeType))
                                    .foregroundStyle(Color.accentColor)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(att.filename).font(.subheadline)
                                    Text(ByteCountFormatter.string(
                                        fromByteCount: Int64(att.size), countStyle: .file))
                                        .font(.caption)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                            }
                        }
                        .onDelete { viewModel.draft.attachments.remove(atOffsets: $0) }
                    }
                }

                // Anhang hinzufügen
                Section {
                    Button {
                        showFilePicker = true
                    } label: {
                        Label("Datei anfügen", systemImage: "paperclip")
                    }
                    Button {
                        showImagePicker = true
                    } label: {
                        Label("Foto anfügen", systemImage: "photo")
                    }
                }

                // Bestätigungsoptionen
                Section {
                    Toggle(isOn: $viewModel.draft.requestMDN) {
                        Label("Lesebestätigung anfordern", systemImage: "envelope.open.badge.clock")
                    }
                    .tint(.blue)
                    Toggle(isOn: $viewModel.draft.requestReceipt) {
                        Label("Empfangsbestätigung anfordern", systemImage: "clock.badge.checkmark")
                    }
                    .tint(.green)
                } header: {
                    Text("Bestätigungen")
                } footer: {
                    Text("MDN (RFC 8098): Benachrichtigung wenn die Mail geöffnet wird.")
                }

                // OpenPGP – nur anbieten, wenn wirklich Schlüssel da sind
                Section {
                    if viewModel.canSign {
                        Toggle(isOn: $viewModel.draft.pgpSign) {
                            Label("Digital signieren", systemImage: "signature")
                        }
                        .tint(.blue)
                    } else {
                        Text("Für dieses Konto ist kein privater Schlüssel hinterlegt. Die Mail wird unsigniert versendet.")
                            .foregroundStyle(.secondary)
                    }

                    if viewModel.canEncrypt {
                        Toggle(isOn: $viewModel.draft.pgpEncrypt) {
                            Label("Verschlüsseln", systemImage: "lock")
                        }
                        .tint(.green)
                    } else if !viewModel.missingEncryptionKeys.isEmpty {
                        VStack(alignment: .leading, spacing: 6) {
                            ForEach(viewModel.missingEncryptionKeys, id: \.self) { address in
                                Label(
                                    String(
                                        format: String(localized: "Für %@ ist kein öffentlicher Schlüssel hinterlegt. Die Nachricht kann nicht verschlüsselt werden."),
                                        address
                                    ),
                                    systemImage: "key.slash"
                                )
                                .font(.caption)
                                .foregroundStyle(.orange)
                            }
                        }
                    }

                    if viewModel.draft.pgpSign && viewModel.draft.pgpEncrypt {
                        Text("Signiert und verschlüsselt: Die Nachricht wird zuerst digital signiert und dann verschlüsselt.")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                } header: {
                    Text("OpenPGP")
                } footer: {
                    Text("Die Signatur umfasst Text und Anhänge. Sie wird mit deinem privaten Schlüssel erstellt, der nur auf diesem Gerät liegt.")
                }

                // Fehler / Erfolg
                if let error = viewModel.errorMessage {
                    Section {
                        Label(error, systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.red)
                    }
                }
                if let success = viewModel.successMessage {
                    Section {
                        Label(success, systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                    }
                }
            }
            .navigationTitle("Neue E-Mail")
            .inlineNavigationTitle()
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Abbrechen") { dismiss() }
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button { viewModel.sendDraft() } label: {
                        if viewModel.isLoading {
                            ProgressView().controlSize(.small)
                        } else {
                            Label("Senden", systemImage: "paperplane.fill")
                        }
                    }
                    .disabled(viewModel.isLoading)
                }
                ToolbarItem(placement: .platformTopBarLeading) {
                    Button { viewModel.saveDraft() } label: {
                        Image(systemName: "square.and.arrow.down")
                    }
                }
            }
            .onChange(of: viewModel.isSent) { _, sent in
                if sent { dismiss() }
            }
            // Datei-Picker
            .fileImporter(
                isPresented: $showFilePicker,
                allowedContentTypes: [.item],
                allowsMultipleSelection: true
            ) { result in
                if case .success(let urls) = result {
                    for url in urls {
                        _ = url.startAccessingSecurityScopedResource()
                        defer { url.stopAccessingSecurityScopedResource() }
                        if let data = try? Data(contentsOf: url) {
                            let att = EmailAttachment(
                                filename: url.lastPathComponent,
                                mimeType: UTType(filenameExtension: url.pathExtension)?
                                    .preferredMIMEType ?? "application/octet-stream",
                                data: data
                            )
                            viewModel.draft.attachments.append(att)
                        }
                    }
                }
            }
        }
    }

    private func mimeIcon(_ mime: String) -> String {
        if mime.hasPrefix("image")  { return "photo" }
        if mime.hasPrefix("video")  { return "film" }
        if mime.contains("pdf")     { return "doc.richtext" }
        if mime.contains("zip")     { return "archivebox" }
        return "doc"
    }
}
