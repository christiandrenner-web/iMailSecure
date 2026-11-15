// iMailSecureApp.swift
// iMail Secure – Datenschutzfreundlicher E-Mail-Client für iOS 18+
// Lizenz: PolyForm Noncommercial 1.0.0 (source-available, nicht kommerziell)

import SwiftUI

@main
struct iMailSecureApp: App {
    @StateObject private var accountStore = AccountStore()
    @StateObject private var mailStore   = MailStore()
    @StateObject private var subscription = SubscriptionManager()

    /// Sichtschutz: true wenn App in den Hintergrund wechselt
    /// → verhindert dass Mail-Inhalte im App-Umschalter sichtbar sind
    @State private var isObscured = false

    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environmentObject(accountStore)
                .environmentObject(mailStore)
                .environmentObject(subscription)
                .onAppear {
                    mailStore.loadAccounts(from: accountStore)
                }
                // Konto hinzugefügt/entfernt/deaktiviert → Sync-Engines
                // nachziehen. Ohne das wirkt ein neues Konto erst nach
                // einem App-Neustart.
                .onReceive(accountStore.$accounts) { accounts in
                    mailStore.loadAccounts(from: accountStore)
                }
                // Sichtschutz-Overlay
                .overlay(privacyOverlay)
                // Szene wechselt (Hintergrund, inaktiv, aktiv) → Inhalt
                // verbergen bzw. wieder zeigen. scenePhase gibt es auf iOS
                // und macOS gleichermaßen.
                .onChange(of: scenePhase) { _, newPhase in
                    withAnimation(.easeInOut(duration: 0.15)) {
                        isObscured = newPhase != .active
                    }
                }
        }
    }

    // MARK: – Privacy Overlay

    @ViewBuilder
    private var privacyOverlay: some View {
        if isObscured {
            ZStack {
                Rectangle()
                    .fill(.ultraThinMaterial)
                    .ignoresSafeArea()

                VStack(spacing: 16) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 48))
                        .foregroundStyle(.secondary)
                    Text("iMail Secure")
                        .font(.title2.bold())
                        .foregroundStyle(.secondary)
                }
            }
            .transition(.opacity)
        }
    }
}
