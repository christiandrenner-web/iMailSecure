// PlatformSupport.swift
//
// Kleine Brücke zwischen iOS und macOS. Beide Targets teilen sich dieselben
// Views; alles, was nur eine der beiden Plattformen kennt, läuft hier durch
// einen gemeinsamen Aufruf. So bleiben die Views frei von `#if os(...)`.

import SwiftUI

#if canImport(UIKit)
import UIKit
#elseif canImport(AppKit)
import AppKit
#endif

// MARK: – Navigationstitel

extension View {
    /// iOS zeigt den Titel in der Navigationsleiste klein und zentriert.
    /// macOS kennt den Modifier nicht und lässt die Ansicht unverändert.
    @ViewBuilder
    func inlineNavigationTitle() -> some View {
        #if os(iOS)
        self.navigationBarTitleDisplayMode(.inline)
        #else
        self
        #endif
    }
}

// MARK: – Tastatur

/// Plattformunabhängige Tastaturbelegung. Auf macOS ohne Wirkung.
enum PlatformKeyboardType {
    case `default`
    case emailAddress
    case numberPad
    case URL
}

extension View {
    @ViewBuilder
    func platformKeyboardType(_ type: PlatformKeyboardType) -> some View {
        #if os(iOS)
        self.keyboardType(type.uiKeyboardType)
        #else
        self
        #endif
    }

    /// Keine automatische Großschreibung. macOS kennt den Modifier nicht.
    @ViewBuilder
    func platformNoAutocapitalization() -> some View {
        #if os(iOS)
        self.textInputAutocapitalization(.never)
        #else
        self
        #endif
    }
}

#if os(iOS)
private extension PlatformKeyboardType {
    var uiKeyboardType: UIKeyboardType {
        switch self {
        case .default:      return .default
        case .emailAddress: return .emailAddress
        case .numberPad:    return .numberPad
        case .URL:          return .URL
        }
    }
}
#endif

// MARK: – Toolbar-Platzierung

extension ToolbarItemPlacement {
    /// iOS: führende Position in der oberen Leiste; macOS: Navigationsleiste.
    static var platformTopBarLeading: ToolbarItemPlacement {
        #if os(iOS)
        .topBarLeading
        #else
        .navigation
        #endif
    }

    /// iOS: abschließende Position in der oberen Leiste; macOS: Hauptaktion.
    static var platformTopBarTrailing: ToolbarItemPlacement {
        #if os(iOS)
        .topBarTrailing
        #else
        .primaryAction
        #endif
    }
}

// MARK: – Farben

extension Color {
    /// Entspricht `secondarySystemBackground` auf iOS und der
    /// Steuerelement-Fläche auf macOS.
    static var platformSecondaryBackground: Color {
        #if os(iOS)
        Color(uiColor: .secondarySystemBackground)
        #else
        Color(nsColor: .controlBackgroundColor)
        #endif
    }
}

// MARK: – Externe Links öffnen

/// Öffnet eine URL im Standardbrowser. Auf iOS bestätigt die App das vorher
/// selbst (siehe MessageDetailView), auf macOS übernimmt das der Aufrufer.
func openExternalURL(_ url: URL) {
    #if canImport(UIKit)
    UIApplication.shared.open(url)
    #elseif canImport(AppKit)
    NSWorkspace.shared.open(url)
    #endif
}
