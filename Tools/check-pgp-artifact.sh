#!/usr/bin/env bash
#
# Prüft, ob das PGP-Artefakt vor dem Öffnen des Xcode-Projekts existiert.
# Läuft als Teil des postGenCommand von XcodeGen, damit der Fehler dort
# auffällt und nicht erst im Linken mit kryptischen Symbolen endet.
#
# Das XCFramework ist ein Build-Artefakt (Crypto/build/, nicht eingecheckt).

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT="$ROOT/Crypto/build/PGPKit.xcframework"

if [[ -d "$ARTIFACT" ]]; then
  exit 0
fi

cat >&2 <<'EOF'
Fehlendes PGP-Artefakt: Crypto/build/PGPKit.xcframework

Das XCFramework ist bewusst nicht eingecheckt. Einmalig bauen mit:

    Tools/build-pgp-ios.sh

Voraussetzung ist eine Rust-Toolchain (rustup); Details stehen in
Crypto/README.md. Danach `xcodegen generate` erneut ausführen.
EOF
exit 1
