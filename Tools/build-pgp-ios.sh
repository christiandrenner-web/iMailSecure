#!/usr/bin/env bash
#
# Baut die rpgp-FFI für iOS und macOS und erzeugt
# Crypto/build/PGPKit.xcframework.
#
# Voraussetzungen (einmalig):
#   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
#   rustup target add aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios \
#                     aarch64-apple-darwin x86_64-apple-darwin
#
# Aufruf: Tools/build-pgp-ios.sh [--debug]
#
# Das Ergebnis ist bewusst nicht eingecheckt: Es ist ein Build-Artefakt.
# Quellcode und Cargo.lock liegen im Repository, damit jeder es reproduzieren
# kann. Ohne dieses Artefakt lässt sich das Xcode-Projekt nicht übersetzen —
# `xcodegen generate` scheitert dann mit einer klaren Meldung.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CRATE="$ROOT/Crypto/pgp-ffi"
OUT="$ROOT/Crypto/build"
PROFILE="release"
CARGO_FLAGS=()

if [[ "${1:-}" == "--debug" ]]; then
  PROFILE="debug"
fi
if [[ "$PROFILE" == "release" ]]; then
  CARGO_FLAGS+=(--release)
fi

if ! command -v cargo >/dev/null 2>&1; then
  # rustup legt cargo nicht in die PATH der aktuellen Shell.
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  else
    echo "cargo fehlt. Siehe Kopf dieser Datei." >&2
    exit 1
  fi
fi

# Gerät, beide Simulator-Slices und beide Mac-Slices. Der Mac braucht eigene
# Bibliotheken, weil das macOS-Target dieselben Quellen übersetzt.
IOS_TARGETS=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
MAC_TARGETS=(aarch64-apple-darwin x86_64-apple-darwin)

missing=()
for target in "${IOS_TARGETS[@]}" "${MAC_TARGETS[@]}"; do
  if ! rustup target list --installed | grep -qx "$target"; then
    missing+=("$target")
  fi
done
if (( ${#missing[@]} )); then
  echo "Fehlende Rust-Targets: ${missing[*]}" >&2
  echo "Nachinstallieren: rustup target add ${missing[*]}" >&2
  exit 1
fi

echo "==> rpgp für iOS und macOS bauen ($PROFILE)"
for target in "${IOS_TARGETS[@]}" "${MAC_TARGETS[@]}"; do
  cargo build --manifest-path "$CRATE/Cargo.toml" "${CARGO_FLAGS[@]}" --target "$target"
done

DEVICE_LIB="$CRATE/target/aarch64-apple-ios/$PROFILE/libimailpgp.a"
SIM_ARM_LIB="$CRATE/target/aarch64-apple-ios-sim/$PROFILE/libimailpgp.a"
SIM_X86_LIB="$CRATE/target/x86_64-apple-ios/$PROFILE/libimailpgp.a"
MAC_ARM_LIB="$CRATE/target/aarch64-apple-darwin/$PROFILE/libimailpgp.a"
MAC_X86_LIB="$CRATE/target/x86_64-apple-darwin/$PROFILE/libimailpgp.a"

for lib in "$DEVICE_LIB" "$SIM_ARM_LIB" "$SIM_X86_LIB" "$MAC_ARM_LIB" "$MAC_X86_LIB"; do
  if [[ ! -f "$lib" ]]; then
    echo "Bibliothek fehlt: $lib" >&2
    exit 1
  fi
done

rm -rf "$OUT"
mkdir -p "$OUT"

# Je Plattform eine Bibliothek mit beiden Architekturen, damit das XCFramework
# auf Intel- und Apple-Silicon-Macs läuft.
SIM_LIB="$OUT/libimailpgp-simulator.a"
MAC_LIB="$OUT/libimailpgp-macos.a"
lipo -create "$SIM_ARM_LIB" "$SIM_X86_LIB" -output "$SIM_LIB"
lipo -create "$MAC_ARM_LIB" "$MAC_X86_LIB" -output "$MAC_LIB"

# Header mit in das XCFramework legen, sonst findet Swift den Modul-Import nicht.
HEADERS="$OUT/Headers"
mkdir -p "$HEADERS"
cp "$CRATE/include/imailpgp.h" "$HEADERS/"
cat > "$HEADERS/module.modulemap" <<'EOF'
// Erlaubt Swift `import imailpgp`, ohne Brücken-Header.
module imailpgp {
    header "imailpgp.h"
    export *
}
EOF

xcodebuild -create-xcframework \
  -library "$DEVICE_LIB" -headers "$HEADERS" \
  -library "$SIM_LIB" -headers "$HEADERS" \
  -library "$MAC_LIB" -headers "$HEADERS" \
  -output "$OUT/PGPKit.xcframework" >/dev/null

echo "==> Fertig: $OUT/PGPKit.xcframework"
du -sh "$OUT/PGPKit.xcframework"
size -m "$DEVICE_LIB" 2>/dev/null | tail -1 || true
