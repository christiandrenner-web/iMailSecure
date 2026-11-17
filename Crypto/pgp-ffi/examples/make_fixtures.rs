// make_fixtures.rs — erzeugt Testdaten für die Swift-Tests.
//
// Aufruf (im Verzeichnis Crypto/pgp-ffi):
//   cargo run --release --example make_fixtures
//
// Ergebnis: Tests/iMailSecureTests/Fixtures/PGPFixtures.swift mit einem
// öffentlichen Schlüssel, einer abgetrennten Signatur über `payload` und den
// Nutzdaten selbst. Die Datei wird eingecheckt, damit die Swift-Tests ohne
// Rust-Toolchain laufen. Neu erzeugen nur, wenn sich das Format ändert.

use std::fs;
use std::path::PathBuf;

use pgp::composed::{
    Deserializable, DetachedSignature, KeyType, SecretKeyParamsBuilder, SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use pgp::crypto::hash::HashAlgorithm;
use pgp::types::{KeyDetails, Password};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(false)
        .can_sign(true)
        .primary_user_id("iMail Secure Test <test@imailsecure.invalid>".into())
        .preferred_hash_algorithms(vec![HashAlgorithm::Sha256].into())
        .subkeys(vec![SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .build()?])
        .build()?;
    let secret = params.generate(&mut rand::thread_rng())?;
    let public = secret.to_public_key();

    // Nutzdaten mit Umlauten und Zeilenumbrüchen: so fällt auf, wenn irgendwo
    // beim Durchreichen der Bytes normalisiert oder neu kodiert wird. Kein
    // abschließender Zeilenumbruch, damit die Swift-Multiline-String-Darstellung
    // exakt denselben Inhalt hat.
    let payload = "Hallo PGP,\n\nGrüße aus der Testsuite – Zeile 3.";

    let signature = DetachedSignature::sign_binary_data(
        &mut rand::thread_rng(),
        &secret.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        payload.as_bytes(),
    )?;

    // Zweiter, unabhängiger Schlüssel: Die Signatur des ersten darf mit ihm
    // nicht als gültig durchgehen.
    let other_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(false)
        .can_sign(true)
        .primary_user_id("iMail Secure Fremdschlüssel <other@imailsecure.invalid>".into())
        .preferred_hash_algorithms(vec![HashAlgorithm::Sha256].into())
        .subkeys(vec![SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .build()?])
        .build()?;
    let other_secret = other_params.generate(&mut rand::thread_rng())?;
    let other_key = String::from_utf8(
        other_secret
            .to_public_key()
            .to_armored_bytes(Default::default())?,
    )?;

    let armored_key = String::from_utf8(public.to_armored_bytes(Default::default())?)?;
    let armored_sig = String::from_utf8(signature.to_armored_bytes(Default::default())?)?;
    let fingerprint = public.fingerprint().to_string().to_uppercase();

    let swift = format!(
        r#"// PGPFixtures.swift — Testdaten, erzeugt mit
// `cargo run --example make_fixtures` in Crypto/pgp-ffi.
// Nicht von Hand ändern; siehe Crypto/README.md.
//
// Schlüssel und Signatur sind Wegwerfdaten (User-ID endet auf .invalid) und
// haben keinen Wert außerhalb der Tests.

enum PGPFixtures {{
    /// Nutzdaten, über die `signature` gilt.
    static let payload = """
{payload}
"""

    /// Armierter öffentlicher Schlüssel (Ed25519, SHA-256).
    static let publicKey = """
{armored_key}"""

    /// Zweiter, unabhängiger öffentlicher Schlüssel. `signature` ist nicht
    /// von ihm erzeugt und darf mit ihm nicht als gültig gelten.
    static let otherPublicKey = """
{other_key}"""

    /// Armierte abgetrennte Signatur über `payload`.
    static let signature = """
{armored_sig}"""

    /// Fingerprint des primären Schlüssels, Großbuchstaben-Hex.
    static let fingerprint = "{fingerprint}"

    /// Dieselben Nutzdaten, ein Zeichen verändert — die Signatur muss dann
    /// ungültig sein.
    static var tamperedPayload: String {{
        var copy = payload
        copy.replaceSubrange(copy.startIndex...copy.startIndex, with: "X")
        return copy
    }}
}}
"#
    );

    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Tests/iMailSecureTests/Fixtures/PGPFixtures.swift");
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&target, swift)?;
    println!("geschrieben: {}", target.display());
    println!("Fingerprint: {fingerprint}");

    // Gegenprobe: Die erzeugten Bytes müssen sich wieder parsen lassen.
    let reparsed_key = pgp::composed::SignedPublicKey::from_string(&armored_key)?.0;
    assert_eq!(
        reparsed_key.fingerprint().to_string().to_uppercase(),
        fingerprint
    );
    assert!(pgp::composed::DetachedSignature::from_string(&armored_sig).is_ok());
    Ok(())
}
