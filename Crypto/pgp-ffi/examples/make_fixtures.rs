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

    // Ein zweiter, passphrasegeschützter Schlüssel für den ausgehenden Pfad.
    // Er bleibt unabhängig vom ersten Fixture-Schlüssel, damit bestehende
    // Tests ihren bekannten Fingerprint behalten.
    let signing_passphrase = "test-passphrase";
    let signing_params = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(false)
        .can_sign(true)
        .passphrase(Some(signing_passphrase.to_string()))
        .primary_user_id("iMail Secure Signing <signing@imailsecure.invalid>".into())
        .preferred_hash_algorithms(vec![HashAlgorithm::Sha256].into())
        .subkeys(vec![SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .build()?])
        .build()?;
    let signing_secret = signing_params.generate(&mut rand::thread_rng())?;
    let signing_public = signing_secret.to_public_key();
    let armored_signing_secret =
        String::from_utf8(signing_secret.to_armored_bytes(Default::default())?)?;
    let armored_signing_public =
        String::from_utf8(signing_public.to_armored_bytes(Default::default())?)?;
    let signing_fingerprint = signing_public.fingerprint().to_string().to_uppercase();

    let armored_key = String::from_utf8(public.to_armored_bytes(Default::default())?)?;
    let armored_sig = String::from_utf8(signature.to_armored_bytes(Default::default())?)?;
    let fingerprint = public.fingerprint().to_string().to_uppercase();

    // --- PGP/MIME (RFC 3156) ------------------------------------------------
    // Eine echte Nachricht: die Signatur gilt über die Rohbytes des ersten
    // Teils, inklusive seiner MIME-Kopfzeilen. Genau das muss der Parser
    // extrahieren — deshalb wird hier nicht irgendetwas „vereinfacht".
    let signed_entity = "Content-Type: text/plain; charset=utf-8\r\n\
                         Content-Transfer-Encoding: 8bit\r\n\
                         \r\n\
                         Hallo PGP/MIME,\r\n\
                         \r\n\
                         dieser Text ist signiert.";

    let mime_signature = DetachedSignature::sign_binary_data(
        &mut rand::thread_rng(),
        &secret.primary_key,
        &Password::empty(),
        HashAlgorithm::Sha256,
        signed_entity.as_bytes(),
    )?;
    let mime_sig_armored = String::from_utf8(
        mime_signature.to_armored_bytes(Default::default())?,
    )?
    .replace('\n', "\r\n");

    let boundary = "imailsecure-test-boundary";
    let signed_message = format!(
        "From: iMail Secure Test <test@imailsecure.invalid>\r\n\
         To: empfaenger@imailsecure.invalid\r\n\
         Subject: Signierte Testnachricht\r\n\
         Date: Tue, 17 Nov 2026 10:00:00 +0000\r\n\
         MIME-Version: 1.0\r\n\
         Content-Type: multipart/signed; micalg=pgp-sha256; protocol=\"application/pgp-signature\"; boundary=\"{boundary}\"\r\n\
         \r\n\
         This is an OpenPGP/MIME signed message (RFC 3156)\r\n\
         --{boundary}\r\n\
         {signed_entity}\r\n\
         --{boundary}\r\n\
         Content-Type: application/pgp-signature; name=\"signature.asc\"\r\n\
         Content-Description: OpenPGP digital signature\r\n\
         Content-Disposition: attachment; filename=\"signature.asc\"\r\n\
         \r\n\
         {mime_sig_armored}--{boundary}--\r\n"
    );

    // Dieselbe Nachricht mit LF-only-Zustellung und einer im Text veränderten
    // Fassung: Beides muss der Parser unterscheiden können. Die Swift-Fixture
    // hält LF fest; CRLF entsteht im Test per Ersetzung, weil Swift-
    // Mehrzeilenliterale keine CRLF zuverlässig abbilden.
    let tampered_message = signed_message.replace(
        "dieser Text ist signiert.",
        "dieser Text wurde verändert.",
    );
    let signed_message_lf = signed_message.replace("\r\n", "\n");
    let tampered_message_lf = tampered_message.replace("\r\n", "\n");

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

    /// Vollständige PGP/MIME-Nachricht (RFC 3156): erster Teil signiert,
    /// zweiter Teil die Signatur. Hier mit LF; `signedMessageCRLF` liefert
    /// dieselbe Nachricht so, wie sie über SMTP läuft.
    static let signedMessage = """
{signed_message_lf}"""

    /// Dieselbe Nachricht mit CRLF-Zeilenenden.
    static var signedMessageCRLF: String {{
        signedMessage.replacingOccurrences(of: "\n", with: "\r\n")
    }}

    /// Dieselbe Nachricht, ein Wort im Text verändert — die Signatur muss
    /// dann als ungültig erkannt werden.
    static let tamperedSignedMessage = """
{tampered_message_lf}"""

    /// Fingerprint des primären Schlüssels, Großbuchstaben-Hex.
    static let fingerprint = "{fingerprint}"

    /// Passphrasegeschützter geheimer Schlüssel für den ausgehenden Pfad.
    static let privateKey = """
{armored_signing_secret}"""

    /// Passphrase zum geheimen Schlüssel. Nur Testdaten.
    static let privateKeyPassphrase = "{signing_passphrase}"

    /// Öffentlicher Gegenstand zum geheimen Schlüssel.
    static let privateKeyPublicKey = """
{armored_signing_public}"""

    /// Fingerprint des geheimen Schlüssels.
    static let privateKeyFingerprint = "{signing_fingerprint}"

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
