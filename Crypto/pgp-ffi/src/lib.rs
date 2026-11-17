// lib.rs — schmale C-Schnittstelle zu rpgp für iMail Secure.
//
// Ziel: Die App ruft ausschließlich diese Funktionen auf; kein Rust-Typ
// überschreitet die Grenze. Alle Zeiger sind für die Dauer des Aufrufs gültig,
// Rückgaben werden kopiert. Fehler werden über einen Rückgabewert gemeldet,
// niemals über Panics — deshalb fängt jede Funktion Panics ab.
//
// Erste Ausbaustufe: parsen, Fingerprint, Signatur prüfen. Ent- und
// Verschlüsseln folgt in eigenen Funktionen, sobald der Schlüsselbund steht.

use std::ffi::{c_char, CString};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::slice;

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::types::KeyDetails;

/// Rückgabewerte. Bewusst klein und stabil, damit Swift sie als Int32 sieht.
pub const OK: i32 = 1;
pub const INVALID: i32 = 0;
pub const BAD_ARGUMENT: i32 = -1;
pub const PARSE_ERROR: i32 = -2;
pub const PANIC: i32 = -3;

thread_local! {
    static LAST_ERROR: std::cell::RefCell<CString> =
        std::cell::RefCell::new(CString::new("").unwrap());
}

fn set_error(message: impl Into<String>) {
    let sanitized = message.into().replace('\0', " ");
    LAST_ERROR.with(|slot| {
        *slot.borrow_mut() = CString::new(sanitized).unwrap_or_default();
    });
}

fn bytes_from<'a>(data: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        // Leere Daten sind gültig (z. B. Signatur über eine leere Nachricht);
        // ein Null-Zeiger ist es nicht.
        return if data.is_null() { None } else { Some(&[]) };
    }
    if data.is_null() {
        return None;
    }
    // SAFETY: Der Aufrufer garantiert, dass `data` für `len` Bytes lesbar ist.
    Some(unsafe { slice::from_raw_parts(data, len) })
}

/// rpgp erkennt Armor nicht selbst: `from_bytes` liest nur binäre Pakete.
/// Schlüssel aus WKD, Autocrypt oder `gpg --armor --export` sind aber fast
/// immer ASCII-armiert. Deshalb wird hier anhand der Kopfzeile entschieden.
fn looks_armored(bytes: &[u8]) -> bool {
    bytes.starts_with(b"-----BEGIN PGP ")
}

fn parse_public_key(bytes: &[u8]) -> Result<SignedPublicKey, String> {
    if looks_armored(bytes) {
        let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
        SignedPublicKey::from_string(text)
            .map(|(key, _headers)| key)
            .map_err(|error| error.to_string())
    } else {
        SignedPublicKey::from_bytes(bytes).map_err(|error| error.to_string())
    }
}

fn parse_detached_signature(bytes: &[u8]) -> Result<DetachedSignature, String> {
    if looks_armored(bytes) {
        let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
        DetachedSignature::from_string(text)
            .map(|(signature, _headers)| signature)
            .map_err(|error| error.to_string())
    } else {
        DetachedSignature::from_bytes(bytes).map_err(|error| error.to_string())
    }
}

/// Version der Bibliothek als NUL-terminierter String. Statisch, muss nicht
/// freigegeben werden.
#[no_mangle]
pub extern "C" fn imailpgp_version() -> *const c_char {
    // Einmalig erzeugt, danach nur noch gelesen.
    static VERSION: std::sync::OnceLock<CString> = std::sync::OnceLock::new();
    VERSION
        .get_or_init(|| {
            CString::new(format!(
                "imailpgp {} / rpgp 0.21.1",
                env!("CARGO_PKG_VERSION")
            ))
            .unwrap()
        })
        .as_ptr()
}

/// Letzte Fehlermeldung des aktuellen Threads. Zeigt auf thread-lokalen
/// Speicher; gültig bis zum nächsten Aufruf im selben Thread.
#[no_mangle]
pub extern "C" fn imailpgp_last_error() -> *const c_char {
    LAST_ERROR.with(|slot| slot.borrow().as_ptr())
}

/// Prüft, ob die Bytes einen öffentlichen Schlüssel enthalten.
/// 1 = gültig, 0 = ungültig, negativ = Fehler.
#[no_mangle]
pub extern "C" fn imailpgp_parse_public_key(data: *const u8, len: usize) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(bytes) = bytes_from(data, len) else {
            set_error("leerer Schlüssel");
            return BAD_ARGUMENT;
        };
        match parse_public_key(bytes) {
            Ok(key) => {
                set_error("");
                // Ein Schlüssel ohne Unterschlüssel kann noch gültig sein
                // (reiner Signaturschlüssel); entscheidend ist, dass er parst.
                let _ = key.primary_key;
                OK
            }
            Err(error) => {
                set_error(error.to_string());
                PARSE_ERROR
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Parsen des Schlüssels");
        PANIC
    })
}

/// Prüft eine abgetrennte Signatur.
///
/// 1 = Signatur gültig, 0 = Signatur ungültig, negativ = Fehler beim Parsen.
/// `key` ist ein Transferable Public Key (armoriert oder binär).
#[no_mangle]
pub extern "C" fn imailpgp_verify_detached(
    signature: *const u8,
    signature_len: usize,
    data: *const u8,
    data_len: usize,
    key: *const u8,
    key_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(signature_bytes), Some(data_bytes), Some(key_bytes)) = (
            bytes_from(signature, signature_len),
            bytes_from(data, data_len),
            bytes_from(key, key_len),
        ) else {
            set_error("leeres Argument");
            return BAD_ARGUMENT;
        };

        let signature = match parse_detached_signature(signature_bytes) {
            Ok(signature) => signature,
            Err(error) => {
                set_error(format!("Signatur nicht lesbar: {error}"));
                return PARSE_ERROR;
            }
        };
        let key = match parse_public_key(key_bytes) {
            Ok(key) => key,
            Err(error) => {
                set_error(format!("Schlüssel nicht lesbar: {error}"));
                return PARSE_ERROR;
            }
        };

        match signature.verify(&key, data_bytes) {
            Ok(()) => {
                set_error("");
                OK
            }
            Err(error) => {
                set_error(error.to_string());
                INVALID
            }
        }
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic bei der Signaturprüfung");
        PANIC
    })
}

/// Gibt den Fingerprint des primären Schlüssels als Hex aus. `out` muss
/// mindestens 64 Bytes fassen. Rückgabe: Länge oder negativ bei Fehler.
#[no_mangle]
pub extern "C" fn imailpgp_primary_fingerprint(
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(key_bytes) = bytes_from(key, key_len) else {
            set_error("leerer Schlüssel");
            return BAD_ARGUMENT;
        };
        if out.is_null() || out_len < 40 {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        let key = match parse_public_key(key_bytes) {
            Ok(key) => key,
            Err(error) => {
                set_error(error.to_string());
                return PARSE_ERROR;
            }
        };
        let hex = key.primary_key.fingerprint().to_string().to_uppercase();
        let bytes = hex.as_bytes();
        if bytes.len() > out_len {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: `out` zeigt auf mindestens `out_len` beschreibbare Bytes.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
        bytes.len() as i32
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Fingerprint");
        PANIC
    })
}

/// Gibt die primäre User-ID (z. B. `Name <mail@example.org>`) als UTF-8 aus.
/// `out` muss großzügig sein (256 Bytes reichen für übliche IDs).
/// Rückgabe: Länge, 0 = keine User-ID vorhanden, negativ = Fehler.
#[no_mangle]
pub extern "C" fn imailpgp_primary_user_id(
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(key_bytes) = bytes_from(key, key_len) else {
            set_error("leerer Schlüssel");
            return BAD_ARGUMENT;
        };
        if out.is_null() || out_len == 0 {
            set_error("Ausgabepuffer fehlt");
            return BAD_ARGUMENT;
        }
        let key = match parse_public_key(key_bytes) {
            Ok(key) => key,
            Err(error) => {
                set_error(error.to_string());
                return PARSE_ERROR;
            }
        };
        let Some(user) = key.details.users.first() else {
            set_error("");
            return 0;
        };
        // User-IDs sind laut RFC UTF-8, in der Praxis aber nicht immer. Verlust-
        // behaftete Umwandlung ist hier richtig: lieber anzeigen als abbrechen.
        let text = String::from_utf8_lossy(user.id.id());
        let bytes = text.as_bytes();
        if bytes.len() > out_len {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: `out` zeigt auf mindestens `out_len` beschreibbare Bytes.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
        bytes.len() as i32
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Lesen der User-ID");
        PANIC
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{
        KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
    };
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::ser::Serialize;
    use pgp::types::Password;

    fn generate_key() -> SignedSecretKey {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(false)
            .can_sign(true)
            .primary_user_id("Test <test@example.org>".into())
            .preferred_hash_algorithms(vec![HashAlgorithm::Sha256].into())
            .subkeys(vec![SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                .build()
                .expect("Subkey")])
            .build()
            .expect("Params");
        params.generate(&mut rand::thread_rng()).expect("Schlüssel")
    }

    #[test]
    fn roundtrip_detached_signature() {
        let secret = generate_key();
        let public = secret.to_public_key();
        let data = b"Hallo Welt";

        let signature = DetachedSignature::sign_binary_data(
            &mut rand::thread_rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &data[..],
        )
        .expect("signieren");

        let sig_bytes = signature.to_bytes().expect("serialisieren");
        let key_bytes = public.to_bytes().expect("schlüssel serialisieren");

        let status = imailpgp_verify_detached(
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            data.as_ptr(),
            data.len(),
            key_bytes.as_ptr(),
            key_bytes.len(),
        );
        assert_eq!(status, OK, "Signatur muss gültig sein");

        let mut tampered = data.to_vec();
        tampered[0] ^= 0xFF;
        let status = imailpgp_verify_detached(
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            tampered.as_ptr(),
            tampered.len(),
            key_bytes.as_ptr(),
            key_bytes.len(),
        );
        assert_eq!(status, INVALID, "Manipulierte Daten müssen auffallen");
    }

    #[test]
    fn empty_data_is_not_a_bad_argument() {
        // Leere Nutzdaten sind zulässig; sie dürfen nicht als „leeres Argument“
        // abgewiesen werden, sondern müssen zur Prüfung führen.
        let secret = generate_key();
        let public = secret.to_public_key();
        let signature = DetachedSignature::sign_binary_data(
            &mut rand::thread_rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &b""[..],
        )
        .expect("leere Daten signieren");

        let sig_bytes = signature.to_bytes().expect("serialisieren");
        let key_bytes = public.to_bytes().expect("schlüssel");

        let empty: [u8; 1] = [0];
        let status = imailpgp_verify_detached(
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            empty.as_ptr(),
            0,
            key_bytes.as_ptr(),
            key_bytes.len(),
        );
        assert_eq!(status, OK, "Signatur über leere Daten muss gültig sein");
    }

    #[test]
    fn accepts_armored_key_and_signature() {
        // WKD und Autocrypt liefern ASCII-armierte Schlüssel; `gpg --detach-sign
        // --armor` ebenso. Beides muss die FFI annehmen.
        let secret = generate_key();
        let public = secret.to_public_key();
        let data = b"Hallo Welt";

        let signature = DetachedSignature::sign_binary_data(
            &mut rand::thread_rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &data[..],
        )
        .expect("signieren");

        let armored_sig = signature.to_armored_bytes(Default::default()).expect("armor sig");
        let armored_key = public.to_armored_bytes(Default::default()).expect("armor key");
        assert_eq!(
            imailpgp_parse_public_key(armored_key.as_ptr(), armored_key.len()),
            OK
        );

        let status = imailpgp_verify_detached(
            armored_sig.as_ptr(),
            armored_sig.len(),
            data.as_ptr(),
            data.len(),
            armored_key.as_ptr(),
            armored_key.len(),
        );
        assert_eq!(status, OK, "armierte Signatur muss gültig sein");
    }

    #[test]
    fn parses_and_rejects_garbage() {
        let secret = generate_key();
        let public = secret.to_public_key();
        let key_bytes = public.to_bytes().expect("schlüssel");
        assert_eq!(
            imailpgp_parse_public_key(key_bytes.as_ptr(), key_bytes.len()),
            OK
        );

        let garbage = b"kein OpenPGP";
        assert_eq!(
            imailpgp_parse_public_key(garbage.as_ptr(), garbage.len()),
            PARSE_ERROR
        );
    }

    #[test]
    fn reads_primary_user_id() {
        let secret = generate_key();
        let public = secret.to_public_key();
        let key_bytes = public.to_bytes().expect("schlüssel");
        let mut out = [0u8; 256];
        let len = imailpgp_primary_user_id(
            key_bytes.as_ptr(),
            key_bytes.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert!(len > 0);
        let user_id = std::str::from_utf8(&out[..len as usize]).expect("UTF-8");
        assert!(user_id.contains("test@example.org"), "{user_id}");
    }

    #[test]
    fn fingerprint_is_hex() {
        let secret = generate_key();
        let public = secret.to_public_key();
        let key_bytes = public.to_bytes().expect("schlüssel");
        let mut out = [0u8; 64];
        let len = imailpgp_primary_fingerprint(
            key_bytes.as_ptr(),
            key_bytes.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert!(len > 0);
        let hex = std::str::from_utf8(&out[..len as usize]).expect("ASCII");
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
