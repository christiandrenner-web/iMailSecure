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

use pgp::composed::{
    Deserializable, DetachedSignature, Message, MessageBuilder, SignedPublicKey,
    SignedPublicSubKey, SignedSecretKey,
};
use pgp::crypto::{hash::HashAlgorithm, sym::SymmetricKeyAlgorithm};
use pgp::packet::PublicKey as PublicKeyPacket;
use pgp::types::{KeyDetails, Password};

/// Rückgabewerte. Bewusst klein und stabil, damit Swift sie als Int32 sieht.
pub const OK: i32 = 1;
pub const INVALID: i32 = 0;
pub const BAD_ARGUMENT: i32 = -1;
pub const PARSE_ERROR: i32 = -2;
pub const PANIC: i32 = -3;
/// Der geheime Schlüssel ist lesbar, aber die Passphrase passt nicht.
pub const WRONG_PASSWORD: i32 = -4;
/// Entschlüsseln ging nicht: kein passender Schlüssel oder kaputte Nachricht.
pub const DECRYPT_ERROR: i32 = -5;

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

fn parse_secret_key(bytes: &[u8]) -> Result<SignedSecretKey, String> {
    if looks_armored(bytes) {
        let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
        SignedSecretKey::from_string(text)
            .map(|(key, _headers)| key)
            .map_err(|error| error.to_string())
    } else {
        SignedSecretKey::from_bytes(bytes).map_err(|error| error.to_string())
    }
}

/// Leere Passphrase bedeutet: ein unverschlüsselter Schlüssel darf benutzt
/// werden. Bei einem verschlüsselten Schlüssel schlägt `unlock` fehl.
fn password_from(bytes: Option<&[u8]>) -> Password {
    match bytes {
        Some(bytes) if !bytes.is_empty() => Password::from(bytes),
        _ => Password::empty(),
    }
}

/// `Message::from_bytes` liest nur Binärpakete. Unsere Ausgabe ist armoriert
/// (und eingehende Mails sind es meist auch), deshalb hier dieselbe
/// Kopfzeilen-Prüfung wie bei Schlüsseln und Signaturen.
fn parse_message(bytes: &[u8]) -> Result<Message<'_>, String> {
    if looks_armored(bytes) {
        let text = std::str::from_utf8(bytes).map_err(|error| error.to_string())?;
        Message::from_string(text).map(|(message, _headers)| message)
    } else {
        Message::from_bytes(bytes)
    }
    .map_err(|error| error.to_string())
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

/// Empfänger-Schlüssel kommen als ein Puffer: auf jeden Schlüssel folgt eine
/// `u32` in Little-Endian mit seiner Länge. So bleibt die C-Schnittstelle bei
/// zwei Zeigern, auch wenn eine Mail an mehrere Empfänger geht. Swift baut
/// den Puffer; hier wird er streng gelesen — ein abgeschnittener Eintrag ist
/// ein Fehler, kein still ignoriertes Ende.
fn read_key_bundle(bytes: &[u8]) -> Result<Vec<SignedPublicKey>, String> {
    let mut index = 0;
    let mut keys = Vec::new();
    while index < bytes.len() {
        if index + 4 > bytes.len() {
            return Err("Schlüsselbund abgeschnitten".into());
        }
        let length = u32::from_le_bytes(
            bytes[index..index + 4]
                .try_into()
                .expect("vier Bytes"),
        ) as usize;
        index += 4;
        if length == 0 || index + length > bytes.len() {
            return Err("Schlüssellänge im Bund ungültig".into());
        }
        keys.push(parse_public_key(&bytes[index..index + length])?);
        index += length;
    }
    if keys.is_empty() {
        return Err("keine Empfänger im Schlüsselbund".into());
    }
    Ok(keys)
}

/// Wählt den Verschlüsselungsschlüssel eines Zertifikats. Bei modernen
/// Ed25519/Curve25519-Schlüsseln ist das der ECDH-Subkey, nicht der Primär-
/// schlüssel — `SignedPublicKey::encrypt` würde sonst den Primärschlüssel
/// nehmen und an einer Signatur-Kapazität scheitern.
/// `EncryptionKey` hat eine generische `encrypt`-Methode und ist deshalb
/// nicht als Trait-Objekt nutzbar — daher zwei konkrete Fälle im enum.
enum EncryptionTarget<'a> {
    Subkey(&'a SignedPublicSubKey),
    Primary(&'a PublicKeyPacket),
}

fn encryption_target(key: &SignedPublicKey) -> Option<EncryptionTarget<'_>> {
    if let Some(subkey) = key
        .public_subkeys
        .iter()
        .find(|subkey| subkey.algorithm().can_encrypt())
    {
        return Some(EncryptionTarget::Subkey(subkey));
    }
    if key.primary_key.algorithm().can_encrypt() {
        return Some(EncryptionTarget::Primary(&key.primary_key));
    }
    None
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

/// Schreibt einen öffentlichen Schlüssel als ASCII-Armor in `out`.
/// WKD liefert binäre Schlüssel, Autocrypt base64-kodierte Binärschlüssel;
/// der Schlüsselbund speichert aber einheitlich armierte Texte. Die FFI
/// übernimmt die Serialisierung, damit Swift keine OpenPGP-Pakete baut.
/// Rückgabe: Länge (>0), negativ = Fehler.
#[no_mangle]
pub extern "C" fn imailpgp_armor_public_key(
    key: *const u8,
    key_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(bytes) = bytes_from(key, key_len) else {
            set_error("leerer Schlüssel");
            return BAD_ARGUMENT;
        };
        if out.is_null() || out_len == 0 {
            set_error("Ausgabepuffer fehlt");
            return BAD_ARGUMENT;
        }
        let public = match parse_public_key(bytes) {
            Ok(key) => key,
            Err(error) => {
                set_error(format!("Schlüssel nicht lesbar: {error}"));
                return PARSE_ERROR;
            }
        };
        let armored = match public.to_armored_bytes(Default::default()) {
            Ok(bytes) => bytes,
            Err(error) => {
                set_error(format!("Schlüssel nicht armierbar: {error}"));
                return PARSE_ERROR;
            }
        };
        if armored.len() > out_len {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: `out` zeigt auf mindestens `out_len` beschreibbare Bytes.
        unsafe { ptr::copy_nonoverlapping(armored.as_ptr(), out, armored.len()) };
        set_error("");
        armored.len() as i32
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Armieren des Schlüssels");
        PANIC
    })
}

/// Liest einen geheimen Schlüssel und prüft die Passphrase. Liefert
/// Fingerprint und User-ID, damit die App den Schlüssel eindeutig anzeigen
/// und der eingegebenen Adresse zuordnen kann. Es wird nichts gespeichert.
///
/// Rückgabe: OK bei Erfolg, WRONG_PASSWORD bei falscher Passphrase, sonst
/// negativ. `passphrase` darf leer sein (unverschlüsselter Schlüssel).
#[no_mangle]
pub extern "C" fn imailpgp_secret_key_info(
    key: *const u8,
    key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    fingerprint_out: *mut u8,
    fingerprint_out_len: usize,
    user_id_out: *mut u8,
    user_id_out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(key_bytes) = bytes_from(key, key_len) else {
            set_error("leerer Schlüssel");
            return BAD_ARGUMENT;
        };
        let passphrase = bytes_from(passphrase, passphrase_len);
        if fingerprint_out.is_null() || fingerprint_out_len < 40 || user_id_out.is_null() {
            set_error("Ausgabepuffer fehlt");
            return BAD_ARGUMENT;
        }
        let secret = match parse_secret_key(key_bytes) {
            Ok(secret) => secret,
            Err(error) => {
                set_error(format!("Geheimer Schlüssel nicht lesbar: {error}"));
                return PARSE_ERROR;
            }
        };

        // `unlock` führt keine Kryptographie aus, sondern entschlüsselt nur
        // kurzfristig die geheimen Parameter. Genau damit prüfen wir die
        // Passphrase, ohne den Schlüssel in eine Datei zu schreiben.
        let password = password_from(passphrase);
        if let Err(error) = secret
            .primary_key
            .unlock(&password, |_, _| Ok(()))
            .and_then(|inner| inner)
        {
            set_error(format!("Passphrase passt nicht: {error}"));
            return WRONG_PASSWORD;
        }

        let fingerprint = secret.primary_key.fingerprint().to_string().to_uppercase();
        let fingerprint_bytes = fingerprint.as_bytes();
        if fingerprint_bytes.len() > fingerprint_out_len {
            set_error("Ausgabepuffer für Fingerprint zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: Der Aufrufer garantiert die angegebene Puffergröße.
        unsafe {
            ptr::copy_nonoverlapping(
                fingerprint_bytes.as_ptr(),
                fingerprint_out,
                fingerprint_bytes.len(),
            )
        };

        if user_id_out_len > 0 {
            if let Some(user) = secret.details.users.first() {
                let text = String::from_utf8_lossy(user.id.id());
                let bytes = text.as_bytes();
                let copy_length = bytes.len().min(user_id_out_len);
                // SAFETY: Der Aufrufer garantiert die angegebene Puffergröße.
                unsafe {
                    ptr::copy_nonoverlapping(bytes.as_ptr(), user_id_out, copy_length)
                };
            }
        }

        set_error("");
        OK
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Lesen des geheimen Schlüssels");
        PANIC
    })
}

/// Erzeugt eine abgetrennte OpenPGP-Signatur (SHA-256, binär) über `data`.
/// Ausgegeben wird ASCII-Armor, wie er in `multipart/signed` steht. SHA-256
/// ist hier fest verdrahtet, damit micalg und Signaturalgorithmus zusammen-
/// passen und die Gegenprobe mit `imailpgp_verify_detached` funktioniert.
///
/// Rückgabe: Länge der armorierten Signatur (>0), negativ = Fehler.
#[no_mangle]
pub extern "C" fn imailpgp_sign_detached(
    key: *const u8,
    key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(key_bytes), Some(data_bytes)) = (
            bytes_from(key, key_len),
            bytes_from(data, data_len),
        ) else {
            set_error("leeres Argument");
            return BAD_ARGUMENT;
        };
        let passphrase = bytes_from(passphrase, passphrase_len);
        if out.is_null() || out_len == 0 {
            set_error("Ausgabepuffer fehlt");
            return BAD_ARGUMENT;
        }
        let secret = match parse_secret_key(key_bytes) {
            Ok(secret) => secret,
            Err(error) => {
                set_error(format!("Geheimer Schlüssel nicht lesbar: {error}"));
                return PARSE_ERROR;
            }
        };
        let password = password_from(passphrase);
        if let Err(error) = secret
            .primary_key
            .unlock(&password, |_, _| Ok(()))
            .and_then(|inner| inner)
        {
            set_error(format!("Passphrase passt nicht: {error}"));
            return WRONG_PASSWORD;
        }

        let signature = match DetachedSignature::sign_binary_data(
            &mut rand::thread_rng(),
            &secret.primary_key,
            &password,
            HashAlgorithm::Sha256,
            data_bytes,
        ) {
            Ok(signature) => signature,
            Err(error) => {
                set_error(format!("Signieren fehlgeschlagen: {error}"));
                return PARSE_ERROR;
            }
        };
        let armored = match signature.to_armored_bytes(Default::default()) {
            Ok(bytes) => bytes,
            Err(error) => {
                set_error(format!("Signatur nicht armierbar: {error}"));
                return PARSE_ERROR;
            }
        };
        if armored.len() > out_len {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: Der Aufrufer garantiert die angegebene Puffergröße.
        unsafe { ptr::copy_nonoverlapping(armored.as_ptr(), out, armored.len()) };
        set_error("");
        armored.len() as i32
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Signieren");
        PANIC
    })
}

/// Verschlüsselt `data` für alle Empfänger im Schlüsselbund (siehe
/// `read_key_bundle`). Ausgegeben wird ein armoriertes OpenPGP-Message-Block,
/// wie er im zweiten Teil von `multipart/encrypted` steht. AES-256 ist fest
/// verdrahtet; es gibt keine Passphrase-Verschlüsselung ohne Empfänger.
///
/// Rückgabe: Länge der armorierten Nachricht (>0), negativ = Fehler.
#[no_mangle]
pub extern "C" fn imailpgp_encrypt(
    data: *const u8,
    data_len: usize,
    keys: *const u8,
    keys_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(data_bytes), Some(key_bytes)) = (
            bytes_from(data, data_len),
            bytes_from(keys, keys_len),
        ) else {
            set_error("leeres Argument");
            return BAD_ARGUMENT;
        };
        if out.is_null() || out_len == 0 {
            set_error("Ausgabepuffer fehlt");
            return BAD_ARGUMENT;
        }

        let recipients = match read_key_bundle(key_bytes) {
            Ok(keys) => keys,
            Err(error) => {
                set_error(format!("Empfänger nicht lesbar: {error}"));
                return BAD_ARGUMENT;
            }
        };
        let mut targets: Vec<EncryptionTarget<'_>> = Vec::with_capacity(recipients.len());
        for recipient in &recipients {
            match encryption_target(recipient) {
                Some(target) => targets.push(target),
                None => {
                    set_error("Ein Empfänger hat keinen Verschlüsselungsschlüssel");
                    return BAD_ARGUMENT;
                }
            }
        }

        let mut rng = rand::thread_rng();
        let mut builder = MessageBuilder::from_bytes("message.mime", data_bytes)
            .seipd_v1(&mut rng, SymmetricKeyAlgorithm::AES256);
        for target in targets {
            let result = match target {
                EncryptionTarget::Subkey(subkey) => builder.encrypt_to_key(&mut rng, subkey),
                EncryptionTarget::Primary(primary) => builder.encrypt_to_key(&mut rng, primary),
            };
            if let Err(error) = result {
                set_error(format!("Verschlüsseln fehlgeschlagen: {error}"));
                return PARSE_ERROR;
            }
        }
        let armored = match builder.to_armored_string(&mut rng, Default::default()) {
            Ok(armored) => armored,
            Err(error) => {
                set_error(format!("Nachricht nicht armierbar: {error}"));
                return PARSE_ERROR;
            }
        };
        let bytes = armored.as_bytes();
        if bytes.len() > out_len {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: Der Aufrufer garantiert die angegebene Puffergröße.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
        set_error("");
        bytes.len() as i32
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Verschlüsseln");
        PANIC
    })
}

/// Entschlüsselt ein armoriertes oder binäres OpenPGP-Message-Block mit dem
/// geheimen Schlüssel. Geliefert werden die inneren Bytes — bei PGP/MIME eine
/// MIME-Einheit, die der Aufrufer weiter liest. Es wird nichts gespeichert.
///
/// Rückgabe: Länge der Klartext-Bytes (>0), WRONG_PASSWORD oder negativ.
#[no_mangle]
pub extern "C" fn imailpgp_decrypt(
    message: *const u8,
    message_len: usize,
    key: *const u8,
    key_len: usize,
    passphrase: *const u8,
    passphrase_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let (Some(message_bytes), Some(key_bytes)) = (
            bytes_from(message, message_len),
            bytes_from(key, key_len),
        ) else {
            set_error("leeres Argument");
            return BAD_ARGUMENT;
        };
        let passphrase = bytes_from(passphrase, passphrase_len);
        if out.is_null() || out_len == 0 {
            set_error("Ausgabepuffer fehlt");
            return BAD_ARGUMENT;
        }
        let secret = match parse_secret_key(key_bytes) {
            Ok(secret) => secret,
            Err(error) => {
                set_error(format!("Geheimer Schlüssel nicht lesbar: {error}"));
                return PARSE_ERROR;
            }
        };
        let password = password_from(passphrase);
        if let Err(error) = secret
            .primary_key
            .unlock(&password, |_, _| Ok(()))
            .and_then(|inner| inner)
        {
            set_error(format!("Passphrase passt nicht: {error}"));
            return WRONG_PASSWORD;
        }

        let mut decrypted = match parse_message(message_bytes).and_then(|message| {
            message
                .decrypt(&password, &secret)
                .map_err(|error| error.to_string())
        }) {
            Ok(message) => message,
            Err(error) => {
                set_error(format!("Entschlüsseln fehlgeschlagen: {error}"));
                return DECRYPT_ERROR;
            }
        };
        if decrypted.is_compressed() {
            match decrypted.decompress() {
                Ok(message) => decrypted = message,
                Err(error) => {
                    set_error(format!("Dekomprimieren fehlgeschlagen: {error}"));
                    return DECRYPT_ERROR;
                }
            }
        }
        let plain = match decrypted.as_data_vec() {
            Ok(data) => data,
            Err(error) => {
                set_error(format!("Klartext nicht lesbar: {error}"));
                return DECRYPT_ERROR;
            }
        };
        if plain.len() > out_len {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: Der Aufrufer garantiert die angegebene Puffergröße.
        unsafe { ptr::copy_nonoverlapping(plain.as_ptr(), out, plain.len()) };
        set_error("");
        plain.len() as i32
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Entschlüsseln");
        PANIC
    })
}

/// Hexadezimal, Großbuchstaben — für Key IDs, die rpgp nicht selbst als
/// String ausgibt.
fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Schreibt den Aussteller einer abgetrennten Signatur als Hex in `out`:
/// bevorzugt den Issuer-Fingerprint (v4/v6), sonst die 8-Byte-Key-ID
/// (16 Hexzeichen). Nur ein Hinweis, welche Schlüssel zu prüfen sind —
/// die eigentliche Prüfung macht `imailpgp_verify_detached`.
/// Rückgabe: Länge (>0), 0 = kein Aussteller angegeben, negativ = Fehler.
#[no_mangle]
pub extern "C" fn imailpgp_signature_issuer(
    signature: *const u8,
    signature_len: usize,
    out: *mut u8,
    out_len: usize,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        let Some(sig_bytes) = bytes_from(signature, signature_len) else {
            set_error("leere Signatur");
            return BAD_ARGUMENT;
        };
        if out.is_null() || out_len == 0 {
            set_error("Ausgabepuffer fehlt");
            return BAD_ARGUMENT;
        }
        let sig = match parse_detached_signature(sig_bytes) {
            Ok(sig) => sig,
            Err(error) => {
                set_error(format!("Signatur nicht lesbar: {error}"));
                return PARSE_ERROR;
            }
        };
        let issuer = sig
            .signature
            .issuer_fingerprint()
            .first()
            .map(|fingerprint| fingerprint.to_string().to_uppercase())
            .or_else(|| {
                sig.signature
                    .issuer_key_id()
                    .first()
                    .map(|key_id| hex_upper(key_id.as_ref()))
            });
        let Some(issuer) = issuer else {
            set_error("");
            return 0;
        };
        let bytes = issuer.as_bytes();
        if bytes.len() > out_len {
            set_error("Ausgabepuffer zu klein");
            return BAD_ARGUMENT;
        }
        // SAFETY: `out` zeigt auf mindestens `out_len` beschreibbare Bytes.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out, bytes.len()) };
        bytes.len() as i32
    }));
    result.unwrap_or_else(|_| {
        set_error("Panic beim Lesen des Ausstellers");
        PANIC
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pgp::composed::{
        EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
    };
    use pgp::crypto::ecc_curve::ECCCurve;
    use pgp::crypto::hash::HashAlgorithm;
    use pgp::ser::Serialize;
    use pgp::types::Password;

    fn generate_key_with_passphrase(passphrase: Option<&str>) -> SignedSecretKey {
        let params = SecretKeyParamsBuilder::default()
            .key_type(KeyType::Ed25519Legacy)
            .can_certify(false)
            .can_sign(true)
            .primary_user_id("Test <test@example.org>".into())
            .preferred_hash_algorithms(vec![HashAlgorithm::Sha256].into())
            .passphrase(passphrase.map(str::to_string))
            .subkeys(vec![SubkeyParamsBuilder::default()
                .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
                .can_encrypt(EncryptionCaps::All)
                .build()
                .expect("Subkey")])
            .build()
            .expect("Params");
        params.generate(&mut rand::thread_rng()).expect("Schlüssel")
    }

    fn generate_key() -> SignedSecretKey {
        generate_key_with_passphrase(None)
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
    fn armors_binary_key_for_the_store() {
        // WKD und Autocrypt liefern Binärschlüssel; der Schlüsselbund
        // speichert armierte Texte. Die gerundete FFI muss daraus genau
        // denselben Schlüssel machen.
        let secret = generate_key();
        let public = secret.to_public_key();
        let binary = public.to_bytes().expect("schlüssel");

        let mut out = vec![0u8; 16_384];
        let len = imailpgp_armor_public_key(
            binary.as_ptr(),
            binary.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert!(len > 0);
        let armored = &out[..len as usize];
        assert!(armored.starts_with(b"-----BEGIN PGP PUBLIC KEY BLOCK-----"));
        assert_eq!(imailpgp_parse_public_key(armored.as_ptr(), armored.len()), OK);
    }

    #[test]
    fn secret_key_info_checks_passphrase_and_reports_identity() {
        // Der Import muss die Passphrase prüfen, bevor der Schlüssel im
        // Keychain landet. Fingerprint und User-ID kommen aus rpgp, nicht aus
        // dem Textfeld der Oberfläche.
        let secret = generate_key_with_passphrase(Some("geheim"));
        let key_bytes = secret.to_armored_bytes(Default::default()).expect("armor");
        let public = secret.to_public_key();
        let expected = public.fingerprint().to_string().to_uppercase();
        let password = b"geheim";

        let mut fingerprint = [0u8; 64];
        let mut user_id = [0u8; 256];
        let status = imailpgp_secret_key_info(
            key_bytes.as_ptr(),
            key_bytes.len(),
            password.as_ptr(),
            password.len(),
            fingerprint.as_mut_ptr(),
            fingerprint.len(),
            user_id.as_mut_ptr(),
            user_id.len(),
        );
        assert_eq!(status, OK);
        assert_eq!(
            std::str::from_utf8(&fingerprint).expect("UTF-8").trim_end_matches('\0'),
            expected
        );
        assert!(std::str::from_utf8(&user_id)
            .expect("UTF-8")
            .contains("test@example.org"));

        let wrong = b"falsch";
        let status = imailpgp_secret_key_info(
            key_bytes.as_ptr(),
            key_bytes.len(),
            wrong.as_ptr(),
            wrong.len(),
            fingerprint.as_mut_ptr(),
            fingerprint.len(),
            user_id.as_mut_ptr(),
            user_id.len(),
        );
        assert_eq!(status, WRONG_PASSWORD, "falsche Passphrase muss auffallen");
    }

    #[test]
    fn sign_detached_roundtrips_and_rejects_wrong_passphrase() {
        // Genau diese Signatur später in multipart/signed: Sie muss mit dem
        // öffentlichen Schlüssel prüfbar sein und mit falscher Passphrase
        // gar nicht erst entstehen.
        let secret = generate_key_with_passphrase(Some("geheim"));
        let key_bytes = secret.to_armored_bytes(Default::default()).expect("armor");
        let public_bytes = secret
            .to_public_key()
            .to_bytes()
            .expect("öffentlicher Schlüssel");
        let data = b"signierte MIME-Einheit\r\nZeile 2";
        let password = b"geheim";

        let mut signature = vec![0u8; 16_384];
        let len = imailpgp_sign_detached(
            key_bytes.as_ptr(),
            key_bytes.len(),
            password.as_ptr(),
            password.len(),
            data.as_ptr(),
            data.len(),
            signature.as_mut_ptr(),
            signature.len(),
        );
        assert!(len > 0, "Signatur muss erzeugt werden");
        let signature = &signature[..len as usize];
        assert!(signature.starts_with(b"-----BEGIN PGP SIGNATURE-----"));
        assert_eq!(
            imailpgp_verify_detached(
                signature.as_ptr(),
                signature.len(),
                data.as_ptr(),
                data.len(),
                public_bytes.as_ptr(),
                public_bytes.len(),
            ),
            OK
        );

        let mut tampered = data.to_vec();
        tampered[0] ^= 0xFF;
        assert_eq!(
            imailpgp_verify_detached(
                signature.as_ptr(),
                signature.len(),
                tampered.as_ptr(),
                tampered.len(),
                public_bytes.as_ptr(),
                public_bytes.len(),
            ),
            INVALID
        );

        let wrong = b"falsch";
        let mut out = vec![0u8; 16_384];
        let status = imailpgp_sign_detached(
            key_bytes.as_ptr(),
            key_bytes.len(),
            wrong.as_ptr(),
            wrong.len(),
            data.as_ptr(),
            data.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert_eq!(status, WRONG_PASSWORD);
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
    fn reports_signature_issuer() {
        // Der Aussteller ist der Hinweis, welchen Schlüssel die App zum
        // Prüfen heranziehen muss. Fingerprint (v4) oder Key ID, nie leer.
        let secret = generate_key();
        let public = secret.to_public_key();
        let signature = DetachedSignature::sign_binary_data(
            &mut rand::thread_rng(),
            &secret.primary_key,
            &Password::empty(),
            HashAlgorithm::Sha256,
            &b"aussteller"[..],
        )
        .expect("signieren");
        let sig_bytes = signature.to_bytes().expect("serialisieren");

        let mut out = [0u8; 128];
        let len = imailpgp_signature_issuer(
            sig_bytes.as_ptr(),
            sig_bytes.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert!(len > 0);
        let issuer = std::str::from_utf8(&out[..len as usize]).expect("UTF-8");
        let fingerprint = public.fingerprint().to_string().to_uppercase();
        assert!(
            fingerprint.ends_with(issuer) || issuer == fingerprint,
            "Aussteller {issuer} passt nicht zu {fingerprint}"
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

    /// Der Bund wird von Swift gebaut: `[u32 LE][Schlüssel]`, zwei Empfänger.
    fn bundle(keys: &[Vec<u8>]) -> Vec<u8> {
        let mut out = Vec::new();
        for key in keys {
            out.extend_from_slice(&(key.len() as u32).to_le_bytes());
            out.extend_from_slice(key);
        }
        out
    }

    #[test]
    fn encrypts_to_multiple_recipients_and_decrypts_with_each() {
        let first = generate_key_with_passphrase(Some("eins"));
        let second = generate_key_with_passphrase(Some("zwei"));
        let bundle = bundle(&[
            first.to_public_key().to_bytes().expect("öffentlich 1"),
            second
                .to_public_key()
                .to_armored_bytes(Default::default())
                .expect("öffentlich 2"),
        ]);
        let plain = b"Content-Type: text/plain\r\n\r\nGeheim mit Umlauten: \xc3\xbc\r\n";

        let mut encrypted = vec![0u8; 64 * 1024];
        let len = imailpgp_encrypt(
            plain.as_ptr(),
            plain.len(),
            bundle.as_ptr(),
            bundle.len(),
            encrypted.as_mut_ptr(),
            encrypted.len(),
        );
        assert!(len > 0);
        let encrypted = &encrypted[..len as usize];
        assert!(encrypted.starts_with(b"-----BEGIN PGP MESSAGE-----"));

        for (secret, password) in [(&first, b"eins"), (&second, b"zwei")] {
            let key = secret.to_armored_bytes(Default::default()).expect("geheim");
            let mut out = vec![0u8; 64 * 1024];
            let out_len = imailpgp_decrypt(
                encrypted.as_ptr(),
                encrypted.len(),
                key.as_ptr(),
                key.len(),
                password.as_ptr(),
                password.len(),
                out.as_mut_ptr(),
                out.len(),
            );
            assert_eq!(
                out_len,
                plain.len() as i32,
                "Entschlüsseln scheiterte: {}",
                unsafe {
                    std::ffi::CStr::from_ptr(imailpgp_last_error())
                        .to_string_lossy()
                }
            );
            assert_eq!(&out[..out_len as usize], plain);
        }
    }

    #[test]
    fn decrypt_rejects_wrong_passphrase_and_foreign_key() {
        let secret = generate_key_with_passphrase(Some("richtig"));
        let bundle = bundle(&[secret
            .to_public_key()
            .to_bytes()
            .expect("öffentlich")]);
        let plain = b"nur fr dich";
        let mut encrypted = vec![0u8; 64 * 1024];
        let len = imailpgp_encrypt(
            plain.as_ptr(),
            plain.len(),
            bundle.as_ptr(),
            bundle.len(),
            encrypted.as_mut_ptr(),
            encrypted.len(),
        );
        assert!(len > 0);

        let key = secret
            .to_armored_bytes(Default::default())
            .expect("geheim");
        let mut out = vec![0u8; 64 * 1024];
        let wrong = b"falsch";
        assert_eq!(
            imailpgp_decrypt(
                encrypted.as_ptr(),
                len as usize,
                key.as_ptr(),
                key.len(),
                wrong.as_ptr(),
                wrong.len(),
                out.as_mut_ptr(),
                out.len(),
            ),
            WRONG_PASSWORD
        );

        // Ein anderer Schlüssel darf den Session Key nicht lesen, auch mit
        // korrekter Passphrase nicht.
        let foreign = generate_key_with_passphrase(Some("richtig"));
        let foreign_key = foreign
            .to_armored_bytes(Default::default())
            .expect("geheim");
        let status = imailpgp_decrypt(
            encrypted.as_ptr(),
            len as usize,
            foreign_key.as_ptr(),
            foreign_key.len(),
            wrong.as_ptr(),
            wrong.len(),
            out.as_mut_ptr(),
            out.len(),
        );
        assert!(status < 0, "fremder Schlüssel darf nicht entschlüsseln");
    }

    #[test]
    fn encrypt_rejects_a_broken_recipient_bundle() {
        let plain = b"test";
        let mut out = vec![0u8; 1024];
        // Länge 4, aber nur zwei Bytes Schlüssel — darf nicht still enden.
        let broken = [4u8, 0, 0, 0, b'a', b'b'];
        assert_eq!(
            imailpgp_encrypt(
                plain.as_ptr(),
                plain.len(),
                broken.as_ptr(),
                broken.len(),
                out.as_mut_ptr(),
                out.len(),
            ),
            BAD_ARGUMENT
        );
    }
}
