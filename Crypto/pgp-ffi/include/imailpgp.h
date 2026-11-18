// imailpgp.h — C-Schnittstelle zu rpgp für iMail Secure.
//
// Alle Funktionen sind thread-sicher, solange verschiedene Threads nicht
// dieselbe „letzte Fehlermeldung“ erwarten: `imailpgp_last_error` ist
// thread-lokal. Zeiger bleiben nur für die Dauer des Aufrufs gültig;
// Ausgaben werden in vom Aufrufer bereitgestellte Puffer kopiert.

#ifndef IMAILPGP_H
#define IMAILPGP_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/// Rückgabewerte, identisch zu den Konstanten in Rust.
#define IMAILPGP_OK 1
#define IMAILPGP_INVALID 0
#define IMAILPGP_BAD_ARGUMENT -1
#define IMAILPGP_PARSE_ERROR -2
#define IMAILPGP_PANIC -3
#define IMAILPGP_WRONG_PASSWORD -4
#define IMAILPGP_DECRYPT_ERROR -5

/// Version als statischer C-String, z. B. "imailpgp 0.1.0 / rpgp 0.21.1".
const char *imailpgp_version(void);

/// Letzte Fehlermeldung des aufrufenden Threads (leer, wenn kein Fehler).
const char *imailpgp_last_error(void);

/// Prüft, ob `data` einen öffentlichen Schlüssel (armoriert oder binär) enthält.
int32_t imailpgp_parse_public_key(const uint8_t *data, size_t len);

/// Prüft eine abgetrennte Signatur über `data` mit dem öffentlichen Schlüssel.
/// Rückgabe: 1 gültig, 0 ungültig, negativ Fehler.
int32_t imailpgp_verify_detached(const uint8_t *signature, size_t signature_len,
                                 const uint8_t *data, size_t data_len,
                                 const uint8_t *key, size_t key_len);

/// Gibt die primäre User-ID als UTF-8 in `out` (z. B. "Name <mail@example.org>").
/// Rückgabe: Länge, 0 = keine User-ID, negativ = Fehler.
int32_t imailpgp_primary_user_id(const uint8_t *key, size_t key_len,
                                 uint8_t *out, size_t out_len);

/// Schreibt einen öffentlichen Schlüssel als ASCII-Armor in `out`
/// (akzeptiert binär und armiert). Rückgabe: Länge, negativ = Fehler.
int32_t imailpgp_armor_public_key(const uint8_t *key, size_t key_len,
                                  uint8_t *out, size_t out_len);

/// Schreibt den Aussteller der Signatur als Hex (Fingerprint, sonst Key ID)
/// in `out`. Rückgabe: Länge, 0 = kein Aussteller angegeben, negativ = Fehler.
int32_t imailpgp_signature_issuer(const uint8_t *signature, size_t signature_len,
                                  uint8_t *out, size_t out_len);

/// Schreibt den Fingerprint des primären Schlüssels als Hex in `out`
/// (mindestens 40 Bytes, 64 für v6). Rückgabe: Länge oder negativ.
int32_t imailpgp_primary_fingerprint(const uint8_t *key, size_t key_len,
                                     uint8_t *out, size_t out_len);

/// Liest einen geheimen Schlüssel, prüft die Passphrase und schreibt
/// Fingerprint und User-ID in die Puffer. Rückgabe: IMAILPGP_OK,
/// IMAILPGP_WRONG_PASSWORD oder negativ bei Lesefehlern.
int32_t imailpgp_secret_key_info(const uint8_t *key, size_t key_len,
                                 const uint8_t *passphrase, size_t passphrase_len,
                                 uint8_t *fingerprint_out, size_t fingerprint_out_len,
                                 uint8_t *user_id_out, size_t user_id_out_len);

/// Erzeugt eine armierte, abgetrennte SHA-256-Signatur über `data`.
/// Rückgabe: Länge der Signatur (>0) oder negativ bei Fehlern.
int32_t imailpgp_sign_detached(const uint8_t *key, size_t key_len,
                               const uint8_t *passphrase, size_t passphrase_len,
                               const uint8_t *data, size_t data_len,
                               uint8_t *out, size_t out_len);

/// Verschlüsselt `data` für alle Empfänger. `keys` ist eine Folge von
/// `[uint32 little-endian Länge][Schlüssel-Bytes]`; armierte und binäre
/// Schlüssel sind erlaubt. Ausgabe ist ein armoriertes PGP-MESSAGE-Block.
/// Rückgabe: Länge (>0) oder negativ bei Fehlern.
int32_t imailpgp_encrypt(const uint8_t *data, size_t data_len,
                         const uint8_t *keys, size_t keys_len,
                         uint8_t *out, size_t out_len);

/// Entschlüsselt einen armorierten oder binären PGP-MESSAGE-Block mit dem
/// geheimen Schlüssel. Rückgabe: Länge der Klartext-Bytes (>0),
/// IMAILPGP_WRONG_PASSWORD oder negativ bei Fehlern.
int32_t imailpgp_decrypt(const uint8_t *message, size_t message_len,
                         const uint8_t *key, size_t key_len,
                         const uint8_t *passphrase, size_t passphrase_len,
                         uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* IMAILPGP_H */
