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

/// Schreibt den Fingerprint des primären Schlüssels als Hex in `out`
/// (mindestens 40 Bytes, 64 für v6). Rückgabe: Länge oder negativ.
int32_t imailpgp_primary_fingerprint(const uint8_t *key, size_t key_len,
                                     uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* IMAILPGP_H */
