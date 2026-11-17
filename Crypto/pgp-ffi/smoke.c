// smoke.c — prüft das iOS-Artefakt ohne Xcode-Projekt: ABI, Linken, Aufrufe.
//
// Wird gegen die Simulator-Slice gebaut und direkt auf dem Mac ausgeführt
// (iOS-Simulator-Binaries laufen nativ auf Apple Silicon). Die eigentliche
// Kryptographie decken die Rust-Tests ab; hier geht es um das, was beim
// Einbinden schiefgehen kann: Symbole, Header, Rückgabewerte.

#include <stdio.h>
#include <string.h>
#include "imailpgp.h"

int main(void) {
    printf("version: %s\n", imailpgp_version());

    const uint8_t garbage[] = "kein OpenPGP";
    int32_t parse = imailpgp_parse_public_key(garbage, sizeof(garbage) - 1);
    printf("parse(garbage): %d (erwartet %d) %s\n", parse, IMAILPGP_PARSE_ERROR,
           parse == IMAILPGP_PARSE_ERROR ? "ok" : "FEHLER");
    if (parse != IMAILPGP_PARSE_ERROR) return 1;

    int32_t empty = imailpgp_verify_detached(NULL, 0, NULL, 0, NULL, 0);
    printf("verify(leer): %d (erwartet %d) %s\n", empty, IMAILPGP_BAD_ARGUMENT,
           empty == IMAILPGP_BAD_ARGUMENT ? "ok" : "FEHLER");
    if (empty != IMAILPGP_BAD_ARGUMENT) return 1;

    int32_t fp = imailpgp_primary_fingerprint(garbage, sizeof(garbage) - 1, NULL, 0);
    printf("fingerprint(leer): %d (erwartet negativ) %s\n", fp,
           fp < 0 ? "ok" : "FEHLER");
    if (fp >= 0) return 1;

    printf("Fehlermeldung: %s\n", imailpgp_last_error());
    return 0;
}
