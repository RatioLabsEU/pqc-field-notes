/* Run the Wycheproof ML-KEM vectors that carry an explicit key against liboqs.
 *
 * Input: the text produced by mlkem_to_text.py. Only two line types are used here, because they
 * need nothing but the public liboqs API of every version:
 *   E  encapsulation with a given encapsulation key (invalid keys must be rejected)
 *   X  decapsulation with a given expanded decapsulation key (invalid keys must be rejected)
 * liboqs takes keys as fixed-length byte strings, so a key of another length is counted as rejected
 * without calling the library.
 *
 * Usage:  wycheproof_mlkem_liboqs <vector file> <512|768|1024>
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <oqs/oqs.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAXB 20000
static size_t unhex(const char* s, uint8_t* out)
{
    size_t n = 0;
    while (s[0] && s[1] && n < MAXB) {
        unsigned v;
        if (sscanf(s, "%2x", &v) != 1) break;
        out[n++] = (uint8_t)v;
        s += 2;
    }
    return n;
}

int main(int argc, char** argv)
{
    static char line[100000];
    static uint8_t a[MAXB], b[MAXB], c[MAXB], kexp[MAXB], ct[MAXB];
    FILE* f = argc > 2 ? fopen(argv[1], "r") : NULL;
    int p = argc > 2 ? atoi(argv[2]) : 0;
    long n[2] = {0, 0}, accepted[2] = {0, 0}, failed[2] = {0, 0};
    static const char* const KIND[2] = {"encaps", "expanded dk"};
    OQS_KEM* kem;
    int t;

    if (f == NULL) { printf("usage: wycheproof_mlkem_liboqs <vectors> <512|768|1024>\n"); return 2; }
    OQS_init();
    kem = OQS_KEM_new(p == 512 ? "ML-KEM-512" : p == 768 ? "ML-KEM-768" : "ML-KEM-1024");
    if (kem == NULL) { printf("ML-KEM-%d not available\n", p); return 2; }
    while (fgets(line, sizeof(line), f)) {
        char* x[8];
        char* q = line;
        uint8_t K[64];
        int i, ok, expected, good;
        size_t na, nb, nc, nk;
        line[strcspn(line, "\r\n")] = 0;
        for (i = 0; i < 8; i++) {
            x[i] = q;
            if (i < 7) { q = strchr(q, '|'); if (q == NULL) break; *q++ = 0; }
        }
        if (i < 7) continue;
        expected = strcmp(x[2], "valid") == 0;
        memset(K, 0, sizeof(K));
        if (x[0][0] == 'E') {
            t = 0;
            na = unhex(x[3], a); nb = unhex(x[4], b);
            ok = na == 32 && nb == kem->length_public_key && OQS_KEM_encaps(kem, ct, K, b) == OQS_SUCCESS;
            good = ok; /* randomness is not fixed here: only acceptance is checked */
        } else if (x[0][0] == 'X') {
            t = 1;
            na = unhex(x[3], a); nc = unhex(x[4], c); nk = unhex(x[5], kexp);
            ok = na == kem->length_secret_key && nc == kem->length_ciphertext && OQS_KEM_decaps(kem, K, c, a) == OQS_SUCCESS;
            good = ok && nk == 32 && memcmp(K, kexp, 32) == 0;
        } else {
            continue;
        }
        n[t]++;
        if (expected && !good) { failed[t]++; printf("  VALID FAILED      [%s] tcId=%s  %s\n", KIND[t], x[1], x[7]); }
        if (!expected && ok) { accepted[t]++; printf("  INVALID ACCEPTED  [%s] tcId=%s  %s\n", KIND[t], x[1], x[7]); }
    }
    printf("liboqs %-8s ML-KEM-%-4d", OQS_version(), p);
    for (t = 0; t < 2; t++)
        printf(" | %s: %ld vectors, INVALID ACCEPTED=%ld, VALID FAILED=%ld", KIND[t], n[t], accepted[t], failed[t]);
    printf("\n");
    return 0;
}
