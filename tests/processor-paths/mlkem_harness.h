/* Shared harness that runs the Wycheproof ML-KEM vectors through a library written in C or C++.
 *
 * Each adapter defines the following (p is 512, 768 or 1024; they return 1 = operation succeeded, 0 = error or
 * input rejected, -1 = the library has no interface for this):
 *   lib_seed       generates the key from the 64-byte seed and decapsulates c. If it can, it returns the
 *                  encapsulation key in ek (and its length in *nek; 0 if the library does not give it).
 *   lib_encaps     encapsulates with the encapsulation key ek and the randomness m. If the library lets the caller fix
 *                  the randomness, it returns the ciphertext in c (*nc > 0) and the shared secret in K; if not, *nc = 0.
 *   lib_decaps_dk  decapsulates c with the expanded decapsulation key dk.
 *
 * Usage:  <program> <file from mlkem_to_text.py> <512|768|1024> [adapter arguments]
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef MLKEM_HARNESS_H
#define MLKEM_HARNESS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* lib_name(void);
void lib_init(int argc, char** argv);
int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K);
int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K);
int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K);

#define MK_EK(p) ((p) == 512 ? 800 : (p) == 768 ? 1184 : 1568)
#define MK_DK(p) ((p) == 512 ? 1632 : (p) == 768 ? 2400 : 3168)
#define MK_CT(p) ((p) == 512 ? 768 : (p) == 768 ? 1088 : 1568)

#define HARNESS_MAXB 20000
static size_t harness_hex(const char* s, uint8_t* out)
{
    size_t n = 0;
    while (s[0] && s[1] && n < HARNESS_MAXB) {
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
    static uint8_t a[HARNESS_MAXB], b[HARNESS_MAXB], c[HARNESS_MAXB], kexp[HARNESS_MAXB], o1[HARNESS_MAXB], o2[HARNESS_MAXB];
    FILE* f = argc > 2 ? fopen(argv[1], "r") : NULL;
    int p = argc > 2 ? atoi(argv[2]) : 0;
    long n[3] = {0, 0, 0}, accepted[3] = {0, 0, 0}, failed[3] = {0, 0, 0}, na[3] = {0, 0, 0};
    static const char* const KIND[3] = {"seed", "encaps", "expanded dk"};
    int t;

    if (f == NULL) { printf("usage: program <vectors> <512|768|1024>\n"); return 2; }
    lib_init(argc, argv);
    while (fgets(line, sizeof(line), f)) {
        char* x[8];
        char* q = line;
        uint8_t K[64];
        int i, r, expected, good = 0;
        size_t na_, nb_, nc_, nk_, n1 = 0;
        line[strcspn(line, "\r\n")] = 0;
        for (i = 0; i < 8; i++) {
            x[i] = q;
            if (i < 7) { q = strchr(q, '|'); if (q == NULL) break; *q++ = 0; }
        }
        if (i < 7) continue;
        expected = strcmp(x[2], "valid") == 0;
        memset(K, 0, sizeof(K));
        if (x[0][0] == 'D') {
            t = 0;
            na_ = harness_hex(x[3], a); nb_ = harness_hex(x[4], b); nc_ = harness_hex(x[5], c); nk_ = harness_hex(x[6], kexp);
            if (na_ != 64) { r = 0; }
            else r = lib_seed(p, a, o1, &n1, c, nc_, K);
            good = r == 1 && nk_ == 32 && memcmp(K, kexp, 32) == 0 && (n1 == 0 || nb_ == 0 || (n1 == nb_ && memcmp(o1, b, nb_) == 0));
        } else if (x[0][0] == 'E') {
            t = 1;
            na_ = harness_hex(x[3], a); nb_ = harness_hex(x[4], b); nc_ = harness_hex(x[5], c); nk_ = harness_hex(x[6], kexp);
            if (na_ != 32) { r = 0; }
            else r = lib_encaps(p, b, nb_, a, o2, &n1, K);
            good = r == 1 && (n1 == 0 || (n1 == nc_ && memcmp(o2, c, nc_) == 0 && nk_ == 32 && memcmp(K, kexp, 32) == 0));
        } else if (x[0][0] == 'X') {
            t = 2;
            na_ = harness_hex(x[3], a); nc_ = harness_hex(x[4], c); nk_ = harness_hex(x[5], kexp);
            r = lib_decaps_dk(p, a, na_, c, nc_, K);
            good = r == 1 && nk_ == 32 && memcmp(K, kexp, 32) == 0;
        } else {
            continue;
        }
        if (r < 0) { na[t]++; continue; }
        n[t]++;
        if (expected && !good) {
            failed[t]++;
            printf("  valid fails       [%s] tcId=%s (%s)  %s\n", KIND[t], x[1], r == 1 ? "different result" : "error", x[7]);
        }
        if (!expected && r == 1) { accepted[t]++; printf("  INVALID ACCEPTED  [%s] tcId=%s  %s\n", KIND[t], x[1], x[7]); }
    }
    printf("%-30s ML-KEM-%-4d", lib_name(), p);
    for (t = 0; t < 3; t++) {
        if (n[t] == 0 && na[t] > 0) printf(" | %s: no interface", KIND[t]);
        else printf(" | %s: %ld vectors, INVALID ACCEPTED=%ld, valid fails=%ld", KIND[t], n[t], accepted[t], failed[t]);
    }
    printf("\n");
    return 0;
}

#endif
