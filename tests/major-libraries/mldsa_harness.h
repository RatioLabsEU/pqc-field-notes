/* Shared harness that runs the Wycheproof ML-DSA verification vectors through a library written in C or C++.
 *
 * Each adapter defines:
 *   const char* lib_name(void);
 *   void lib_init(int argc, char** argv);                   (may do nothing)
 *   int  lib_verify(int p, pk, npk, msg, nmsg, ctx, nctx, sig, nsig);   1 = accepted, 0 = rejected, -1 = no interface
 * where p is 44, 65 or 87. A key or a context that the library does not take counts as a rejection.
 *
 * Usage:  <program> <vector file in text form> <44|65|87> [adapter arguments]
 * Line format:  tcId|result|public key|message|context|signature|comment   (hex)
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef MLDSA_HARNESS_H
#define MLDSA_HARNESS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char* lib_name(void);
void lib_init(int argc, char** argv);
int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig);

#define HARNESS_MAXB 70000
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
    static char line[400000];
    static uint8_t pk[HARNESS_MAXB], msg[HARNESS_MAXB], ctx[HARNESS_MAXB], sig[HARNESS_MAXB];
    FILE* f = argc > 2 ? fopen(argv[1], "r") : NULL;
    int p = argc > 2 ? atoi(argv[2]) : 0;
    long total = 0, bad_accept = 0, bad_reject = 0, not_applicable = 0;

    if (f == NULL) { printf("usage: program <vectors> <44|65|87>\n"); return 2; }
    lib_init(argc, argv);
    while (fgets(line, sizeof(line), f)) {
        char* c[7];
        char* q = line;
        int i, ok, expected;
        size_t npk, nmsg, nctx, nsig;
        line[strcspn(line, "\r\n")] = 0;
        for (i = 0; i < 7; i++) {
            c[i] = q;
            if (i < 6) { q = strchr(q, '|'); if (q == NULL) break; *q++ = 0; }
        }
        if (i < 6) continue;
        npk = harness_hex(c[2], pk); nmsg = harness_hex(c[3], msg); nctx = harness_hex(c[4], ctx); nsig = harness_hex(c[5], sig);
        expected = strcmp(c[1], "valid") == 0;
        ok = lib_verify(p, pk, npk, msg, nmsg, ctx, nctx, sig, nsig);
        if (ok < 0) { not_applicable++; continue; } /* the library has no interface for this vector */
        total++;
        if (ok && !expected) { bad_accept++; printf("  INVALID ACCEPTED  tcId=%s  %s\n", c[0], c[6]); }
        if (!ok && expected) { bad_reject++; printf("  valid rejected    tcId=%s  %s\n", c[0], c[6]); }
    }
    printf("%-34s ML-DSA-%d  vectors=%ld   INVALID ACCEPTED=%ld   valid rejected=%ld",
           lib_name(), p, total, bad_accept, bad_reject);
    if (not_applicable > 0) printf("   (not applicable: %ld)", not_applicable);
    printf("\n");
    return bad_accept > 0 || bad_reject > 0;
}

#endif
