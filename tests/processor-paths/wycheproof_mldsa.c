/* Run Wycheproof ML-DSA verification vectors against one implementation and list the mismatches.
 *
 * Input: the text produced by wycheproof_to_text.py.
 * Two build modes:
 *   -DWITH_LIBOQS -DALG="\"ML-DSA-65\""     verify with OQS_SIG_verify_with_ctx_str
 *   -DNS=PQCLEAN_MLDSA65_AARCH64             verify with the PQClean function of that namespace
 *
 * A mismatch is an "invalid" vector that is accepted or a "valid" vector that is rejected.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_LIBOQS
#include <oqs/oqs.h>
static OQS_SIG* S;
static size_t PK_LEN;
static const char* LABEL = ALG;
static int verify(const uint8_t* sig, size_t n, const uint8_t* m, size_t mlen, const uint8_t* ctx, size_t ctxlen,
                  const uint8_t* pk)
{
    return OQS_SIG_verify_with_ctx_str(S, m, mlen, sig, n, ctx, ctxlen, pk) == OQS_SUCCESS;
}
#else
#include "api.h"
#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
#define F(x) CAT(NS, x)
#define STR2(x) #x
#define STR(x) STR2(x)
static size_t PK_LEN = F(_CRYPTO_PUBLICKEYBYTES);
static const char* LABEL = STR(NS);
static int verify(const uint8_t* sig, size_t n, const uint8_t* m, size_t mlen, const uint8_t* ctx, size_t ctxlen,
                  const uint8_t* pk)
{
    return F(_crypto_sign_verify_ctx)(sig, n, m, mlen, ctx, ctxlen, pk) == 0;
}
#endif

#define MAXB 70000
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
    static char line[400000];
    static uint8_t pk[MAXB], msg[MAXB], ctx[MAXB], sig[MAXB];
    FILE* f = argc > 1 ? fopen(argv[1], "r") : NULL;
    long total = 0, valid = 0, invalid = 0, bad_accept = 0, bad_reject = 0, skipped = 0;

    if (f == NULL) { printf("missing vector file\n"); return 2; }
#ifdef WITH_LIBOQS
    OQS_init();
    S = OQS_SIG_new(ALG);
    if (S == NULL) { printf("%s not available\n", ALG); return 2; }
    PK_LEN = S->length_public_key;
#endif
    while (fgets(line, sizeof(line), f)) {
        char* c[7];
        int i, ok, expected;
        size_t npk, nmsg, nctx, nsig;
        char* p = line;
        line[strcspn(line, "\r\n")] = 0;
        for (i = 0; i < 7; i++) {
            c[i] = p;
            if (i < 6) { p = strchr(p, '|'); if (p == NULL) break; *p++ = 0; }
        }
        if (i < 6) continue;
        npk = unhex(c[2], pk); nmsg = unhex(c[3], msg); nctx = unhex(c[4], ctx); nsig = unhex(c[5], sig);
        if (npk != PK_LEN || nctx > 255) { skipped++; continue; } /* key or context the API cannot take */
        total++;
        expected = strcmp(c[1], "valid") == 0;
        if (expected) valid++; else invalid++;
        ok = verify(sig, nsig, msg, nmsg, ctx, nctx, pk);
        if (ok && !expected) { bad_accept++; printf("  INVALID ACCEPTED  tcId=%s  %s\n", c[0], c[6]); }
        if (!ok && expected) { bad_reject++; printf("  valid rejected    tcId=%s  %s\n", c[0], c[6]); }
    }
    printf("%-26s vectors=%ld (valid %ld, invalid %ld, not applicable %ld)   INVALID ACCEPTED=%ld   valid rejected=%ld\n",
           LABEL, total, valid, invalid, skipped, bad_accept, bad_reject);
    return bad_accept > 0 || bad_reject > 0;
}
