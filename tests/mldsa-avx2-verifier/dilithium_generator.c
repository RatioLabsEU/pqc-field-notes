/* pqcrypto-dilithium 0.5.0: writes the inputs on which the crate's AVX2 verifier is compared with its portable ("clean")
 * verifier. Built against the C code shipped in the crate itself (pqclean/crypto_sign/dilithiumN/clean, a version of
 * Dilithium from before the standard, pq-crystals 918af1a), with a patched sign.c.
 *
 * The same kind of input as oob_z.c:
 *   out_of_bound  20 signatures per parameter set made by the "clean" signer, patched (run_pqcrypto_dilithium.sh, as in
 *                 run.sh) so that it ONLY emits signatures with  gamma1 - beta <= ||z||_inf < gamma1. A correct signer
 *                 never produces them and the verifier must reject them (FIPS 204, Algorithm 8, line 13:
 *                 ||z|| < gamma1 - beta; the pre-standard version has the same check). Key: the crate's own key
 *                 generation (crypto_sign_keypair of "clean"). Message: the one of oob_z.c ("out-of-bound z test" in
 *                 32 bytes, with the last byte = signature number).
 * And, as a case of our own (run.sh covers it with Wycheproof vector 147/161/174, which does not apply here):
 *   use_hint      a VALID signature built by hand with an all-zero public key (rho = 0, t1 = 0), z = 0 and hints on
 *                 coefficients where w = 0: the verifier has to compute UseHint(1, 0) = (0 - 1) mod m = m - 1
 *                 (m = (q-1)/(2*gamma2), 16 or 44; FIPS 204, Algorithm 40, the same in the pre-standard version).
 *                 c~ is computed as the verifier does: mu = H(H(pk) || M), c~ = H(mu || w1Encode(w1)). The crate's
 *                 "clean" verifier must accept it (control: if it does not, the construction is wrong and the line
 *                 is not written).
 * Output, one line per case:  variant|origin|pk|message|signature|note   (binary fields in hexadecimal).
 * Build (run_pqcrypto_dilithium.sh): -DNS=PQCLEAN_DILITHIUM3_CLEAN -DVARIANT='"dilithium3"' with the .c files of clean
 * (sign.c patched) and common/fips202.c. randombytes is provided by this file (it reads /dev/urandom).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "api.h"
#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "packing.h"
#include "fips202.h"

#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
#define F(x) CAT(NS, x)
#define PKB CAT(NS, _CRYPTO_PUBLICKEYBYTES)
#define SKB CAT(NS, _CRYPTO_SECRETKEYBYTES)
#define SIGB CAT(NS, _CRYPTO_BYTES)

/* randombytes for the PQClean code (common/randombytes.h renames it PQCLEAN_randombytes). */
int PQCLEAN_randombytes(uint8_t* out, size_t n)
{
    FILE* f = fopen("/dev/urandom", "rb");
    size_t r = f ? fread(out, 1, n, f) : 0;
    if (f) fclose(f);
    if (r != n) { fprintf(stderr, "no /dev/urandom\n"); exit(2); }
    return 0;
}

static void hex(const uint8_t* b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) printf("%02x", b[i]);
}

static void line(const char* origin, const uint8_t* pk, const uint8_t* m, size_t mlen, const uint8_t* sig, const char* note)
{
    printf("%s|%s|", VARIANT, origin);
    hex(pk, PKB); printf("|");
    hex(m, mlen); printf("|");
    hex(sig, SIGB); printf("|%s\n", note);
}

/* Valid signature with pk = 0, z = 0 and hints in "nhints" polynomials (coefficient 0). 1 if "clean" accepts it. */
static int usehint(int nhints, uint8_t* pk, uint8_t* m, size_t mlen, uint8_t* sig)
{
    polyvecl z;
    polyveck h, w0, w1, w1lib;
    uint8_t mu[CRHBYTES], ctilde[CTILDEBYTES], buf[K * POLYW1_PACKEDBYTES];
    shake256incctx st;
    int i, j, mm = (Q - 1) / (2 * GAMMA2); /* 16 (gamma2 = (q-1)/32) or 44 (gamma2 = (q-1)/88) */

    memset(pk, 0, PKB);
    memset(&z, 0, sizeof(z));
    memset(&h, 0, sizeof(h));
    memset(&w0, 0, sizeof(w0));
    memset(&w1, 0, sizeof(w1));
    for (i = 0; i < nhints && i < K; i++) {
        h.vec[i].coeffs[0] = 1;
        w1.vec[i].coeffs[0] = mm - 1; /* UseHint(1, r = 0): r0 = 0 is not > 0, so r1 - 1 mod m */
    }
    /* Cross-check with the library's own function (informative only). */
    F(_polyveck_use_hint)(&w1lib, &w0, &h);
    for (i = 0; i < K; i++)
        for (j = 0; j < N; j++)
            if (w1lib.vec[i].coeffs[j] != w1.vec[i].coeffs[j]) { fprintf(stderr, "%s: clean's use_hint differs from FIPS 204 at (%d,%d)\n", VARIANT, i, j); return 0; }
    F(_polyveck_pack_w1)(buf, &w1);
    /* mu = H(H(pk, 64) || M, 64) and c~ = H(mu || w1, CTILDEBYTES), as in crypto_sign_verify of this code. */
    shake256(mu, CRHBYTES, pk, PKB);
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, mu, CRHBYTES);
    shake256_inc_absorb(&st, m, mlen);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(mu, CRHBYTES, &st);
    shake256_inc_ctx_release(&st);
    shake256_inc_init(&st);
    shake256_inc_absorb(&st, mu, CRHBYTES);
    shake256_inc_absorb(&st, buf, K * POLYW1_PACKEDBYTES);
    shake256_inc_finalize(&st);
    shake256_inc_squeeze(ctilde, CTILDEBYTES, &st);
    shake256_inc_ctx_release(&st);
    F(_pack_sig)(sig, ctilde, &z, &h);
    return F(_crypto_sign_verify)(sig, SIGB, m, mlen, pk) == 0;
}

int main(void)
{
    static uint8_t pk[PKB], sk[SKB], sig[SIGB];
    uint8_t msg[32] = "out-of-bound z test";
    size_t n = 0;
    int i, ref = 0;
    char note[96];

    /* 1. Out of bound (as in oob_z.c). */
    if (F(_crypto_sign_keypair)(pk, sk) != 0) return 2;
    for (i = 0; i < 20; i++) {
        msg[31] = (uint8_t)i;
        if (F(_crypto_sign_signature)(sig, &n, msg, sizeof(msg), sk) != 0 || n != SIGB) return 2;
        ref += F(_crypto_sign_verify)(sig, n, msg, sizeof(msg), pk) == 0;
        snprintf(note, sizeof(note), "patched clean signer, signature %d", i);
        line("out_of_bound", pk, msg, sizeof(msg), sig, note);
    }
    fprintf(stderr, "%s: 20 out-of-bound signatures; accepted by the crate's clean verifier: %d\n", VARIANT, ref);

    /* 2. UseHint(1, 0): one hint, and one hint in each of the K polynomials. */
    {
        uint8_t m2[40];
        int cases[2] = {1, K}, c, ok = 0;
        for (c = 0; c < 2; c++) {
            size_t ml = (size_t)snprintf((char*)m2, sizeof(m2), "use_hint(1, 0) with %d hint(s)", cases[c]);
            if (usehint(cases[c], pk, m2, ml, sig)) {
                snprintf(note, sizeof(note), "zero pk, z = 0, %d hint(s) at r = 0 (our construction)", cases[c]);
                line("use_hint", pk, m2, ml, sig, note);
                ok++;
            } else fprintf(stderr, "%s: CONTROL FAILED, clean does not accept the signature built with %d hint(s)\n", VARIANT, cases[c]);
        }
        fprintf(stderr, "%s: use_hint signatures built and accepted by clean: %d of 2\n", VARIANT, ok);
    }
    return 0;
}
