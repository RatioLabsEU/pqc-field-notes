/* SLH-DSA (FIPS 205) interoperability between a library and OpenSSL (development branch commit 354f1cf64842).
 *
 * Built with an adapter (-include adapter_bitcoinpqc.h, adapter_btx.h or adapter_pqmagic.h) that provides L_name,
 * L_supports, L_keygen, L_keygen_seed, L_sign, L_verify and L_verify_raw, all on the library's public interface.
 *
 * For each parameter set that the library offers and each test message (empty, "abc", 200 fixed bytes):
 *   Controls (if they fail, what is broken is this program or the build, not the interoperability):
 *     C1  the library verifies its own signature;          C1n  and rejects that signature with one byte changed
 *     C2  OpenSSL verifies its own signature (OpenSSL's own key, pure, empty context)
 *     C2k OpenSSL signs with the library's private key (imported as "priv") and verifies with the library's public
 *         key itself (not a pure control: it depends on the library's key being the FIPS 205 one; see K1)
 *   Interoperability (the question asked):
 *     I1  library signature -> OpenSSL, pure SLH-DSA, empty context (FIPS 205, Algorithm 24 with an empty ctx)
 *     I3  OpenSSL signature (pure, empty context) -> verification by the library
 *     K1  the seed of the library's key (sk[0..3n) = SK.seed ‖ SK.prf ‖ PK.seed) -> OpenSSL key generation with that
 *         seed: are the public and private keys the same?
 *   Diagnostics (to find out why, if it fails):
 *     I2  library signature -> OpenSSL internal interface (message-encoding = 0: M' = M, no prefix; Algorithm 20)
 *     I4  OpenSSL signature made through the internal interface on M -> verification by the library with M
 *     I5  OpenSSL pure signature (empty ctx) -> verification by the library with M' = 0x00 ‖ 0x00 ‖ M
 *   If I2/I4/I5 pass and I1/I3 fail, the only difference is the FIPS 205 prefix (0x00 ‖ |ctx| ‖ ctx). If I2/I4/I5 fail
 *   too, the signature core (for example the bit order of FORS) is not the one of FIPS 205.
 * Output: one line per test and parameter set with "n/m". Exit code 2 if any control fails.
 *
 * OpenSSL conventions (EVP_SIGNATURE-SLH-DSA(7)): EVP_PKEY_verify returns 1 if the signature is valid, 0 if not and
 * < 0 on other errors; the other EVP calls return 1 on success. "message-encoding" 1 = pure (with the prefix), 0 = no
 * encoding (internal interface). Keys are imported with EVP_PKEY_fromdata ("pub" 2n bytes, "priv" 4n bytes).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/opensslv.h>

typedef struct { const char* name; int n; size_t npk, nsk, nsig; } iset_t;
/* FIPS 205, Table 2. */
static const iset_t ISETS[12] = {
    {"SLH-DSA-SHA2-128s", 16, 32, 64, 7856},   {"SLH-DSA-SHAKE-128s", 16, 32, 64, 7856},
    {"SLH-DSA-SHA2-128f", 16, 32, 64, 17088},  {"SLH-DSA-SHAKE-128f", 16, 32, 64, 17088},
    {"SLH-DSA-SHA2-192s", 24, 48, 96, 16224},  {"SLH-DSA-SHAKE-192s", 24, 48, 96, 16224},
    {"SLH-DSA-SHA2-192f", 24, 48, 96, 35664},  {"SLH-DSA-SHAKE-192f", 24, 48, 96, 35664},
    {"SLH-DSA-SHA2-256s", 32, 64, 128, 29792}, {"SLH-DSA-SHAKE-256s", 32, 64, 128, 29792},
    {"SLH-DSA-SHA2-256f", 32, 64, 128, 49856}, {"SLH-DSA-SHAKE-256f", 32, 64, 128, 49856},
};

#define MAX_SIG 50000

/* ---------- OpenSSL ---------- */
static EVP_PKEY* os_import(const char* pset, const uint8_t* k, size_t nk, int is_private)
{
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(NULL, pset, NULL);
    EVP_PKEY* p = NULL;
    OSSL_PARAM par[2];
    par[0] = OSSL_PARAM_construct_octet_string(is_private ? OSSL_PKEY_PARAM_PRIV_KEY : OSSL_PKEY_PARAM_PUB_KEY, (void*)k, nk);
    par[1] = OSSL_PARAM_construct_end();
    if (c == NULL || EVP_PKEY_fromdata_init(c) != 1
        || EVP_PKEY_fromdata(c, &p, is_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, par) != 1)
        p = NULL;
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return p;
}

/* Key generation with a 3n-byte seed (the "seed" parameter). 1 = success. */
static int os_keygen_seed(const iset_t* j, const uint8_t* seed, uint8_t* pk, uint8_t* sk)
{
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(NULL, j->name, NULL);
    EVP_PKEY* p = NULL;
    OSSL_PARAM par[2];
    size_t npk = 0, nsk = 0;
    int ok;
    par[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, (void*)seed, 3 * (size_t)j->n);
    par[1] = OSSL_PARAM_construct_end();
    ok = c != NULL && EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_CTX_set_params(c, par) == 1 && EVP_PKEY_keygen(c, &p) == 1
         && EVP_PKEY_get_octet_string_param(p, OSSL_PKEY_PARAM_PUB_KEY, pk, 256, &npk) == 1
         && EVP_PKEY_get_octet_string_param(p, OSSL_PKEY_PARAM_PRIV_KEY, sk, 256, &nsk) == 1 && npk == j->npk && nsk == j->nsk;
    EVP_PKEY_free(p);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

/* Randomised signature (no "deterministic"): pure (encode = 1, empty context) or internal (encode = 0). 1 = success. */
static int os_sign(const iset_t* j, const uint8_t* sk, const uint8_t* m, size_t mlen, int encode, uint8_t* sig, size_t* nsig)
{
    EVP_PKEY* p = os_import(j->name, sk, j->nsk, 1);
    EVP_PKEY_CTX* c = NULL;
    EVP_SIGNATURE* s = NULL;
    OSSL_PARAM par[3], *q = par;
    size_t n = MAX_SIG;
    int ok;
    if (p == NULL) return 0;
    if (encode) *q++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"", 0);
    *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    *q = OSSL_PARAM_construct_end();
    ok = (c = EVP_PKEY_CTX_new_from_pkey(NULL, p, NULL)) != NULL && (s = EVP_SIGNATURE_fetch(NULL, j->name, NULL)) != NULL
         && EVP_PKEY_sign_message_init(c, s, par) == 1 && EVP_PKEY_sign(c, sig, &n, m, mlen) == 1;
    *nsig = ok ? n : 0;
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(p);
    ERR_clear_error();
    return ok;
}

/* 1 = accepts, 0 = rejects (or the key could not be imported: reported separately). */
static int os_verify(const iset_t* j, const uint8_t* pk, const uint8_t* m, size_t mlen, int encode, const uint8_t* sig, size_t nsig)
{
    EVP_PKEY* p = os_import(j->name, pk, j->npk, 0);
    EVP_PKEY_CTX* c = NULL;
    EVP_SIGNATURE* s = NULL;
    OSSL_PARAM par[3], *q = par;
    int r = 0;
    if (p == NULL) { printf("   WARNING: OpenSSL does not import the public key\n"); return 0; }
    if (encode) *q++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)"", 0);
    *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    *q = OSSL_PARAM_construct_end();
    if ((c = EVP_PKEY_CTX_new_from_pkey(NULL, p, NULL)) != NULL && (s = EVP_SIGNATURE_fetch(NULL, j->name, NULL)) != NULL
        && EVP_PKEY_verify_message_init(c, s, par) == 1)
        r = EVP_PKEY_verify(c, sig, nsig, m, mlen) == 1;
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(p);
    ERR_clear_error();
    return r;
}

/* ---------- program ---------- */
typedef struct { const char* key; const char* text; int ok, total; } count_t;
enum { C1, C1N, C2, C2K, I1, I3, K1, I2, I4, I5, NTESTS };
static count_t COUNTS[NTESTS] = {
    {"C1 ", "control: the library verifies its own signature", 0, 0},
    {"C1n", "control: the library rejects its signature with one byte changed", 0, 0},
    {"C2 ", "control: OpenSSL verifies its own signature (own key, pure, empty ctx)", 0, 0},
    {"C2k", "OpenSSL signs with the library's key and verifies itself", 0, 0},
    {"I1 ", "library signature -> OpenSSL pure, empty ctx: accepted", 0, 0},
    {"I3 ", "OpenSSL signature, pure, empty ctx -> library: accepted", 0, 0},
    {"K1 ", "same seed -> OpenSSL gives the same keys (pk and sk)", 0, 0},
    {"I2 ", "diagnostic: library signature -> OpenSSL internal (M' = M): accepted", 0, 0},
    {"I4 ", "diagnostic: OpenSSL internal signature (M' = M) -> library: accepted", 0, 0},
    {"I5 ", "diagnostic: OpenSSL pure signature -> library with M' = 00 00 || M: accepted", 0, 0},
};

static void record(int test, int ok) { COUNTS[test].total++; COUNTS[test].ok += ok != 0; }

int main(void)
{
    static uint8_t pk[256], sk[256], pk2[256], sk2[256], sig[MAX_SIG], sig_os[MAX_SIG], sig_osi[MAX_SIG], mp[400], rnd[128];
    static uint8_t m200[200];
    const struct { const char* name; const uint8_t* m; size_t n; } MESSAGES[3] = {
        {"empty", (const uint8_t*)"", 0}, {"abc", (const uint8_t*)"abc", 3}, {"200 bytes", m200, 200}};
    int i, k, t, controls_bad = 0, sets = 0;

    for (i = 0; i < 200; i++) m200[i] = (uint8_t)(i * 37 + 11); /* fixed, reproducible message */
    printf("# %s against OpenSSL %s\n", L_name(), OPENSSL_FULL_VERSION_STR);
    for (k = 0; k < 12; k++) {
        const iset_t* j = &ISETS[k];
        size_t ns = 0, nso = 0, nsoi = 0;
        int raw_good = 0, raw_bad = 0;
        if (!L_supports(j->name)) continue;
        sets++;
        for (t = 0; t < NTESTS; t++) COUNTS[t].ok = COUNTS[t].total = 0;
        for (i = 0; i < 3; i++) {
            const uint8_t* m = MESSAGES[i].m;
            size_t mlen = MESSAGES[i].n;
            /* The library's key and signature, through its public interface. */
            if (RAND_bytes(rnd, sizeof(rnd)) != 1 || !L_keygen(j->name, rnd, pk, sk)) { printf("   %s: the library does not generate a key\n", j->name); controls_bad++; continue; }
            if (!L_sign(j->name, sk, j->nsk, m, mlen, sig, &ns) || ns != j->nsig) { printf("   %s: the library does not sign (or size %zu)\n", j->name, ns); controls_bad++; continue; }
            raw_good = L_verify_raw(j->name, pk, j->npk, m, mlen, sig, ns);
            record(C1, L_verify(j->name, pk, j->npk, m, mlen, sig, ns));
            sig[ns / 2] ^= 0x01;
            raw_bad = L_verify_raw(j->name, pk, j->npk, m, mlen, sig, ns);
            record(C1N, !L_verify(j->name, pk, j->npk, m, mlen, sig, ns));
            sig[ns / 2] ^= 0x01;
            /* K1: the same seed in OpenSSL. */
            record(K1, os_keygen_seed(j, sk, pk2, sk2) && memcmp(pk, pk2, j->npk) == 0 && memcmp(sk, sk2, j->nsk) == 0);
            /* I1, I2: OpenSSL verifies the library's signature. */
            record(I1, os_verify(j, pk, m, mlen, 1, sig, ns));
            record(I2, os_verify(j, pk, m, mlen, 0, sig, ns));
            /* OpenSSL signatures with the library's own private key (imported as "priv"). */
            if (!os_sign(j, sk, m, mlen, 1, sig_os, &nso) || !os_sign(j, sk, m, mlen, 0, sig_osi, &nsoi)) {
                printf("   %s: OpenSSL does not sign with the library's key\n", j->name); controls_bad++; continue;
            }
            record(C2K, os_verify(j, pk, m, mlen, 1, sig_os, nso));
            /* C2: a control independent of the library, with OpenSSL's own key (random seed). */
            {
                static uint8_t seed[96], pko[256], sko[256], so[MAX_SIG];
                size_t nso2 = 0;
                record(C2, RAND_bytes(seed, 3 * j->n) == 1 && os_keygen_seed(j, seed, pko, sko)
                               && os_sign(j, sko, m, mlen, 1, so, &nso2) && os_verify(j, pko, m, mlen, 1, so, nso2));
            }
            record(I3, L_verify(j->name, pk, j->npk, m, mlen, sig_os, nso));
            record(I4, L_verify(j->name, pk, j->npk, m, mlen, sig_osi, nsoi));
            mp[0] = 0x00; mp[1] = 0x00; memcpy(mp + 2, m, mlen);
            record(I5, L_verify(j->name, pk, j->npk, mp, mlen + 2, sig_os, nso));
        }
        printf("== %s  (%s; messages: empty, \"abc\", 200 bytes)\n", j->name, L_name());
        printf("   value returned by the library's verification: own signature = %d, signature with one byte changed = %d\n", raw_good, raw_bad);
        for (t = 0; t < NTESTS; t++) printf("   %s %-78s %d/%d\n", COUNTS[t].key, COUNTS[t].text, COUNTS[t].ok, COUNTS[t].total);
        for (t = C1; t <= C2; t++) if (COUNTS[t].ok != COUNTS[t].total || COUNTS[t].total == 0) controls_bad++;
        fflush(stdout);
    }
    if (sets == 0) { printf("no parameter set supported\n"); return 2; }
    if (controls_bad) { printf("CONTROLS FAILED: %d (the interoperability result is not valid)\n", controls_bad); return 2; }
    printf("controls correct in %d parameter set(s)\n", sets);
    return 0;
}
