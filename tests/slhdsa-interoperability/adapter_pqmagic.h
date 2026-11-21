/* Adapter of PQMagic (pqcrypto-cn/PQMagic), SLH-DSA, for interop_slhdsa.c and acvp_lib.c. Public interface:
 * include/pqmagic_api.h ("SLH-DSA API ... ALL USE SIMPLE THASH ACCORDING TO FIPS 205"):
 *   - pqmagic_slh_dsa_<hash>_<level><v>_simple_std_sign_keypair(pk, sk): with its own randomness (randombytes).
 *   - ..._sign_signature(sig, &siglen, m, mlen, sk): signs with its own randomness (randombytes(optrand), sign.c:126).
 *     No context.
 *   - ..._sign_verify(sig, siglen, m, mlen, pk). Note the convention: the comment in pqmagic_api.h says "return 0/1 if
 *     verification failed/success, or return error code (neg number)", but the function is crypto_sign_verify of
 *     sig/slh_dsa/std/sign.c (SPX_NAMESPACE macro of config.h), which returns 0 if the signature is valid and -1 if not
 *     (sign.c:180-240). 0 is taken as valid, and this is checked by the controls (own signature and altered
 *     signature), which print the returned value.
 *   - Key generation from a seed: ..._sign_seed_keypair(pk, sk, seed) is exported (PQMAGIC_EXPORT, sign.c:54) and
 *     declared in sig/slh_dsa/std/api.h, but NOT in include/pqmagic_api.h. It is used for the ACVP keyGen vectors, and
 *     the documentation of the test says so.
 * Parameter sets: the 12 of FIPS 205 (SHA2 and SHAKE). The SM3 ones (128f/128s) are not part of FIPS 205: left out.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef ADAPTER_PQMAGIC_H
#define ADAPTER_PQMAGIC_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "pqmagic_api.h"

typedef int (*pqm_kp_t)(unsigned char*, unsigned char*);
typedef int (*pqm_sign_t)(unsigned char*, size_t*, const unsigned char*, size_t, const unsigned char*);
typedef int (*pqm_verify_t)(const unsigned char*, size_t, const unsigned char*, size_t, const unsigned char*);
typedef int (*pqm_seed_t)(unsigned char*, unsigned char*, const unsigned char*);

/* Prototypes of the key generation from a seed (not in pqmagic_api.h). */
#define PQM_DECL(HM, L) int pqmagic_slh_dsa_##HM##_##L##_simple_std_sign_seed_keypair(unsigned char*, unsigned char*, const unsigned char*);
PQM_DECL(sha2, 128f) PQM_DECL(sha2, 128s) PQM_DECL(sha2, 192f) PQM_DECL(sha2, 192s) PQM_DECL(sha2, 256f) PQM_DECL(sha2, 256s)
PQM_DECL(shake, 128f) PQM_DECL(shake, 128s) PQM_DECL(shake, 192f) PQM_DECL(shake, 192s) PQM_DECL(shake, 256f) PQM_DECL(shake, 256s)

typedef struct {
    const char* name;
    pqm_kp_t kp;
    pqm_sign_t sign;
    pqm_verify_t verify;
    pqm_seed_t seed;
} pqm_t;

#define PQM(H, HM, L)                                                                                                  \
    { "SLH-DSA-" H "-" #L, pqmagic_slh_dsa_##HM##_##L##_simple_std_sign_keypair,                                       \
      pqmagic_slh_dsa_##HM##_##L##_simple_std_sign_signature, pqmagic_slh_dsa_##HM##_##L##_simple_std_sign_verify,       \
      pqmagic_slh_dsa_##HM##_##L##_simple_std_sign_seed_keypair }

static const pqm_t PQM_TABLE[12] = {
    PQM("SHA2", sha2, 128f),   PQM("SHA2", sha2, 128s),   PQM("SHA2", sha2, 192f),   PQM("SHA2", sha2, 192s),
    PQM("SHA2", sha2, 256f),   PQM("SHA2", sha2, 256s),   PQM("SHAKE", shake, 128f), PQM("SHAKE", shake, 128s),
    PQM("SHAKE", shake, 192f), PQM("SHAKE", shake, 192s), PQM("SHAKE", shake, 256f), PQM("SHAKE", shake, 256s),
};

static const pqm_t* pqm_find(const char* pset)
{
    int i;
    for (i = 0; i < 12; i++)
        if (strcmp(PQM_TABLE[i].name, pset) == 0) return &PQM_TABLE[i];
    return NULL;
}

static const char* L_name(void) { return "PQMagic"; }
static int L_supports(const char* pset) { return pqm_find(pset) != NULL; }

static int L_keygen_seed(const char* pset, const uint8_t* seed, size_t nseed, uint8_t* pk, uint8_t* sk)
{
    const pqm_t* p = pqm_find(pset);
    (void)nseed;
    return p != NULL && p->seed(pk, sk, seed) == 0;
}

/* New key through the public interface (the library's own randomness; "rnd" is not used). */
static int L_keygen(const char* pset, const uint8_t rnd[128], uint8_t* pk, uint8_t* sk)
{
    const pqm_t* p = pqm_find(pset);
    (void)rnd;
    return p != NULL && p->kp(pk, sk) == 0;
}

static int L_sign(const char* pset, const uint8_t* sk, size_t nsk, const uint8_t* m, size_t mlen, uint8_t* sig, size_t* nsig)
{
    const pqm_t* p = pqm_find(pset);
    (void)nsk;
    return p != NULL && p->sign(sig, nsig, m, mlen, sk) == 0;
}

static int L_verify_raw(const char* pset, const uint8_t* pk, size_t npk, const uint8_t* m, size_t mlen, const uint8_t* sig, size_t nsig)
{
    const pqm_t* p = pqm_find(pset);
    (void)npk;
    return p == NULL ? -99 : p->verify(sig, nsig, m, mlen, pk);
}
static int L_verify(const char* pset, const uint8_t* pk, size_t npk, const uint8_t* m, size_t mlen, const uint8_t* sig, size_t nsig)
{
    return L_verify_raw(pset, pk, npk, m, mlen, sig, nsig) == 0;
}
static const char* L_keygen_txt(void)
{
    return "..._sign_seed_keypair (exported and in sig/slh_dsa/std/api.h, not in include/pqmagic_api.h)";
}
#endif
