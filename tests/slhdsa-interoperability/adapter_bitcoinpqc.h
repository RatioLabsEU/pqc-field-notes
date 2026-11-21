/* Adapter of libbitcoinpqc (cryptoquick/libbitcoinpqc) for interop_slhdsa.c and acvp_lib.c. Documented public
 * interface only (include/libbitcoinpqc/bitcoinpqc.h):
 *   - bitcoin_pqc_keygen(alg, &kp, random_data, n): n >= 128. According to src/slh_dsa/keygen.c and the README ("three
 *     explicit n-byte values (SK.seed ‖ SK.prf ‖ PK.seed)"), the first 3n bytes are the FIPS 205 seed; the rest is
 *     ignored. Returns BITCOIN_PQC_OK (0) on success.
 *   - bitcoin_pqc_sign(alg, sk, nsk, m, mlen, &sig): deterministic signature (opt_rand comes from SHA-256(sk‖m‖0)).
 *     There is no context and no other interface. Returns BITCOIN_PQC_OK (0) on success.
 *   - bitcoin_pqc_verify(alg, pk, npk, m, mlen, sig, nsig): BITCOIN_PQC_OK (0) if the signature is valid; a negative
 *     code if not (header: "@return BITCOIN_PQC_OK if signature is valid, error code otherwise").
 * With -DBTX it is built against the copy that btx carries (src/libbitcoinpqc), with that version's SHAKE-128s
 * algorithm. (run.sh uses adapter_btx.h for btx instead.)
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef ADAPTER_BITCOINPQC_H
#define ADAPTER_BITCOINPQC_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/bitcoinpqc.h"

#ifdef BTX
#define BPQC_ALG BITCOIN_PQC_SLH_DSA_SHAKE_128S
#define BPQC_SET "SLH-DSA-SHAKE-128s"
#define BPQC_NAME "btx (copy of libbitcoinpqc in src/libbitcoinpqc)"
#else
#define BPQC_ALG BITCOIN_PQC_SLH_DSA_SHA2_128S
#define BPQC_SET "SLH-DSA-SHA2-128s"
#define BPQC_NAME "libbitcoinpqc"
#endif

#ifndef BPQC_LABEL
#define BPQC_LABEL ""
#endif

static const char* L_name(void) { return BPQC_NAME BPQC_LABEL; }

/* Only the parameter set that the library documents. */
static int L_supports(const char* pset) { return strcmp(pset, BPQC_SET) == 0; }

/* Key generation from a seed (3n bytes: SK.seed ‖ SK.prf ‖ PK.seed) through the public interface: 128 bytes are
 * passed, the seed followed by zeros. 1 = generated, 0 = the library returned an error. */
static int L_keygen_seed(const char* pset, const uint8_t* seed, size_t nseed, uint8_t* pk, uint8_t* sk)
{
    uint8_t rnd[128] = {0};
    bitcoin_pqc_keypair_t kp;
    int ok;
    (void)pset;
    if (nseed > sizeof(rnd)) return 0;
    memcpy(rnd, seed, nseed);
    memset(&kp, 0, sizeof(kp));
    if (bitcoin_pqc_keygen(BPQC_ALG, &kp, rnd, sizeof(rnd)) != BITCOIN_PQC_OK) return 0;
    ok = kp.public_key_size == bitcoin_pqc_public_key_size(BPQC_ALG) && kp.secret_key_size == bitcoin_pqc_secret_key_size(BPQC_ALG);
    if (ok) { memcpy(pk, kp.public_key, kp.public_key_size); memcpy(sk, kp.secret_key, kp.secret_key_size); }
    bitcoin_pqc_keypair_free(&kp);
    return ok;
}

/* New key: 128 bytes of randomness from the caller (here, passed in "rnd"). */
static int L_keygen(const char* pset, const uint8_t rnd[128], uint8_t* pk, uint8_t* sk)
{
    return L_keygen_seed(pset, rnd, 128, pk, sk);
}

/* 1 = signed, 0 = error. */
static int L_sign(const char* pset, const uint8_t* sk, size_t nsk, const uint8_t* m, size_t mlen, uint8_t* sig, size_t* nsig)
{
    bitcoin_pqc_signature_t s;
    static const uint8_t empty[1] = {0};
    (void)pset;
    memset(&s, 0, sizeof(s));
    if (bitcoin_pqc_sign(BPQC_ALG, sk, nsk, mlen ? m : empty, mlen, &s) != BITCOIN_PQC_OK) return 0;
    memcpy(sig, s.signature, s.signature_size);
    *nsig = s.signature_size;
    bitcoin_pqc_signature_free(&s);
    return 1;
}

/* The return value as is (to document the convention), and 1 = accepts / 0 = rejects. */
static int L_verify_raw(const char* pset, const uint8_t* pk, size_t npk, const uint8_t* m, size_t mlen, const uint8_t* sig, size_t nsig)
{
    static const uint8_t empty[1] = {0};
    (void)pset;
    return (int)bitcoin_pqc_verify(BPQC_ALG, pk, npk, mlen ? m : empty, mlen, sig, nsig);
}
static int L_verify(const char* pset, const uint8_t* pk, size_t npk, const uint8_t* m, size_t mlen, const uint8_t* sig, size_t nsig)
{
    return L_verify_raw(pset, pk, npk, m, mlen, sig, nsig) == BITCOIN_PQC_OK;
}
static const char* L_keygen_txt(void) { return "bitcoin_pqc_keygen (public interface, 128 bytes = seed ‖ zeros)"; }
#endif
