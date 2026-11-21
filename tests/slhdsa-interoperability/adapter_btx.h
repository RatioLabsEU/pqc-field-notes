/* Adapter of the copy of libbitcoinpqc that btx carries (btxchain/btx, src/libbitcoinpqc), parameter set
 * SLH-DSA-SHAKE-128s, for interop_slhdsa.c and acvp_lib.c.
 *
 * This copy differs from cryptoquick's: its public interface (include/libbitcoinpqc/bitcoinpqc.h) has an argument
 * "slhdsa_fips205" in bitcoin_pqc_sign_with_randomness and bitcoin_pqc_verify. With 0 it uses the FORS index order of
 * SPHINCS+ 3.1 ("Legacy round-3.x SPHINCS+ (little-endian) index derivation", sphincsplus/ref/fors.c); with 1, the one
 * of FIPS 205. The FIPS 205 prefix is added not by the library but by the node: src/pqkey.cpp,
 * Fips205PureContextMessage (M' = 0x00 ‖ 0x00 ‖ M), used when the SCRIPT_VERIFY_SLHDSA_FIPS205 rule is active.
 *
 * Mode (environment variable BTX_MODE):
 *   legacy        flag 0 and M as is (what the node does without the FIPS205 rule)
 *   fips205       flag 1 and M' = 0x00 ‖ 0x00 ‖ M, as the node does with the rule (pqkey.cpp:197-243 and 285-305)
 *   fips205-core  flag 1 and M as is (to run the ACVP vectors of the internal interface)
 * Conventions: BITCOIN_PQC_OK (0) on success / if the signature is valid.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef ADAPTER_BTX_H
#define ADAPTER_BTX_H
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libbitcoinpqc/bitcoinpqc.h"

static int btx_flag = -1, btx_wrap = 0;
static char btx_name[96];

static void btx_mode(void)
{
    const char* m;
    if (btx_flag >= 0) return;
    m = getenv("BTX_MODE");
    if (m == NULL || strcmp(m, "legacy") == 0) { btx_flag = 0; btx_wrap = 0; m = "legacy"; }
    else if (strcmp(m, "fips205") == 0) { btx_flag = 1; btx_wrap = 1; }
    else if (strcmp(m, "fips205-core") == 0) { btx_flag = 1; btx_wrap = 0; }
    else { printf("unknown BTX_MODE: %s\n", m); exit(2); }
    snprintf(btx_name, sizeof(btx_name), "btx libbitcoinpqc (mode %s)", m);
}

static const char* L_name(void) { btx_mode(); return btx_name; }
static int L_supports(const char* pset) { btx_mode(); return strcmp(pset, "SLH-DSA-SHAKE-128s") == 0; }

/* The message passed to the library: M or 0x00 ‖ 0x00 ‖ M depending on the mode. Returns a buffer of its own. */
static const uint8_t* btx_message(const uint8_t* m, size_t mlen, size_t* nout)
{
    static uint8_t b[80000];
    if (mlen + 2 > sizeof(b)) { printf("message too long\n"); exit(2); }
    if (btx_wrap) { b[0] = 0x00; b[1] = 0x00; if (mlen) memcpy(b + 2, m, mlen); *nout = mlen + 2; }
    else { if (mlen) memcpy(b, m, mlen); *nout = mlen; }
    return b;
}

static int L_keygen_seed(const char* pset, const uint8_t* seed, size_t nseed, uint8_t* pk, uint8_t* sk)
{
    uint8_t rnd[128] = {0};
    bitcoin_pqc_keypair_t kp;
    int ok;
    (void)pset;
    if (nseed > sizeof(rnd)) return 0;
    memcpy(rnd, seed, nseed);
    memset(&kp, 0, sizeof(kp));
    if (bitcoin_pqc_keygen(BITCOIN_PQC_SLH_DSA_SHAKE_128S, &kp, rnd, sizeof(rnd)) != BITCOIN_PQC_OK) return 0;
    ok = kp.public_key_size == 32 && kp.secret_key_size == 64;
    if (ok) { memcpy(pk, kp.public_key, 32); memcpy(sk, kp.secret_key, 64); }
    bitcoin_pqc_keypair_free(&kp);
    return ok;
}

static int L_keygen(const char* pset, const uint8_t rnd[128], uint8_t* pk, uint8_t* sk)
{
    return L_keygen_seed(pset, rnd, 128, pk, sk);
}

/* Signs as the node does: bitcoin_pqc_sign_with_randomness with 128 bytes of randomness from the caller. */
static int L_sign(const char* pset, const uint8_t* sk, size_t nsk, const uint8_t* m, size_t mlen, uint8_t* sig, size_t* nsig)
{
    bitcoin_pqc_signature_t s;
    uint8_t rnd[128];
    size_t n;
    const uint8_t* mm;
    FILE* f = fopen("/dev/urandom", "rb");
    (void)pset;
    btx_mode();
    if (f == NULL || fread(rnd, 1, sizeof(rnd), f) != sizeof(rnd)) { if (f) fclose(f); return 0; }
    fclose(f);
    mm = btx_message(m, mlen, &n);
    memset(&s, 0, sizeof(s));
    if (bitcoin_pqc_sign_with_randomness(BITCOIN_PQC_SLH_DSA_SHAKE_128S, sk, nsk, mm, n, rnd, sizeof(rnd), &s, btx_flag) != BITCOIN_PQC_OK) return 0;
    memcpy(sig, s.signature, s.signature_size);
    *nsig = s.signature_size;
    bitcoin_pqc_signature_free(&s);
    return 1;
}

static int L_verify_raw(const char* pset, const uint8_t* pk, size_t npk, const uint8_t* m, size_t mlen, const uint8_t* sig, size_t nsig)
{
    size_t n;
    const uint8_t* mm;
    (void)pset;
    btx_mode();
    mm = btx_message(m, mlen, &n);
    return (int)bitcoin_pqc_verify(BITCOIN_PQC_SLH_DSA_SHAKE_128S, pk, npk, mm, n, sig, nsig, btx_flag);
}
static int L_verify(const char* pset, const uint8_t* pk, size_t npk, const uint8_t* m, size_t mlen, const uint8_t* sig, size_t nsig)
{
    return L_verify_raw(pset, pk, npk, m, mlen, sig, nsig) == BITCOIN_PQC_OK;
}
#endif
