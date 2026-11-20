/* Nettle adapter (development branch, ML-KEM-768 and ML-KEM-1024; there is no 512) for mlkem_harness.h.
 *
 * Interface (ml-kem.h and the manual, nettle.texinfo, node "ML-KEM"): ml_kem_<p>_generate_keypair(pub, key, seed,
 * scratch), ml_kem_<p>_encap(pub, secret, ciphertext, random_ctx, random, scratch) and ml_kem_<p>_decap(key, secret,
 * ciphertext, scratch). All three return void: the interface has NO way to reject a key or a ciphertext. So here
 * "accept" means "the function runs and gives a result"; an invalid vector that reaches the function shows up as
 * accepted because there is no error channel.
 * The caller provides the scratch space, of the size given by ml_kem_<p>_*_itch() (in units of uint16_t).
 * Fixed lengths (there is no length parameter): a different length counts as "no interface" (-1).
 * The encapsulation randomness comes in through the "random" function (nettle_random_func): we give it m.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <nettle/ml-kem.h>
#include "mlkem_harness.h"

static long wrong_length = 0, odd_rng = 0;
static void at_exit(void)
{
    if (wrong_length) printf("    (nettle: %ld vectors with a length other than the fixed one: no interface)\n", wrong_length);
    if (odd_rng) printf("    (nettle: %ld encapsulations asked the generator for something other than 32 bytes once)\n", odd_rng);
}
const char* lib_name(void) { return getenv("NT_NAME") ? getenv("NT_NAME") : "nettle"; }
static uint16_t scratch[20000];
void lib_init(int argc, char** argv)
{
    size_t it[6] = { ml_kem_768_generate_keypair_itch(), ml_kem_768_encap_itch(), ml_kem_768_decap_itch(),
                     ml_kem_1024_generate_keypair_itch(), ml_kem_1024_encap_itch(), ml_kem_1024_decap_itch() };
    (void)argc; (void)argv;
    for (int i = 0; i < 6; i++)
        if (it[i] > sizeof(scratch) / sizeof(scratch[0])) { printf("scratch too small (%zu)\n", it[i]); exit(2); }
    atexit(at_exit);
}

struct fixed { const uint8_t* m; size_t n; int uses; };
static void fixed_random(void* ctx, size_t n, uint8_t* dst)
{
    struct fixed* f = ctx;
    f->uses++;
    if (n > f->n) { memset(dst, 0, n); f->n = (size_t)-1; return; }
    memcpy(dst, f->m, n); f->m += n; f->n -= n;
}

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    static uint8_t dk[3168];
    if (p == 512) return -1;
    /* 64-byte seed = d||z (ml-kem-internal.c: z = seed + 32 is copied to the end of dk). */
    if (p == 768) {
        ml_kem_768_generate_keypair(ek, dk, seed, scratch);
        *nek = ML_KEM_768_PUBLIC_KEY_SIZE;
        if (nc != ML_KEM_768_CIPHERTEXT_SIZE) { wrong_length++; return -1; }
        ml_kem_768_decap(dk, K, c, scratch);
    } else {
        ml_kem_1024_generate_keypair(ek, dk, seed, scratch);
        *nek = ML_KEM_1024_PUBLIC_KEY_SIZE;
        if (nc != ML_KEM_1024_CIPHERTEXT_SIZE) { wrong_length++; return -1; }
        ml_kem_1024_decap(dk, K, c, scratch);
    }
    return 1;
}

int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    struct fixed f = { m, 32, 0 };
    if (p == 512) return -1;
    if (p == 768) {
        if (nek != ML_KEM_768_PUBLIC_KEY_SIZE) { wrong_length++; return -1; }
        ml_kem_768_encap(ek, K, c, &f, fixed_random, scratch);
        *nc = ML_KEM_768_CIPHERTEXT_SIZE;
    } else {
        if (nek != ML_KEM_1024_PUBLIC_KEY_SIZE) { wrong_length++; return -1; }
        ml_kem_1024_encap(ek, K, c, &f, fixed_random, scratch);
        *nc = ML_KEM_1024_CIPHERTEXT_SIZE;
    }
    if (f.uses != 1 || f.n != 0) odd_rng++;
    return 1;
}

int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    if (p == 512) return -1;
    if (p == 768) {
        if (ndk != ML_KEM_768_PRIVATE_KEY_SIZE || nc != ML_KEM_768_CIPHERTEXT_SIZE) { wrong_length++; return -1; }
        ml_kem_768_decap(dk, K, c, scratch);
    } else {
        if (ndk != ML_KEM_1024_PRIVATE_KEY_SIZE || nc != ML_KEM_1024_CIPHERTEXT_SIZE) { wrong_length++; return -1; }
        ml_kem_1024_decap(dk, K, c, scratch);
    }
    return 1;
}
