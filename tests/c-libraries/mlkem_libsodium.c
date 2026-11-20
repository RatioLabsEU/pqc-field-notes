/* libsodium (1.0.22) adapter for mlkem_harness.h.  Only ML-KEM-768 exists (crypto_kem_mlkem768_*).
 *
 * Return convention (crypto_kem_mlkem768.h and ref/kem_mlkem768_ref.c): every function returns 0 on success and -1
 * on failure. sodium_init() must be called first (it returns 0, or 1 if already initialised; -1 is an error).
 *
 * The interface takes fixed-length arrays (there is no length parameter): a key or a ciphertext of the wrong length
 * cannot be passed to it. Those vectors are counted as "no interface" (we return -1) and, at the end, the program
 * says how many there were, so that they do not silently drop out of the count.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <sodium.h>
#include "mlkem_harness.h"

static long wrong_length = 0;   /* vectors with a length the interface cannot express */
static void at_exit(void)
{
    if (wrong_length > 0)
        printf("    (libsodium: %ld vectors with a length other than the fixed one; the interface takes no other length: "
               "no interface)\n", wrong_length);
}

const char* lib_name(void) { return "libsodium " SODIUM_VERSION_STRING; }
void lib_init(int argc, char** argv)
{
    (void)argc; (void)argv;
    if (sodium_init() < 0) { printf("sodium_init failed\n"); exit(2); }
    atexit(at_exit);
}

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    static uint8_t sk[crypto_kem_mlkem768_SECRETKEYBYTES];
    if (p != 768) return -1;
    /* The 64-byte seed is d||z, in the same order as FIPS 203 (ref: memcpy(indseed, seed, 32) and z = seed+32). */
    if (crypto_kem_mlkem768_seed_keypair(ek, sk, seed) != 0) return 0;
    *nek = crypto_kem_mlkem768_PUBLICKEYBYTES;
    if (nc != crypto_kem_mlkem768_CIPHERTEXTBYTES) { wrong_length++; return -1; }
    return crypto_kem_mlkem768_dec(K, c, sk) == 0;
}

int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    if (p != 768) return -1;
    if (nek != crypto_kem_mlkem768_PUBLICKEYBYTES) { wrong_length++; return -1; }
    *nc = crypto_kem_mlkem768_CIPHERTEXTBYTES;
    /* Public deterministic variant: the randomness m is the 32-byte "seed". */
    return crypto_kem_mlkem768_enc_deterministic(c, K, ek, m) == 0;
}

int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    if (p != 768) return -1;
    if (ndk != crypto_kem_mlkem768_SECRETKEYBYTES || nc != crypto_kem_mlkem768_CIPHERTEXTBYTES) { wrong_length++; return -1; }
    return crypto_kem_mlkem768_dec(K, c, dk) == 0;
}
