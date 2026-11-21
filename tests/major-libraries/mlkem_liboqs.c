/* liboqs adapter for mlkem_harness.h. liboqs takes keys as fixed-length byte strings.
 * Build with -DNO_DERAND for versions without OQS_KEM_keypair_derand / OQS_KEM_encaps_derand (before 0.15): then only
 * acceptance of encapsulation keys and the expanded decapsulation key are tested.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <oqs/oqs.h>
#include "mlkem_harness.h"

static OQS_KEM* kem(int p)
{
    static OQS_KEM* k[3];
    int i = p == 512 ? 0 : p == 768 ? 1 : 2;
    if (k[i] == NULL) k[i] = OQS_KEM_new(p == 512 ? "ML-KEM-512" : p == 768 ? "ML-KEM-768" : "ML-KEM-1024");
    return k[i];
}
static char name[40];
const char* lib_name(void) { snprintf(name, sizeof(name), "liboqs %s", OQS_version()); return name; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; OQS_init(); }

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    static uint8_t sk[4096];
#ifdef NO_DERAND
    (void)seed; (void)ek; (void)nek; (void)c; (void)nc; (void)K; (void)sk;
    return -1; /* version without key generation from a seed */
#else
    if (OQS_KEM_keypair_derand(kem(p), ek, sk, seed) != OQS_SUCCESS) return 0;
    *nek = kem(p)->length_public_key;
    if (nc != kem(p)->length_ciphertext) return 0;
    return OQS_KEM_decaps(kem(p), K, c, sk) == OQS_SUCCESS;
#endif
}
int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    if (nek != kem(p)->length_public_key) return 0;
#ifdef NO_DERAND
    (void)m;
    *nc = 0;
    return OQS_KEM_encaps(kem(p), c, K, ek) == OQS_SUCCESS;
#else
    if (OQS_KEM_encaps_derand(kem(p), c, K, ek, m) != OQS_SUCCESS) return 0;
    *nc = kem(p)->length_ciphertext;
    return 1;
#endif
}
int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    if (ndk != kem(p)->length_secret_key || nc != kem(p)->length_ciphertext) return 0;
    return OQS_KEM_decaps(kem(p), K, c, dk) == OQS_SUCCESS;
}
