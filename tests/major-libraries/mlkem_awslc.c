/* AWS-LC adapter for mlkem_harness.h. It uses the ml_kem_NNN_* functions of libcrypto (they return 0 on success), which
 * take the keys as fixed-length byte strings.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include "mlkem_harness.h"

#define DECL(N)                                                                                               \
    int ml_kem_##N##_keypair_deterministic(uint8_t* pk, size_t* pkl, uint8_t* sk, size_t* skl, const uint8_t* seed); \
    int ml_kem_##N##_encapsulate_deterministic(uint8_t* c, size_t* cl, uint8_t* K, size_t* Kl, const uint8_t* pk,    \
                                               const uint8_t* seed);                                            \
    int ml_kem_##N##_decapsulate(uint8_t* K, size_t* Kl, const uint8_t* c, const uint8_t* sk);
DECL(512)
DECL(768)
DECL(1024)

const char* lib_name(void) { return "AWS-LC"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; }

#define PICK(p, f, ...) ((p) == 512 ? ml_kem_512_##f(__VA_ARGS__) : (p) == 768 ? ml_kem_768_##f(__VA_ARGS__) : ml_kem_1024_##f(__VA_ARGS__))

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    static uint8_t sk[4096];
    size_t pkl = MK_EK(p), skl = MK_DK(p), kl = 32;
    if (PICK(p, keypair_deterministic, ek, &pkl, sk, &skl, seed) != 0) return 0;
    *nek = pkl;
    if (nc != (size_t)MK_CT(p)) return 0;
    return PICK(p, decapsulate, K, &kl, c, sk) == 0;
}
int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    size_t cl = MK_CT(p), kl = 32;
    if (nek != (size_t)MK_EK(p)) return 0;
    if (PICK(p, encapsulate_deterministic, c, &cl, K, &kl, ek, m) != 0) return 0;
    *nc = cl;
    return 1;
}
int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    size_t kl = 32;
    if (ndk != (size_t)MK_DK(p) || nc != (size_t)MK_CT(p)) return 0;
    return PICK(p, decapsulate, K, &kl, c, dk) == 0;
}
