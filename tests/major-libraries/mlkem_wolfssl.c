/* wolfSSL adapter for mlkem_harness.h (MlKemKey interface). Key generation and encapsulation take the randomness
 * from the caller, so the encapsulation key, the ciphertext and the shared secret are all compared.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mlkem.h>
#include "mlkem_harness.h"

static int type(int p) { return p == 512 ? WC_ML_KEM_512 : p == 768 ? WC_ML_KEM_768 : WC_ML_KEM_1024; }
const char* lib_name(void) { return "wolfSSL"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; }

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    MlKemKey k;
    word32 n = 0;
    int ret = wc_MlKemKey_Init(&k, type(p), NULL, INVALID_DEVID);
    if (ret != 0) return 0;
    ret = wc_MlKemKey_MakeKeyWithRandom(&k, seed, 64);
    if (ret == 0) ret = wc_MlKemKey_PublicKeySize(&k, &n);
    if (ret == 0) ret = wc_MlKemKey_EncodePublicKey(&k, ek, n);
    if (ret == 0) { *nek = n; ret = wc_MlKemKey_Decapsulate(&k, K, c, (word32)nc); }
    wc_MlKemKey_Free(&k);
    return ret == 0;
}
int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    MlKemKey k;
    word32 n = 0;
    int ret = wc_MlKemKey_Init(&k, type(p), NULL, INVALID_DEVID);
    if (ret != 0) return 0;
    ret = wc_MlKemKey_DecodePublicKey(&k, ek, (word32)nek);
    if (ret == 0) ret = wc_MlKemKey_EncapsulateWithRandom(&k, c, K, m, 32);
    if (ret == 0) ret = wc_MlKemKey_CipherTextSize(&k, &n);
    wc_MlKemKey_Free(&k);
    *nc = n;
    return ret == 0;
}
int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    MlKemKey k;
    int ret = wc_MlKemKey_Init(&k, type(p), NULL, INVALID_DEVID);
    if (ret != 0) return 0;
    ret = wc_MlKemKey_DecodePrivateKey(&k, dk, (word32)ndk);
    if (ret == 0) ret = wc_MlKemKey_Decapsulate(&k, K, c, (word32)nc);
    wc_MlKemKey_Free(&k);
    return ret == 0;
}
