/* OpenSSL adapter for mlkem_harness.h (EVP interface).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "mlkem_harness.h"

static const char* alg(int p) { return p == 512 ? "ML-KEM-512" : p == 768 ? "ML-KEM-768" : "ML-KEM-1024"; }
const char* lib_name(void) { return "OpenSSL"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; }

static int decaps(EVP_PKEY* k, const uint8_t* c, size_t nc, uint8_t* K)
{
    EVP_PKEY_CTX* x = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    size_t n = 32;
    int ok = x != NULL && EVP_PKEY_decapsulate_init(x, NULL) > 0 && EVP_PKEY_decapsulate(x, K, &n, c, nc) > 0 && n == 32;
    EVP_PKEY_CTX_free(x);
    return ok;
}

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    EVP_PKEY_CTX* g = EVP_PKEY_CTX_new_from_name(NULL, alg(p), NULL);
    EVP_PKEY* k = NULL;
    OSSL_PARAM par[2];
    int ok;
    par[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_ML_KEM_SEED, (void*)seed, 64);
    par[1] = OSSL_PARAM_construct_end();
    ok = g != NULL && EVP_PKEY_fromdata_init(g) > 0 && EVP_PKEY_fromdata(g, &k, EVP_PKEY_KEYPAIR, par) > 0;
    EVP_PKEY_CTX_free(g);
    if (!ok) return 0;
    if (EVP_PKEY_get_octet_string_param(k, OSSL_PKEY_PARAM_PUB_KEY, ek, 2000, nek) <= 0) *nek = 0;
    ok = decaps(k, c, nc, K);
    EVP_PKEY_free(k);
    return ok;
}
int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    EVP_PKEY* k = EVP_PKEY_new_raw_public_key_ex(NULL, alg(p), NULL, ek, nek);
    EVP_PKEY_CTX* x;
    OSSL_PARAM par[2];
    size_t n = 32, ncl = 2000;
    int ok;
    if (k == NULL) return 0;
    x = EVP_PKEY_CTX_new_from_pkey(NULL, k, NULL);
    par[0] = OSSL_PARAM_construct_octet_string(OSSL_KEM_PARAM_IKME, (void*)m, 32);
    par[1] = OSSL_PARAM_construct_end();
    ok = x != NULL && EVP_PKEY_encapsulate_init(x, par) > 0 && EVP_PKEY_encapsulate(x, c, &ncl, K, &n) > 0;
    *nc = ok ? ncl : 0;
    EVP_PKEY_CTX_free(x);
    EVP_PKEY_free(k);
    return ok;
}
int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    EVP_PKEY* k = EVP_PKEY_new_raw_private_key_ex(NULL, alg(p), NULL, dk, ndk);
    int ok;
    if (k == NULL) return 0;
    ok = decaps(k, c, nc, K);
    EVP_PKEY_free(k);
    return ok;
}
