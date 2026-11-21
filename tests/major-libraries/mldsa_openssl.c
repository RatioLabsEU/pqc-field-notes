/* OpenSSL adapter for mldsa_harness.h (EVP interface, with a context string).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include "mldsa_harness.h"

const char* lib_name(void) { return "OpenSSL"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; }

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig)
{
    const char* alg = p == 44 ? "ML-DSA-44" : p == 65 ? "ML-DSA-65" : "ML-DSA-87";
    EVP_PKEY* key = EVP_PKEY_new_raw_public_key_ex(NULL, alg, NULL, pk, npk);
    EVP_MD_CTX* m;
    OSSL_PARAM par[2];
    int ok;

    if (key == NULL) return 0;
    m = EVP_MD_CTX_new();
    par[0] = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)ctx, nctx);
    par[1] = OSSL_PARAM_construct_end();
    ok = EVP_DigestVerifyInit_ex(m, NULL, NULL, NULL, NULL, key, par) == 1 &&
         EVP_DigestVerify(m, sig, nsig, msg, nmsg) == 1;
    EVP_MD_CTX_free(m);
    EVP_PKEY_free(key);
    return ok;
}
