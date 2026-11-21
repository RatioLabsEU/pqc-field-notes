/* OpenSSL adapter (development branch, commit pinned in run.sh) for slhdsa_harness.h.
 *
 * Documented public interface only: EVP_PKEY-SLH-DSA(7) and EVP_SIGNATURE-SLH-DSA(7).
 *   - Key generation: EVP_PKEY_keygen with the "seed" parameter (OSSL_PKEY_PARAM_SLH_DSA_SEED, 3n bytes:
 *     SK.seed || SK.prf || PK.seed), then reading "pub" and "priv".
 *   - Signing: EVP_PKEY_sign_message_init + EVP_PKEY_sign with "context-string", "message-encoding" (1 = pure SLH-DSA,
 *     0 = no encoding, that is, the internal interface), "deterministic" (1) and "test-entropy" (the vector's addrnd).
 *   - Verification: EVP_PKEY_verify_message_init + EVP_PKEY_verify with "context-string" and "message-encoding".
 *   - Pre-hash (HashSLH-DSA): the documentation says "OpenSSL does not support Pre Hash SLH-DSA Signature
 *     Generation"; the preHash vectors count as no interface.
 * Return convention: EVP_PKEY_verify returns 1 if the signature is valid, 0 if not and < 0 on other errors; the other
 * EVP functions return 1 on success. Keys are imported with EVP_PKEY_fromdata ("priv", 4n bytes, to sign; "pub",
 * 2n bytes, to verify).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/params.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>
#include "slhdsa_harness.h"

const char* lib_name(void)
{
    static char n[64];
    snprintf(n, sizeof(n), "OpenSSL %s", OPENSSL_FULL_VERSION_STR);
    return n;
}
void lib_init(int argc, char** argv) { (void)argc; (void)argv; }

int lib_supports(const param_set_t* p)
{
    EVP_SIGNATURE* s = EVP_SIGNATURE_fetch(NULL, p->name, NULL);
    if (s == NULL) { ERR_clear_error(); return 0; }
    EVP_SIGNATURE_free(s);
    return 1;
}

/* Imports a key: private (4n) if is_private != 0, public (2n) if not. NULL if the library rejects it. */
static EVP_PKEY* import_key(const param_set_t* p, const uint8_t* k, size_t nk, int is_private)
{
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(NULL, p->name, NULL);
    EVP_PKEY* key = NULL;
    OSSL_PARAM par[2];
    par[0] = OSSL_PARAM_construct_octet_string(is_private ? OSSL_PKEY_PARAM_PRIV_KEY : OSSL_PKEY_PARAM_PUB_KEY,
                                               (void*)k, nk);
    par[1] = OSSL_PARAM_construct_end();
    if (c == NULL || EVP_PKEY_fromdata_init(c) != 1
        || EVP_PKEY_fromdata(c, &key, is_private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY, par) != 1)
        key = NULL;
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return key;
}

int lib_keygen(const param_set_t* p, const vector_t* v, uint8_t* pk, uint8_t* sk)
{
    EVP_PKEY_CTX* c = EVP_PKEY_CTX_new_from_name(NULL, p->name, NULL);
    EVP_PKEY* key = NULL;
    OSSL_PARAM par[2];
    size_t npk = 0, nsk = 0;
    int ok;
    par[0] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_SLH_DSA_SEED, (void*)v->seed, v->nseed);
    par[1] = OSSL_PARAM_construct_end();
    ok = c != NULL && EVP_PKEY_keygen_init(c) == 1 && EVP_PKEY_CTX_set_params(c, par) == 1 && EVP_PKEY_keygen(c, &key) == 1
         && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PUB_KEY, pk, 256, &npk) == 1
         && EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_PRIV_KEY, sk, 256, &nsk) == 1
         && npk == p->npk && nsk == p->nsk;
    EVP_PKEY_free(key);
    EVP_PKEY_CTX_free(c);
    ERR_clear_error();
    return ok;
}

int lib_sign(const param_set_t* p, const vector_t* v, uint8_t* sig, size_t* siglen)
{
    EVP_PKEY* key;
    EVP_PKEY_CTX* c = NULL;
    EVP_SIGNATURE* s = NULL;
    OSSL_PARAM par[5], *q = par;
    int encode = v->internal ? 0 : 1, det = v->det == 1, ok;
    size_t n = HARNESS_MAXB;

    if (v->prehash) return NO_INTERFACE;
    if ((key = import_key(p, v->sk, v->nsk, 1)) == NULL) return 0;
    if (!v->internal) *q++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)v->ctx, v->nctx);
    *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    if (det) *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    else *q++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_TEST_ENTROPY, (void*)v->addrnd, v->naddrnd);
    *q = OSSL_PARAM_construct_end();
    ok = (c = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) != NULL && (s = EVP_SIGNATURE_fetch(NULL, p->name, NULL)) != NULL
         && EVP_PKEY_sign_message_init(c, s, par) == 1 && EVP_PKEY_sign(c, sig, &n, v->msg, v->nmsg) == 1;
    *siglen = ok ? n : 0;
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(key);
    ERR_clear_error();
    return ok ? SIG_FIXED : 0;
}

int lib_verify(const param_set_t* p, const vector_t* v, const uint8_t* sig, size_t siglen)
{
    EVP_PKEY* key;
    EVP_PKEY_CTX* c = NULL;
    EVP_SIGNATURE* s = NULL;
    OSSL_PARAM par[3], *q = par;
    int encode = v->internal ? 0 : 1, r = 0;

    if (v->prehash) return NO_INTERFACE;
    if ((key = import_key(p, v->pk, v->npk, 0)) == NULL) return 0; /* key rejected on import */
    if (!v->internal) *q++ = OSSL_PARAM_construct_octet_string(OSSL_SIGNATURE_PARAM_CONTEXT_STRING, (void*)v->ctx, v->nctx);
    *q++ = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_MESSAGE_ENCODING, &encode);
    *q = OSSL_PARAM_construct_end();
    if ((c = EVP_PKEY_CTX_new_from_pkey(NULL, key, NULL)) != NULL && (s = EVP_SIGNATURE_fetch(NULL, p->name, NULL)) != NULL
        && EVP_PKEY_verify_message_init(c, s, par) == 1)
        r = EVP_PKEY_verify(c, sig, siglen, v->msg, v->nmsg) == 1;
    EVP_SIGNATURE_free(s);
    EVP_PKEY_CTX_free(c);
    EVP_PKEY_free(key);
    ERR_clear_error();
    return r;
}
