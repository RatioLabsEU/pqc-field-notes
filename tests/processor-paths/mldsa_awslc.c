/* AWS-LC adapter for mldsa_harness.h. It uses the ml_dsa_NN_verify functions of libcrypto, which take the public key
 * as a fixed-length byte string.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include "mldsa_harness.h"

int ml_dsa_44_verify(const uint8_t* pk, const uint8_t* sig, size_t sig_len, const uint8_t* m, size_t mlen,
                     const uint8_t* ctx, size_t ctxlen);
int ml_dsa_65_verify(const uint8_t* pk, const uint8_t* sig, size_t sig_len, const uint8_t* m, size_t mlen,
                     const uint8_t* ctx, size_t ctxlen);
int ml_dsa_87_verify(const uint8_t* pk, const uint8_t* sig, size_t sig_len, const uint8_t* m, size_t mlen,
                     const uint8_t* ctx, size_t ctxlen);

const char* lib_name(void) { return "AWS-LC"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; }

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig)
{
    size_t expected = p == 44 ? 1312 : p == 65 ? 1952 : 2592;
    if (npk != expected) return 0; /* the interface takes no other length */
    if (p == 44) return ml_dsa_44_verify(pk, sig, nsig, msg, nmsg, ctx, nctx) == 1;
    if (p == 65) return ml_dsa_65_verify(pk, sig, nsig, msg, nmsg, ctx, nctx) == 1;
    return ml_dsa_87_verify(pk, sig, nsig, msg, nmsg, ctx, nctx) == 1;
}
