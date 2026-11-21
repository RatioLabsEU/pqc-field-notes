/* ACVP SLH-DSA vectors (keyGen and sigVer) through the public interface of a library that takes no context string
 * (libbitcoinpqc, btx, PQMagic). Uses the shared harness slhdsa_harness.h (which reads the text written by
 * acvp_to_text.py) and an adapter (-include adapter_*.h).
 *
 * Usage:  acvp_<lib> <vectors.txt> kg,sv <mode>
 *   mode "direct":
 *     keyGen                -> L_keygen_seed with SK.seed || SK.prf || PK.seed
 *     internal sigVer       -> the public verification with M' exactly as ACVP gives it (the library adds no prefix,
 *                              so this is the internal interface of FIPS 205, Algorithm 20)
 *     external pure sigVer  -> the public verification with M, only if the context is empty (what the documentation
 *                              calls FIPS 205 without a context: Algorithm 24 with an empty ctx); with a non-empty
 *                              context, "no interface"
 *     preHash               -> no interface
 *   mode "emulated": external pure sigVer only, all of it: the program builds M' = 0x00 || |ctx| || ctx || M (FIPS 205,
 *     Algorithm 24) and calls the public verification with M'. It measures whether the core is the one of FIPS 205 even
 *     though the prefix is missing. The internal vectors and keyGen are "no interface" in this mode, so that they are
 *     not counted twice.
 * sigGen is not run: libbitcoinpqc signs with randomness it derives itself and PQMagic with system randomness; neither
 * lets the caller fix opt_rand, so there is no signature to compare byte by byte.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include "slhdsa_harness.h"

static int emulated_mode = 0;

const char* lib_name(void)
{
    static char n[120];
    snprintf(n, sizeof(n), "%s [%s]", L_name(), emulated_mode ? "emulated" : "direct");
    return n;
}

void lib_init(int argc, char** argv)
{
    emulated_mode = argc > 3 && strcmp(argv[3], "emulated") == 0;
    if (argc > 3 && !emulated_mode && strcmp(argv[3], "direct") != 0) { printf("unknown mode: %s\n", argv[3]); exit(2); }
}

int lib_supports(const param_set_t* p) { return L_supports(p->name); }

int lib_keygen(const param_set_t* p, const vector_t* v, uint8_t* pk, uint8_t* sk)
{
    if (emulated_mode) return NO_INTERFACE;
    if (v->nseed != 3 * (size_t)p->n) return 0;
    return L_keygen_seed(p->name, v->seed, v->nseed, pk, sk);
}

int lib_sign(const param_set_t* p, const vector_t* v, uint8_t* sig, size_t* siglen)
{
    (void)p; (void)v; (void)sig; (void)siglen;
    return NO_INTERFACE;
}

int lib_verify(const param_set_t* p, const vector_t* v, const uint8_t* sig, size_t siglen)
{
    static uint8_t mp[HARNESS_MAXB + 300];
    if (v->npk != p->npk || v->prehash) return NO_INTERFACE;
    if (v->internal) {
        if (emulated_mode) return NO_INTERFACE;
        return L_verify(p->name, v->pk, v->npk, v->msg, v->nmsg, sig, siglen);
    }
    if (!emulated_mode) {
        if (v->nctx != 0) return NO_INTERFACE;
        return L_verify(p->name, v->pk, v->npk, v->msg, v->nmsg, sig, siglen);
    }
    if (v->nctx > 255) return NO_INTERFACE;
    mp[0] = 0x00;
    mp[1] = (uint8_t)v->nctx;
    memcpy(mp + 2, v->ctx, v->nctx);
    memcpy(mp + 2 + v->nctx, v->msg, v->nmsg);
    return L_verify(p->name, v->pk, v->npk, mp, 2 + v->nctx + v->nmsg, sig, siglen);
}
