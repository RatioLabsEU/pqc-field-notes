/* leancrypto (1.9.1) adapter for mldsa_harness.h.  Documented public interface only (lc_dilithium.h).
 *
 * Return convention (lc_dilithium.h): lc_dilithium_verify*, "0 if signature could be verified correctly and
 * -EBADMSG when signature cannot be verified, < 0 on other errors". The *_load functions return 0 or < 0.
 *
 * The key and the signature are imported with lc_dilithium_pk_load / lc_dilithium_sig_load, which pick the parameter
 * set from the length; if the chosen set is not the one of the file, it counts as a rejection (and is reported at the
 * end).
 *
 * Environment variable MODE:
 *   ctx     (default) lc_dilithium_verify_ctx with a new context and lc_dilithium_ctx_userctx(ctx, nctx), also when the
 *           context is empty;
 *   simple  with an empty context uses lc_dilithium_verify (no context); with a context, same as "ctx";
 *   stream  lc_dilithium_verify_init / _update / _final, with the user context set before init.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <leancrypto/lc_dilithium.h>
#include <leancrypto/lc_init.h>
#include "mldsa_harness.h"

static long other_set = 0;
static void at_exit(void)
{
    if (other_set) printf("    (leancrypto: %ld keys or signatures imported as another parameter set; counted as rejections)\n", other_set);
}
static enum lc_dilithium_type kind(int p) { return p == 44 ? LC_DILITHIUM_44 : p == 65 ? LC_DILITHIUM_65 : LC_DILITHIUM_87; }
static const char* mode(void) { return getenv("MODE") ? getenv("MODE") : "ctx"; }

const char* lib_name(void)
{
    static char n[80];
    snprintf(n, sizeof(n), "%s [%s]", getenv("LC_NAME") ? getenv("LC_NAME") : "leancrypto", mode());
    return n;
}
void lib_init(int argc, char** argv)
{
    (void)argc; (void)argv;
    if (lc_init(0) != 0) { printf("lc_init failed\n"); exit(2); }
    atexit(at_exit);
}

static struct lc_dilithium_pk PK;
static struct lc_dilithium_sig SIG;

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig)
{
    struct lc_dilithium_ctx* c = NULL;
    int r;
    if (lc_dilithium_pk_load(&PK, pk, npk) != 0) return 0;
    if (lc_dilithium_pk_type(&PK) != kind(p)) { other_set++; return 0; }
    if (lc_dilithium_sig_load(&SIG, sig, nsig) != 0) return 0;
    if (lc_dilithium_sig_type(&SIG) != kind(p)) { other_set++; return 0; }
    if (strcmp(mode(), "simple") == 0 && nctx == 0)
        return lc_dilithium_verify(&SIG, msg, nmsg, &PK) == 0;
    /* A new context for every vector, so that the expanded matrix of another key is not carried over
     * (lc_dilithium.h, \warning). */
    if (lc_dilithium_ctx_alloc(&c) != 0) return 0;
    lc_dilithium_ctx_userctx(c, ctx, nctx);
    if (strcmp(mode(), "stream") == 0) {
        r = lc_dilithium_verify_init(c, &PK);
        if (r == 0) r = lc_dilithium_verify_update(c, msg, nmsg);
        if (r == 0) r = lc_dilithium_verify_final(&SIG, c, &PK);
    } else {
        r = lc_dilithium_verify_ctx(&SIG, c, msg, nmsg, &PK);
    }
    lc_dilithium_ctx_zero_free(c);
    return r == 0;
}
