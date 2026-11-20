/* Adapter for the Linux kernel ML-DSA (lib/crypto/mldsa.c, built in user space with the linux_compat/ layer) for
 * mldsa_harness.h.
 *
 * Interface (include/crypto/mldsa.h): int mldsa_verify(alg, sig, sig_len, msg, msg_len, pk, pk_len).
 * Return convention: 0 if the signature is valid; -EBADMSG if the signature or the key is malformed (including a length
 * other than that of the parameter set), -EKEYREJECTED if the signature does not verify, -EINVAL/-ENOMEM otherwise.
 * It only does pure ML-DSA with an empty context: vectors with a non-empty context have no interface (we return -1).
 * With the environment variable DEBUG_REJECT it writes the code of every rejection to stderr.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <crypto/mldsa.h>
#include "mldsa_harness.h"

const char* lib_name(void) { return getenv("LX_NAME") ? getenv("LX_NAME") : "linux mldsa"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; }

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig)
{
    enum mldsa_alg a = p == 44 ? MLDSA44 : p == 65 ? MLDSA65 : MLDSA87;
    int r;
    (void)ctx;
    if (nctx != 0) return -1;
    r = mldsa_verify(a, sig, nsig, msg, nmsg, pk, npk);
    if (r != 0 && getenv("DEBUG_REJECT")) fprintf(stderr, "rejected %d\n", r);
    return r == 0;
}
