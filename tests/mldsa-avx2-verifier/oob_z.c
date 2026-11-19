/* ML-DSA signatures whose z vector violates the norm bound, checked against a verifier.
 *
 * The signer is PQClean's `clean` ML-DSA signer, built from a patched copy (see run.sh) so that it ONLY
 * emits signatures with  gamma1 - beta <= ||z||_inf < gamma1.  A correct signer never produces such a
 * signature, and FIPS 204 (Algorithm 8, line 13) requires verifiers to reject it.
 *
 * Build modes:
 *   -DC=<PQClean clean namespace> -DA=<PQClean avx2 namespace>          verify with PQClean avx2
 *   -DC=<PQClean clean namespace> -DWITH_LIBOQS -DALG="\"ML-DSA-65\""   verify with liboqs
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define CAT2(a, b) a##b
#define CAT(a, b) CAT2(a, b)
#define STR2(x) #x
#define STR(x) STR2(x)

int CAT(C, _crypto_sign_keypair)(uint8_t* pk, uint8_t* sk);
int CAT(C, _crypto_sign_signature)(uint8_t* sig, size_t* siglen, const uint8_t* m, size_t mlen, const uint8_t* sk);
int CAT(C, _crypto_sign_verify)(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);

#ifdef WITH_LIBOQS
#include <oqs/oqs.h>
static OQS_SIG* S;
static int target_verify(const uint8_t* sig, size_t n, const uint8_t* m, size_t mlen, const uint8_t* pk)
{
    return OQS_SIG_verify(S, m, mlen, sig, n, pk) == OQS_SUCCESS;
}
#else
int CAT(A, _crypto_sign_verify)(const uint8_t* sig, size_t siglen, const uint8_t* m, size_t mlen, const uint8_t* pk);
static int target_verify(const uint8_t* sig, size_t n, const uint8_t* m, size_t mlen, const uint8_t* pk)
{
    return CAT(A, _crypto_sign_verify)(sig, n, m, mlen, pk) == 0;
}
#endif

int main(void)
{
    static uint8_t pk[4096], sk[8192], sig[8192];
    uint8_t msg[32] = "out-of-bound z test";
    size_t n = 0;
    int i, total = 20, ref_accepts = 0, target_accepts = 0;

#ifdef WITH_LIBOQS
    OQS_init();
    S = OQS_SIG_new(ALG);
    if (S == NULL) return 2;
#endif
    if (CAT(C, _crypto_sign_keypair)(pk, sk) != 0) return 2;
    for (i = 0; i < total; i++) {
        msg[31] = (uint8_t)i;
        if (CAT(C, _crypto_sign_signature)(sig, &n, msg, sizeof(msg), sk) != 0) return 2;
        ref_accepts += CAT(C, _crypto_sign_verify)(sig, n, msg, sizeof(msg), pk) == 0;
        target_accepts += target_verify(sig, n, msg, sizeof(msg), pk);
    }
#ifdef WITH_LIBOQS
    printf("liboqs %-7s %-10s", OQS_version(), ALG);
#else
    printf("%-25s", STR(A));
#endif
    printf(" out-of-bound signatures: %d   accepted by reference verifier: %d   ACCEPTED BY TARGET: %d\n",
           total, ref_accepts, target_accepts);
    return target_accepts > 0;
}
