/* wolfSSL adapter for mldsa_harness.h (wc_MlDsaKey interface, with a context string).
 *
 * Optional third argument: auto | no-avx512 | no-avx2. wolfSSL picks its x86_64 code path at run time from the CPU
 * feature flags it detects; with no-avx512 the adapter clears the AVX-512 flags before the first operation, and with
 * no-avx2 it also clears the AVX2 flag, so the next path down is used.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/wc_mldsa.h>
#include <wolfssl/wolfcrypt/cpuid.h>
#include "mldsa_harness.h"

static char name[64] = "wolfSSL";
const char* lib_name(void) { return name; }

void lib_init(int argc, char** argv)
{
    const char* mode = argc > 3 ? argv[3] : "auto";
    if (strcmp(mode, "auto") != 0 && strcmp(mode, "no-avx512") != 0 && strcmp(mode, "no-avx2") != 0) {
        printf("unknown mode: %s (auto, no-avx512 or no-avx2)\n", mode);
        exit(2);
    }
    snprintf(name, sizeof(name), "wolfSSL (%s)", mode);
#if defined(WOLFSSL_X86_64_BUILD) || defined(USE_INTEL_SPEEDUP)
    (void)cpuid_get_flags();
    if (strcmp(mode, "no-avx512") == 0 || strcmp(mode, "no-avx2") == 0) {
    #ifdef CPUID_AVX512
        cpuid_clear_flag(CPUID_AVX512);
    #endif
    #ifdef CPUID_AVX512_VBMI
        cpuid_clear_flag(CPUID_AVX512_VBMI);
    #endif
    #ifdef CPUID_AVX512_VBMI2
        cpuid_clear_flag(CPUID_AVX512_VBMI2);
    #endif
    #ifdef CPUID_AVX512_BW
        cpuid_clear_flag(CPUID_AVX512_BW);
    #endif
    #ifdef CPUID_AVX512_VL
        cpuid_clear_flag(CPUID_AVX512_VL);
    #endif
    #ifdef CPUID_AVX512_DQ
        cpuid_clear_flag(CPUID_AVX512_DQ);
    #endif
    #ifdef CPUID_AVX512_IFMA
        cpuid_clear_flag(CPUID_AVX512_IFMA);
    #endif
    }
    if (strcmp(mode, "no-avx2") == 0)
        cpuid_clear_flag(CPUID_AVX2);
    /* check that the flags the library will read are the ones asked for */
    if ((strcmp(mode, "auto") != 0 && IS_INTEL_AVX512(cpuid_get_flags())) ||
        (strcmp(mode, "no-avx2") == 0 && IS_INTEL_AVX2(cpuid_get_flags()))) {
        printf("could not clear the CPU flags for mode %s\n", mode);
        exit(2);
    }
#else
    if (strcmp(mode, "auto") != 0) {
        printf("this wolfSSL build has no x86_64 run-time CPU detection: mode %s not available\n", mode);
        exit(2);
    }
#endif
}

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig)
{
    wc_MlDsaKey key;
    int res = 0, ret;
    int level = p == 44 ? WC_ML_DSA_44 : p == 65 ? WC_ML_DSA_65 : WC_ML_DSA_87;

    if (nctx > 255) return 0; /* the interface takes the context length as a byte */
    if (wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID) != 0) return 0;
    ret = wc_MlDsaKey_SetParams(&key, (byte)level);
    if (ret == 0) ret = wc_MlDsaKey_ImportPubRaw(&key, pk, (word32)npk);
    if (ret == 0) ret = wc_MlDsaKey_VerifyCtx(&key, sig, (word32)nsig, ctx, (byte)nctx, msg, (word32)nmsg, &res);
    wc_MlDsaKey_Free(&key);
    return ret == 0 && res == 1;
}
