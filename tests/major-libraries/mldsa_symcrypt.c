/* SymCrypt adapter for mldsa_harness.h (static libraries, non-FIPS build, POSIX user-mode environment).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <sys/random.h>
#include "symcrypt.h"
#include "mldsa_harness.h"

SYMCRYPT_ENVIRONMENT_POSIX_USERMODE

PVOID SYMCRYPT_CALL SymCryptCallbackAlloc(SIZE_T n)
{
    void* p = NULL;
    return posix_memalign(&p, SYMCRYPT_ASYM_ALIGN_VALUE, n) == 0 ? p : NULL;
}
VOID SYMCRYPT_CALL SymCryptCallbackFree(PVOID p) { free(p); }
SYMCRYPT_ERROR SYMCRYPT_CALL SymCryptCallbackRandom(PBYTE b, SIZE_T n)
{
    return getrandom(b, n, 0) == (ssize_t)n ? SYMCRYPT_NO_ERROR : SYMCRYPT_EXTERNAL_FAILURE;
}
PVOID SYMCRYPT_CALL SymCryptCallbackAllocateMutexFastInproc(void) { return malloc(1); }
VOID SYMCRYPT_CALL SymCryptCallbackFreeMutexFastInproc(PVOID p) { free(p); }
VOID SYMCRYPT_CALL SymCryptCallbackAcquireMutexFastInproc(PVOID p) { (void)p; }
VOID SYMCRYPT_CALL SymCryptCallbackReleaseMutexFastInproc(PVOID p) { (void)p; }

const char* lib_name(void) { return "SymCrypt"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; SymCryptInit(); }

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig)
{
    SYMCRYPT_MLDSA_PARAMS par = p == 44 ? SYMCRYPT_MLDSA_PARAMS_MLDSA44
                              : p == 65 ? SYMCRYPT_MLDSA_PARAMS_MLDSA65 : SYMCRYPT_MLDSA_PARAMS_MLDSA87;
    PSYMCRYPT_MLDSAKEY k;
    int ok;

    if (nctx > 255) return 0; /* FIPS 204 allows at most 255 bytes of context */
    k = SymCryptMlDsakeyAllocate(par);
    if (k == NULL) return 0;
    ok = SymCryptMlDsakeySetValue(pk, npk, SYMCRYPT_MLDSAKEY_FORMAT_PUBLIC_KEY, 0, k) == SYMCRYPT_NO_ERROR &&
         SymCryptMlDsaVerify(k, msg, nmsg, ctx, nctx, sig, nsig, 0) == SYMCRYPT_NO_ERROR;
    SymCryptMlDsakeyFree(k);
    return ok;
}
