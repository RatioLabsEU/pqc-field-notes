/* SymCrypt adapter for mlkem_harness.h (static libraries, non-FIPS build, POSIX user-mode environment).
 * SymCrypt's public encapsulation takes its randomness from the library's generator, so for the encapsulation vectors
 * only acceptance or rejection of the key is checked (*nc = 0), not the ciphertext or the shared secret.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <sys/random.h>
#include "symcrypt.h"
#include "mlkem_harness.h"

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

static SYMCRYPT_MLKEM_PARAMS par(int p)
{
    return p == 512 ? SYMCRYPT_MLKEM_PARAMS_MLKEM512 : p == 768 ? SYMCRYPT_MLKEM_PARAMS_MLKEM768 : SYMCRYPT_MLKEM_PARAMS_MLKEM1024;
}
const char* lib_name(void) { return "SymCrypt"; }
void lib_init(int argc, char** argv) { (void)argc; (void)argv; SymCryptInit(); }

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    PSYMCRYPT_MLKEMKEY k = SymCryptMlKemkeyAllocate(par(p));
    int ok;
    (void)ek;
    *nek = 0;
    if (k == NULL) return 0;
    ok = SymCryptMlKemkeySetValue(seed, 64, SYMCRYPT_MLKEMKEY_FORMAT_PRIVATE_SEED, 0, k) == SYMCRYPT_NO_ERROR &&
         SymCryptMlKemDecapsulate(k, c, nc, K, 32) == SYMCRYPT_NO_ERROR;
    SymCryptMlKemkeyFree(k);
    return ok;
}
int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    PSYMCRYPT_MLKEMKEY k = SymCryptMlKemkeyAllocate(par(p));
    int ok;
    (void)m;
    *nc = 0;
    if (k == NULL) return 0;
    ok = SymCryptMlKemkeySetValue(ek, nek, SYMCRYPT_MLKEMKEY_FORMAT_ENCAPSULATION_KEY, 0, k) == SYMCRYPT_NO_ERROR &&
         SymCryptMlKemEncapsulate(k, K, 32, c, MK_CT(p)) == SYMCRYPT_NO_ERROR;
    SymCryptMlKemkeyFree(k);
    return ok;
}
int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    PSYMCRYPT_MLKEMKEY k = SymCryptMlKemkeyAllocate(par(p));
    int ok;
    if (k == NULL) return 0;
    ok = SymCryptMlKemkeySetValue(dk, ndk, SYMCRYPT_MLKEMKEY_FORMAT_DECAPSULATION_KEY, 0, k) == SYMCRYPT_NO_ERROR &&
         SymCryptMlKemDecapsulate(k, c, nc, K, 32) == SYMCRYPT_NO_ERROR;
    SymCryptMlKemkeyFree(k);
    return ok;
}
