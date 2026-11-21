// BoringSSL adapter for mldsa_harness.h.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
#include <openssl/bytestring.h>
#include <openssl/mldsa.h>
extern "C" {
#include "mldsa_harness.h"
}

const char* lib_name(void) { return "BoringSSL"; }
void lib_init(int, char**) {}

#define CASE(N)                                                                              \
  {                                                                                          \
    static MLDSA##N##_public_key pub;                                                        \
    CBS cbs;                                                                                 \
    CBS_init(&cbs, pk, npk);                                                                 \
    if (!MLDSA##N##_parse_public_key(&pub, &cbs) || CBS_len(&cbs) != 0) return 0;            \
    return MLDSA##N##_verify(&pub, sig, nsig, msg, nmsg, ctx, nctx) == 1;                    \
  }

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig) {
  if (p == 44) CASE(44)
  if (p == 65) CASE(65)
  CASE(87)
}
