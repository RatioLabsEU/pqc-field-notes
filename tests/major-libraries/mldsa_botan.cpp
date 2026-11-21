// Botan adapter for mldsa_harness.h. Botan's ML-DSA verifier takes no context string: vectors with a non-empty
// context are returned as -1 and the harness reports them as "not applicable".
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
#include <botan/ml_dsa.h>
#include <botan/pubkey.h>
#include <span>
#include <vector>
extern "C" {
#include "mldsa_harness.h"
}

const char* lib_name(void) { return "Botan (empty context only)"; }
void lib_init(int, char**) {}

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig) {
   (void)ctx;
   if(nctx != 0) {
      return -1;  // no interface for a context string
   }
   try {
      const auto mode = p == 44 ? Botan::ML_DSA_Mode::ML_DSA_4x4
                      : p == 65 ? Botan::ML_DSA_Mode::ML_DSA_6x5 : Botan::ML_DSA_Mode::ML_DSA_8x7;
      Botan::ML_DSA_PublicKey pub(std::span<const uint8_t>(pk, npk), mode);
      Botan::PK_Verifier ver(pub, "");
      return ver.verify_message(std::span<const uint8_t>(msg, nmsg), std::span<const uint8_t>(sig, nsig)) ? 1 : 0;
   } catch(const std::exception&) {
      return 0;
   }
}
