// Botan adapter for mldsa_harness.h. The context string is passed with PK_Signature_Options::with_context
// (pk_options.h). Any exception (malformed key, context too long) counts as a rejection.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
#include <botan/ml_dsa.h>
#include <botan/pk_options.h>
#include <botan/pubkey.h>
#include <span>
#include <vector>
extern "C" {
#include "mldsa_harness.h"
}

const char* lib_name(void) { return "Botan"; }
void lib_init(int, char**) {}

int lib_verify(int p, const uint8_t* pk, size_t npk, const uint8_t* msg, size_t nmsg, const uint8_t* ctx,
               size_t nctx, const uint8_t* sig, size_t nsig) {
   try {
      const auto mode = p == 44 ? Botan::ML_DSA_Mode::ML_DSA_4x4
                      : p == 65 ? Botan::ML_DSA_Mode::ML_DSA_6x5 : Botan::ML_DSA_Mode::ML_DSA_8x7;
      Botan::ML_DSA_PublicKey pub(std::span<const uint8_t>(pk, npk), mode);
      Botan::PK_Signature_Options options;
      if(nctx != 0) {
         options = options.with_context(std::span<const uint8_t>(ctx, nctx));
      }
      Botan::PK_Verifier ver(pub, options);
      return ver.verify_message(std::span<const uint8_t>(msg, nmsg), std::span<const uint8_t>(sig, nsig)) ? 1 : 0;
   } catch(const std::exception&) {
      return 0;
   }
}
