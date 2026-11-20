// BoringSSL adapter for mlkem_harness.h. BoringSSL does not implement ML-KEM-512, and its public interface exposes
// neither encapsulation with fixed randomness nor import of expanded decapsulation keys.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
#include <openssl/bytestring.h>
#include <openssl/mlkem.h>
extern "C" {
#include "mlkem_harness.h"
}

const char* lib_name(void) { return "BoringSSL"; }
void lib_init(int, char**) {}

#define SEED(N)                                                                     \
  {                                                                                 \
    static MLKEM##N##_private_key priv;                                             \
    if (!MLKEM##N##_private_key_from_seed(&priv, seed, 64)) return 0;               \
    *nek = 0;                                                                       \
    return MLKEM##N##_decap(K, c, nc, &priv) == 1;                                  \
  }
#define ENCAPS(N)                                                                   \
  {                                                                                 \
    static MLKEM##N##_public_key pub;                                               \
    CBS cbs;                                                                        \
    CBS_init(&cbs, ek, nek);                                                        \
    if (!MLKEM##N##_parse_public_key(&pub, &cbs) || CBS_len(&cbs) != 0) return 0;   \
    MLKEM##N##_encap(c, K, &pub);                                                   \
    *nc = 0;                                                                        \
    return 1;                                                                       \
  }

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K) {
  (void)ek;
  if (p == 512) return -1;
  if (p == 768) SEED(768)
  SEED(1024)
}
int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K) {
  (void)m;
  if (p == 512) return -1;
  if (p == 768) ENCAPS(768)
  ENCAPS(1024)
}
int lib_decaps_dk(int, const uint8_t*, size_t, const uint8_t*, size_t, uint8_t*) { return -1; }
