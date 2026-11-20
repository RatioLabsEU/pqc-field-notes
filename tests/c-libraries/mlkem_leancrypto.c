/* leancrypto (1.9.1) adapter for mlkem_harness.h.  Documented public interface only (lc_kyber.h, lc_rng.h).
 *
 * Return convention (lc_kyber.h): every lc_kyber_* function returns 0 on success and < 0 on failure
 * (lc_kyber_dec says "@return 0", but internally it can return -EINVAL if the decapsulation key fails its check).
 *
 * Call order: keys and ciphertext are imported with lc_kyber_{pk,sk,ct}_load, which pick the parameter set from the
 * length; we also check that the chosen set is the one of the file (if the length matched another set, we count it
 * as a rejection and say so at the end).
 *
 * Encapsulation with fixed randomness: the public interface has no "enc_internal", but it does have lc_rng_set_seeded
 * (lc_rng.h: "Set an externally defined RNG as the seeded RNG"), and lc_kyber_enc takes its only random input (m,
 * 32 bytes) from lc_seeded_rng (ml-kem/src/kyber_kem_api_c.c:77 and kyber_kem.c:154). We install our own generator
 * that delivers exactly m and check that it is asked for 32 bytes, once. With the environment variable RANDOM_RNG the
 * normal generator is used and only acceptance or rejection of the key is checked (c and K are not compared).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <errno.h>
#include <leancrypto/lc_init.h>
#include <leancrypto/lc_kyber.h>
#include <leancrypto/lc_rng.h>
#include "mlkem_harness.h"

static long other_set = 0, odd_rng = 0;
static void at_exit(void)
{
    if (other_set) printf("    (leancrypto: %ld inputs imported as another parameter set; counted as rejections)\n", other_set);
    if (odd_rng) printf("    (leancrypto: %ld encapsulations asked the generator for something other than 32 bytes once)\n", odd_rng);
}

static enum lc_kyber_type kind(int p) { return p == 512 ? LC_KYBER_512 : p == 768 ? LC_KYBER_768 : LC_KYBER_1024; }

/* "External" generator that returns the fixed bytes (and fails if asked for more). */
struct fixed { const uint8_t* m; size_t n; int uses; };
static int fixed_generate(void* st, const uint8_t* a, size_t na, uint8_t* out, size_t nout)
{
    struct fixed* f = st;
    (void)a; (void)na;
    f->uses++;
    if (out == NULL) return 0;
    if (nout > f->n) return -EFAULT;
    memcpy(out, f->m, nout); f->m += nout; f->n -= nout;
    return 0;
}
static int fixed_seed(void* st, const uint8_t* s, size_t ns, const uint8_t* p, size_t np)
{ (void)st; (void)s; (void)ns; (void)p; (void)np; return 0; }
static void fixed_zero(void* st) { (void)st; }
static const struct lc_rng FIXED_RNG = { fixed_generate, fixed_seed, fixed_zero, 0 };

const char* lib_name(void) { return getenv("LC_NAME") ? getenv("LC_NAME") : "leancrypto"; }
void lib_init(int argc, char** argv)
{
    (void)argc; (void)argv;
    if (lc_init(0) != 0) { printf("lc_init failed\n"); exit(2); }
    atexit(at_exit);
}

static int copy_ss(struct lc_kyber_ss* ss, uint8_t* K)
{
    uint8_t* q; size_t n;
    if (lc_kyber_ss_ptr(&q, &n, ss) != 0 || n != 32) return 0;
    memcpy(K, q, 32);
    return 1;
}

static struct lc_kyber_pk PK;
static struct lc_kyber_sk SK;
static struct lc_kyber_ct CT;
static struct lc_kyber_ss SS;

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    uint8_t* q; size_t n;
    /* Seed = d||z (lc_kyber.h: "seed = d || z"). */
    if (lc_kyber_keypair_from_seed(&PK, &SK, seed, 64, kind(p)) != 0) return 0;
    if (lc_kyber_pk_ptr(&q, &n, &PK) == 0 && n <= 1568) { memcpy(ek, q, n); *nek = n; }
    if (lc_kyber_ct_load(&CT, c, nc) != 0) return 0;
    if (lc_kyber_ct_type(&CT) != kind(p)) { other_set++; return 0; }
    if (lc_kyber_dec(&SS, &CT, &SK) != 0) return 0;
    return copy_ss(&SS, K);
}

int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    uint8_t* q; size_t n;
    int r;
    struct fixed f = { m, 32, 0 };
    struct lc_rng_ctx ctx = { &FIXED_RNG, &f };
    if (lc_kyber_pk_load(&PK, ek, nek) != 0) return 0;
    if (lc_kyber_pk_type(&PK) != kind(p)) { other_set++; return 0; }
    if (getenv("RANDOM_RNG")) { *nc = 0; return lc_kyber_enc(&CT, &SS, &PK) == 0; }
    lc_rng_set_seeded(&ctx);
    r = lc_kyber_enc(&CT, &SS, &PK);
    lc_rng_set_seeded(NULL);   /* back to the internal generator */
    if (r != 0) return 0;
    if (f.uses != 1 || f.n != 0) odd_rng++;
    if (lc_kyber_ct_ptr(&q, &n, &CT) != 0 || n > 1568) return 0;
    memcpy(c, q, n); *nc = n;
    return copy_ss(&SS, K);
}

int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    /* lc_kyber_sk_load checks H(ek) inside dk (kyber_api.c, lc_kyber_*_iv_sk). */
    if (lc_kyber_sk_load(&SK, dk, ndk) != 0) return 0;
    if (lc_kyber_sk_type(&SK) != kind(p)) { other_set++; return 0; }
    if (lc_kyber_ct_load(&CT, c, nc) != 0) return 0;
    if (lc_kyber_ct_type(&CT) != kind(p)) { other_set++; return 0; }
    if (lc_kyber_dec(&SS, &CT, &SK) != 0) return 0;
    return copy_ss(&SS, K);
}
