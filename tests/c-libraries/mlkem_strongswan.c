/* Adapter for the strongSwan "ml" plugin (libstrongswan) for mlkem_harness.h.
 *
 * Public interface: key_exchange_t (src/libstrongswan/crypto/key_exchange.h), created with
 * lib->crypto->create_ke(lib->crypto, ML_KEM_512/768/1024). For a KEM, the responder calls set_public_key(ek): it checks
 * length and modulus (ml_kem.c, validate_public_key) and encapsulates with its own randomness; get_public_key() then
 * gives it the ciphertext. set_public_key returns TRUE if the key is accepted.
 *
 * What the public interface does NOT allow (counted as "no interface", -1):
 *   - generating the key from a given seed (it only generates with its own generator; set_seed exists only when built
 *     with TESTABLE_KE, which is for the project's internal tests);
 *   - fixing the encapsulation randomness (so c and K are not compared: only accept/reject the key);
 *   - importing an expanded decapsulation key.
 * Order: library_init and explicit loading of the random, sha3 and ml plugins (and no other that provides ML-KEM).
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <library.h>
#include <crypto/key_exchange.h>
#include "mlkem_harness.h"

static key_exchange_method_t method(int p) { return p == 512 ? ML_KEM_512 : p == 768 ? ML_KEM_768 : ML_KEM_1024; }

const char* lib_name(void) { return getenv("SW_NAME") ? getenv("SW_NAME") : "strongswan ml"; }

/* Positive control that the interface does allow: a full round trip (the initiator generates ek, the responder
 * encapsulates, the initiator decapsulates) and both secrets must match. */
static void round_trip(int p)
{
    key_exchange_t* a = lib->crypto->create_ke(lib->crypto, method(p));
    key_exchange_t* b = lib->crypto->create_ke(lib->crypto, method(p));
    chunk_t ek = chunk_empty, ct = chunk_empty, ka = chunk_empty, kb = chunk_empty;
    int good = 0, i;
    for (i = 0; i < 20 && a && b; i++) {
        if (!a->get_public_key(a, &ek) || !b->set_public_key(b, ek) || !b->get_public_key(b, &ct) ||
            !a->set_public_key(a, ct) || !a->get_shared_secret(a, &ka) || !b->get_shared_secret(b, &kb))
            break;
        good += chunk_equals(ka, kb) && ka.len == 32;
        chunk_free(&ek); chunk_free(&ct); chunk_clear(&ka); chunk_clear(&kb);
        a->destroy(a); b->destroy(b);
        a = lib->crypto->create_ke(lib->crypto, method(p));
        b = lib->crypto->create_ke(lib->crypto, method(p));
    }
    chunk_free(&ek); chunk_free(&ct); chunk_clear(&ka); chunk_clear(&kb);
    DESTROY_IF(a); DESTROY_IF(b);
    printf("strongswan ML-KEM-%d: round trip (generate, encapsulate, decapsulate) with equal secrets: %d of 20\n", p, good);
}

void lib_init(int argc, char** argv)
{
    /* SW_CONF: a minimal strongswan.conf (without it, library_init aborts with "invalid configuration"). */
    if (!library_init(getenv("SW_CONF"), "wycheproof")) { printf("library_init failed\n"); exit(2); }
    if (!lib->plugins->load(lib->plugins, "random sha3 ml")) { printf("the plugins do not load\n"); exit(2); }
    round_trip(argc > 2 ? atoi(argv[2]) : 768);
}

int lib_seed(int p, const uint8_t* seed, uint8_t* ek, size_t* nek, const uint8_t* c, size_t nc, uint8_t* K)
{
    (void)p; (void)seed; (void)ek; (void)nek; (void)c; (void)nc; (void)K;
    return -1;
}

int lib_encaps(int p, const uint8_t* ek, size_t nek, const uint8_t* m, uint8_t* c, size_t* nc, uint8_t* K)
{
    key_exchange_t* ke = lib->crypto->create_ke(lib->crypto, method(p));
    chunk_t ct = chunk_empty;
    bool ok;
    (void)m; (void)c; (void)K;
    *nc = 0;   /* no fixed randomness: the harness does not compare c or K */
    if (ke == NULL) return 0;
    ok = ke->set_public_key(ke, chunk_create((u_char*)ek, nek));
    /* if it accepts, the ciphertext must exist and have the length of the parameter set */
    if (ok && (!ke->get_public_key(ke, &ct) || ct.len != (size_t)MK_CT(p))) {
        printf("  warning: key accepted but no correct ciphertext (len %zu)\n", ct.len);
        ok = FALSE;
    }
    chunk_free(&ct);
    ke->destroy(ke);
    return ok ? 1 : 0;
}

int lib_decaps_dk(int p, const uint8_t* dk, size_t ndk, const uint8_t* c, size_t nc, uint8_t* K)
{
    (void)p; (void)dk; (void)ndk; (void)c; (void)nc; (void)K;
    return -1;
}
