/* Shared harness for running the NIST ACVP SLH-DSA (FIPS 205) vectors through a library written in C or C++.
 *
 * Reads the text written by acvp_to_text.py: one line per vector with 17 fields separated by "|"
 * (type|tcId|set|interface|prehash|det|hashAlg|expected|sk|pk|seed|addrnd|msg|ctx|ph|sig|comment).
 *
 * Each adapter defines:
 *   const char* lib_name(void);
 *   void lib_init(int argc, char** argv);             argv[3..]: the adapter's own options
 *   int  lib_supports(const param_set_t* p);          1 if the library has that parameter set
 *   int  lib_keygen(const param_set_t* p, const vector_t* v, uint8_t* pk, uint8_t* sk);
 *            1 = generated (pk of 2n and sk of 4n bytes), 0 = the library returned an error, NO_INTERFACE
 *   int  lib_sign(const param_set_t* p, const vector_t* v, uint8_t* sig, size_t* siglen);
 *            SIG_FIXED      = signed deterministically or with the vector's additional randomness: compared byte by
 *                             byte;
 *            SIG_RANDOMISED = signed with its own randomness (the public interface does not let it be fixed): the
 *                             signature is checked by verifying it with the vector's public key through lib_verify;
 *            0 = the library returned an error; NO_INTERFACE; POLICY (see below)
 *   int  lib_verify(const param_set_t* p, const vector_t* v, const uint8_t* sig, size_t siglen);
 *            1 = accepts, 0 = rejects, NO_INTERFACE, POLICY
 * NO_INTERFACE: the public interface does not allow the operation (for example, there is no internal interface, or the
 *               key is passed as a fixed-size array and a different length cannot be given). Not counted as a vector.
 * POLICY:       the library refuses, as it documents, to use that pre-hash with that parameter set (for example
 *               SHA-224); the adapter returns POLICY only if the library did refuse. Counted separately.
 *
 * Usage:  <program> <vector file> <types: kg,sg,sv or a subset> [adapter options]
 * Output: one summary line per group (type, interface, pre-hash, deterministic, origin NIST or OWN) and one line per
 * discrepancy, with the tcId and the vector's comment. The exit code is 1 if there was any.
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#ifndef SLHDSA_HARNESS_H
#define SLHDSA_HARNESS_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define NO_INTERFACE (-1)
#define POLICY (-2)
#define SIG_FIXED 1
#define SIG_RANDOMISED 2

typedef struct {
    const char* name; /* "SLH-DSA-SHA2-128s" */
    int n;            /* parameter n in bytes (16, 24, 32) */
    int shake;        /* 1 = SHAKE, 0 = SHA2 */
    int is_small;     /* 1 = "s", 0 = "f" */
    size_t npk, nsk, nsig;
} param_set_t;

/* FIPS 205, Table 2: public key (2n), private key (4n) and signature sizes. */
static const param_set_t PARAM_SETS[12] = {
    {"SLH-DSA-SHA2-128s", 16, 0, 1, 32, 64, 7856},   {"SLH-DSA-SHAKE-128s", 16, 1, 1, 32, 64, 7856},
    {"SLH-DSA-SHA2-128f", 16, 0, 0, 32, 64, 17088},  {"SLH-DSA-SHAKE-128f", 16, 1, 0, 32, 64, 17088},
    {"SLH-DSA-SHA2-192s", 24, 0, 1, 48, 96, 16224},  {"SLH-DSA-SHAKE-192s", 24, 1, 1, 48, 96, 16224},
    {"SLH-DSA-SHA2-192f", 24, 0, 0, 48, 96, 35664},  {"SLH-DSA-SHAKE-192f", 24, 1, 0, 48, 96, 35664},
    {"SLH-DSA-SHA2-256s", 32, 0, 1, 64, 128, 29792}, {"SLH-DSA-SHAKE-256s", 32, 1, 1, 64, 128, 29792},
    {"SLH-DSA-SHA2-256f", 32, 0, 0, 64, 128, 49856}, {"SLH-DSA-SHAKE-256f", 32, 1, 0, 64, 128, 49856},
};

typedef struct {
    const char *type, *tcid, *set, *interface_txt, *prehash_txt, *hash, *comment;
    int internal;  /* 1 = internal interface (slh_sign_internal / slh_verify_internal) */
    int prehash;   /* 1 = HashSLH-DSA */
    int det;       /* 1 = deterministic (opt_rand = PK.seed), 0 = with addrnd, -1 = not applicable */
    int expected;  /* 1 = valid, 0 = invalid */
    int own;       /* 1 = an edge case of our own (comment starting with "OWN"), 0 = NIST vector */
    uint8_t *sk, *pk, *seed, *addrnd, *msg, *ctx, *ph, *sig;
    size_t nsk, npk, nseed, naddrnd, nmsg, nctx, nph, nsig;
} vector_t;

const char* lib_name(void);
void lib_init(int argc, char** argv);
int lib_supports(const param_set_t* p);
int lib_keygen(const param_set_t* p, const vector_t* v, uint8_t* pk, uint8_t* sk);
int lib_sign(const param_set_t* p, const vector_t* v, uint8_t* sig, size_t* siglen);
int lib_verify(const param_set_t* p, const vector_t* v, const uint8_t* sig, size_t siglen);

#define HARNESS_MAXB 70000

static const param_set_t* harness_set(const char* name)
{
    int i;
    for (i = 0; i < 12; i++)
        if (strcmp(PARAM_SETS[i].name, name) == 0) return &PARAM_SETS[i];
    return NULL;
}

static int harness_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Hexadecimal to bytes; aborts if the text is not hexadecimal of even length (a misread vector must not pass silently). */
static size_t harness_hex(const char* s, uint8_t* out, const char* tcid)
{
    size_t n = 0, len = strlen(s);
    if (len % 2 != 0 || len / 2 > HARNESS_MAXB) { printf("malformed hexadecimal field in tcId=%s\n", tcid); exit(2); }
    for (; n < len / 2; n++) {
        int a = harness_nibble(s[2 * n]), b = harness_nibble(s[2 * n + 1]);
        if (a < 0 || b < 0) { printf("malformed hexadecimal field in tcId=%s\n", tcid); exit(2); }
        out[n] = (uint8_t)(a * 16 + b);
    }
    return n;
}

/* Counters of a group of vectors. */
typedef struct {
    char key[96];
    long total, correct, bad_accept, bad_reject, different, errors, no_interface, policy, randomised, randomised_fail;
    double seconds;
} group_t;

static group_t harness_groups[64];
static int harness_ngroups = 0;

static group_t* harness_group(const vector_t* v)
{
    char key[96];
    int i;
    if (strcmp(v->type, "kg") == 0)
        snprintf(key, sizeof(key), "keyGen %s", v->own ? "OWN" : "NIST");
    else
        snprintf(key, sizeof(key), "%s %s/%s%s %s", strcmp(v->type, "sg") == 0 ? "sigGen" : "sigVer",
                 v->interface_txt, v->prehash_txt,
                 v->det == 1 ? " det" : v->det == 0 ? " rand" : "", v->own ? "OWN" : "NIST");
    for (i = 0; i < harness_ngroups; i++)
        if (strcmp(harness_groups[i].key, key) == 0) return &harness_groups[i];
    if (harness_ngroups == 64) { printf("too many groups\n"); exit(2); }
    memset(&harness_groups[harness_ngroups], 0, sizeof(group_t));
    snprintf(harness_groups[harness_ngroups].key, sizeof(harness_groups[0].key), "%s", key);
    return &harness_groups[harness_ngroups++];
}

static void harness_report(const char* what, const vector_t* v)
{
    printf("  %-28s %s tcId=%s  [%s %s/%s %s]  %s\n", what, v->set, v->tcid, v->type, v->interface_txt, v->prehash_txt,
           v->hash, v->comment);
}

static double harness_now(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec + (double)t.tv_nsec / 1e9;
}

int main(int argc, char** argv)
{
    static char text[600000];
    static uint8_t b_sk[HARNESS_MAXB], b_pk[HARNESS_MAXB], b_seed[HARNESS_MAXB], b_add[HARNESS_MAXB], b_msg[HARNESS_MAXB],
        b_ctx[HARNESS_MAXB], b_ph[HARNESS_MAXB], b_sig[HARNESS_MAXB], out[HARNESS_MAXB], o_pk[256], o_sk[256];
    FILE* f = argc > 2 ? fopen(argv[1], "r") : NULL;
    const char* types = argc > 2 ? argv[2] : "";
    const char* current_set = NULL;
    long discrepancies = 0, not_available = 0;
    int i;

    if (f == NULL) { printf("usage: program <vectors> <kg,sg,sv> [options]\n"); return 2; }
    lib_init(argc, argv);
    while (fgets(text, sizeof(text), f)) {
        char* c[17];
        char* q = text;
        vector_t v;
        const param_set_t* p;
        group_t* g;
        double t0;
        int r;
        size_t nout = 0;

        if (strlen(text) == sizeof(text) - 1) { printf("line too long\n"); return 2; }
        text[strcspn(text, "\r\n")] = 0;
        if (text[0] == 0 || text[0] == '#') continue;
        for (i = 0; i < 17; i++) {
            c[i] = q;
            if (i < 16) { q = strchr(q, '|'); if (q == NULL) break; *q++ = 0; }
        }
        if (i < 16) { printf("line with fewer than 17 fields\n"); return 2; }
        if (strstr(types, c[0]) == NULL) continue;
        memset(&v, 0, sizeof(v));
        v.type = c[0]; v.tcid = c[1]; v.set = c[2]; v.interface_txt = c[3]; v.prehash_txt = c[4]; v.hash = c[6];
        v.comment = c[16];
        v.internal = strcmp(c[3], "internal") == 0;
        v.prehash = strcmp(c[4], "preHash") == 0;
        v.det = strcmp(c[5], "1") == 0 ? 1 : strcmp(c[5], "0") == 0 ? 0 : -1;
        v.expected = strcmp(c[7], "valid") == 0;
        v.own = strncmp(c[16], "OWN", 3) == 0;
        v.sk = b_sk; v.nsk = harness_hex(c[8], b_sk, v.tcid);
        v.pk = b_pk; v.npk = harness_hex(c[9], b_pk, v.tcid);
        v.seed = b_seed; v.nseed = harness_hex(c[10], b_seed, v.tcid);
        v.addrnd = b_add; v.naddrnd = harness_hex(c[11], b_add, v.tcid);
        v.msg = b_msg; v.nmsg = harness_hex(c[12], b_msg, v.tcid);
        v.ctx = b_ctx; v.nctx = harness_hex(c[13], b_ctx, v.tcid);
        v.ph = b_ph; v.nph = harness_hex(c[14], b_ph, v.tcid);
        v.sig = b_sig; v.nsig = harness_hex(c[15], b_sig, v.tcid);
        p = harness_set(v.set);
        if (p == NULL) { printf("unknown parameter set: %s\n", v.set); return 2; }
        if (current_set == NULL) current_set = p->name;
        if (!lib_supports(p)) { not_available++; continue; }
        g = harness_group(&v);
        t0 = harness_now();

        if (strcmp(v.type, "kg") == 0) {
            r = lib_keygen(p, &v, o_pk, o_sk);
            if (r == NO_INTERFACE) g->no_interface++;
            else if (r == 0) { g->total++; g->errors++; discrepancies++; harness_report("KEY GENERATION ERROR", &v); }
            else {
                g->total++;
                if (memcmp(o_pk, v.pk, p->npk) == 0 && memcmp(o_sk, v.sk, p->nsk) == 0) g->correct++;
                else { g->different++; discrepancies++; harness_report("DIFFERENT KEY", &v); }
            }
        } else if (strcmp(v.type, "sg") == 0) {
            r = lib_sign(p, &v, out, &nout);
            if (r == NO_INTERFACE) g->no_interface++;
            else if (r == POLICY) g->policy++;
            else if (!v.expected) { /* a case of our own that the library must refuse to sign (256-byte context) */
                g->total++;
                if (r == 0) g->correct++;
                else { g->bad_accept++; discrepancies++; harness_report("SIGNED WHAT IT SHOULD REFUSE", &v); }
            } else if (r == 0) { g->total++; g->errors++; discrepancies++; harness_report("SIGNING ERROR", &v); }
            else if (r == SIG_FIXED) {
                g->total++;
                if (nout == v.nsig && memcmp(out, v.sig, nout) == 0) g->correct++;
                else { g->different++; discrepancies++; harness_report("DIFFERENT SIGNATURE", &v); }
            } else { /* SIG_RANDOMISED: cannot be compared; it must verify with the vector's public key */
                g->total++; g->randomised++;
                if (nout == p->nsig && lib_verify(p, &v, out, nout) == 1) g->correct++;
                else { g->randomised_fail++; discrepancies++; harness_report("RANDOMISED SIGNATURE FAILS", &v); }
            }
        } else if (strcmp(v.type, "sv") == 0) {
            r = lib_verify(p, &v, v.sig, v.nsig);
            if (r == NO_INTERFACE) g->no_interface++;
            else if (r == POLICY) g->policy++;
            else {
                g->total++;
                if ((r == 1) == (v.expected == 1)) g->correct++;
                else if (r == 1) { g->bad_accept++; discrepancies++; harness_report("INVALID ACCEPTED", &v); }
                else { g->bad_reject++; discrepancies++; harness_report("valid rejected", &v); }
            }
        }
        g->seconds += harness_now() - t0;
    }
    for (i = 0; i < harness_ngroups; i++) {
        group_t* g = &harness_groups[i];
        printf("%-30s %-18s %-36s vectors=%-3ld correct=%-3ld", lib_name(), current_set ? current_set : "?", g->key,
               g->total, g->correct);
        if (strncmp(g->key, "sigVer", 6) == 0)
            printf(" INVALID ACCEPTED=%ld valid rejected=%ld", g->bad_accept, g->bad_reject);
        else
            printf(" DIFFERENT=%ld errors=%ld", g->different, g->errors);
        if (g->bad_accept && strncmp(g->key, "sigGen", 6) == 0) printf(" SIGNED-WHAT-IT-SHOULD-REFUSE=%ld", g->bad_accept);
        if (g->randomised) printf(" (randomised, checked by verifying: %ld, failing: %ld)", g->randomised, g->randomised_fail);
        if (g->no_interface) printf(" no interface=%ld", g->no_interface);
        if (g->policy) printf(" refused by policy=%ld", g->policy);
        printf("  %.1f s\n", g->seconds);
    }
    if (not_available) printf("%-30s %-18s parameter set not in the library (%ld vectors not tested)\n", lib_name(),
                              current_set ? current_set : "?", not_available);
    fclose(f);
    return discrepancies > 0;
}

#endif
