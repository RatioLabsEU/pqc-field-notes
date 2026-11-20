/* Check of the SHA-3 code taken from the kernel (lib/crypto/sha3.c with the linux_compat/ layer): for messages of
 * several lengths it writes SHAKE128 and SHAKE256 (squeezed in pieces of varying size, as mldsa.c does in
 * sample_in_ball and rej_ntt_poly) and SHA3-256. run.sh compares the output with Python's hashlib.
 * Line format:  algorithm|message length|output length|output in hex
 *
 * Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
 */
#include <stdio.h>
#include <crypto/sha3.h>

static void hex(const u8* b, size_t n) { for (size_t i = 0; i < n; i++) printf("%02x", b[i]); printf("\n"); }

int main(void)
{
    static u8 msg[700], out[1200];
    static const size_t LM[] = {0, 1, 3, 31, 32, 64, 135, 136, 137, 167, 168, 169, 300, 333, 512, 700};
    static const size_t LS[] = {1, 32, 64, 136, 168, 169, 400, 1200};
    for (size_t i = 0; i < sizeof(msg); i++) msg[i] = (u8)(i * 7 + 3);
    for (size_t a = 0; a < sizeof(LM) / sizeof(LM[0]); a++) {
        for (size_t b = 0; b < sizeof(LS) / sizeof(LS[0]); b++) {
            for (int alg = 128; alg <= 256; alg += 128) {
                struct shake_ctx c;
                size_t done = 0, piece = 1;
                if (alg == 128) shake128_init(&c); else shake256_init(&c);
                /* absorb in two parts and squeeze in pieces of 1, 2, 3, ... bytes */
                shake_update(&c, msg, LM[a] / 2);
                shake_update(&c, msg + LM[a] / 2, LM[a] - LM[a] / 2);
                while (done < LS[b]) {
                    size_t t = piece < LS[b] - done ? piece : LS[b] - done;
                    shake_squeeze(&c, out + done, t);
                    done += t; piece++;
                }
                printf("shake%d|%zu|%zu|", alg, LM[a], LS[b]);
                hex(out, LS[b]);
            }
        }
        sha3_256(msg, LM[a], out);
        printf("sha3_256|%zu|32|", LM[a]);
        hex(out, 32);
    }
    return 0;
}
