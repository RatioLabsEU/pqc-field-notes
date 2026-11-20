# Processor-specific code paths: same vectors, every variant

## Summary

The two defects in our earlier notes lived in optimised code that the portable version did not share. We therefore ran the same Wycheproof ML-KEM and ML-DSA vectors again while forcing each processor-specific path of each implementation.

We found no new discrepancy. Every implementation gave the same results on every path we could exercise. This note records what was covered, so that the earlier results can be read with the right scope.

## What this narrows

- The AVX2 ML-DSA verifier defect described in `2026-mldsa-avx2-verifier` is specific to x86-64 with AVX2. liboqs 0.12.0 to 0.15.0 and PQClean are correct on 64-bit ARM, RISC-V and s390x. The `pqcrypto-mldsa` crate with its `neon` feature is not affected.
- liboqs 0.12.0 does not validate ML-KEM keys on any architecture, as expected: that code has no processor-specific variant.

## Coverage

### 64-bit ARM (cross-compiled, run under `qemu-user`)

| Implementation | Version | Variants | ML-DSA | ML-KEM |
|---|---|---|---|---|
| PQClean | archived master `0586a824fc0d` | `aarch64` (NEON) | conformant | not run |
| liboqs | 0.16.0 | `aarch64` | conformant | conformant |
| liboqs | 0.12.0 to 0.15.0 | reference code for ML-DSA; `aarch64` for ML-KEM from 0.13.0 | conformant | conformant from 0.13.0; 0.12.0 accepts invalid keys as on x86-64 |
| wolfSSL | master | NEON | conformant | conformant |
| libcrux | 0.0.12 (main) | automatic, portable, NEON | conformant | conformant |
| RustCrypto `ml-dsa`, `ml-kem` | main | single | conformant | conformant |
| OpenSSL | master `354f1cf64842` | with assembly | conformant | conformant |
| AWS-LC | main `784feabf5fe3` | with assembly | conformant | conformant |
| BoringSSL | main `12cb59022ae9` | with assembly | conformant | conformant (no ML-KEM-512, no expanded private key import) |

### x86-64 with instruction sets disabled

OpenSSL, AWS-LC and BoringSSL (same commits), using `OPENSSL_ia32cap` to disable AVX-512, then AVX2, then AVX on a processor that has all three: conformant in all four configurations.

### RISC-V and s390x

liboqs 0.13.0 to 0.16.0: conformant. liboqs 0.12.0: ML-DSA conformant, ML-KEM without input validation, as elsewhere. PQClean, `clean` implementation of ML-DSA: conformant. s390x is big-endian, which exercises the portable code with the opposite byte order.

## How to reproduce

[`tests/processor-paths`](../../tests/processor-paths/) has the scripts for the ARM, RISC-V and s390x runs, and `results/run.log` has the output of ours.

## Limits

- Everything outside x86-64 is emulation. It executes the same instructions but does not reproduce differences between real processors.
- For the x86-64 masks we relied on each library honouring `OPENSSL_ia32cap`; we did not confirm from inside which path was taken.
- liboqs 0.13.0 and 0.14.0 have no deterministic ML-KEM interface, so only key acceptance and expanded private keys were checked there.
- Not covered: 32-bit ARM; the large libraries on RISC-V and s390x.

## Method

The research strategy and the test code were designed and written with AI assistance, and the tests were run with AI tooling (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs.
