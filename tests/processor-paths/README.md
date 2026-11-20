# Processor-specific paths: Wycheproof ML-KEM and ML-DSA vectors on other architectures

Libraries that have separate code for each processor were tested on x86_64 first. This directory runs the [Wycheproof](https://github.com/C2SP/wycheproof) vectors (commit `65ca494727a5`) through their other code paths, with cross compilation and user-mode emulation (qemu-user):

| Argument | Libraries | Code paths |
|---|---|---|
| `arm` | PQClean `0586a824fc0d`, liboqs 0.12.0 to 0.16.0 | PQClean aarch64 ML-DSA (NEON); liboqs distribution build for aarch64 (ML-DSA and ML-KEM) |
| `cross` | PQClean, liboqs | PQClean "clean" ML-DSA and liboqs on riscv64 and s390x (big-endian) |
| `rust-arm` | RustCrypto `ml-dsa` / `ml-kem`, libcrux `libcrux-ml-dsa` / `libcrux-ml-kem` (commits pinned in `rust-*/Cargo.toml`) | automatic, portable and NEON paths on aarch64 |
| `big-arm` | OpenSSL `354f1cf64842`, AWS-LC `784feabf5fe3`, BoringSSL `12cb59022ae9` | aarch64 builds with their assembly |

The C adapters (`mlkem_*.c`, `mldsa_*.c`, `*.cc`) plug into the shared harnesses `mlkem_harness.h` and `mldsa_harness.h`; `wycheproof_mldsa.c` is a stand-alone ML-DSA runner for liboqs and PQClean. liboqs before 0.15 has no functions with fixed randomness: for those versions `mlkem_liboqs.c` is built with `-DNO_DERAND` and only key acceptance and the expanded decapsulation key are tested.

## Requirements

Linux x86_64 with git, curl, python3, cmake, make, perl, qemu-user (`qemu-aarch64`, `qemu-riscv64`, `qemu-s390x`), `gcc-aarch64-linux-gnu`, `g++-aarch64-linux-gnu`, `gcc-riscv64-linux-gnu`, `gcc-s390x-linux-gnu` and their `libc6-dev-*-cross`; for `rust-arm`, rustup and cargo (the `aarch64-unknown-linux-gnu` target is added). Everything is downloaded and built under `$WORK` (default `~/pqc-field-notes-work`).

## Run

```sh
./run.sh                                              # arm cross rust-arm big-arm
LIBOQS_VERSIONS="0.12.0 0.16.0" CROSS_ARCHS=s390x ./run.sh cross
```

## Expected output

No architecture-specific discrepancy: on every path, the counts are the ones of the same library on x86_64.

- PQClean and liboqs ML-DSA: `vectors=171 (valid 77, invalid 94, not applicable 9)` for ML-DSA-44 (201 and 232 for -65 and -87), `INVALID ACCEPTED=0   valid rejected=0`.
- liboqs ML-KEM: 0.15.0 and 0.16.0 conform. 0.12.0 accepts the encapsulation keys with unreduced coefficients (`encaps: ... INVALID ACCEPTED=108`, `112`, `116`), as on x86_64; 0.13.0 and 0.14.0 conform.
- RustCrypto, libcrux, OpenSSL, AWS-LC and BoringSSL: no invalid vector accepted and no valid vector failed (BoringSSL has no ML-KEM-512 and no interface for fixed randomness or expanded keys).

The two-way Keccak in PQClean's `common/keccak2x` uses NEON, so it is only linked into the aarch64 build.


Re-run after translation; the output is in `results/run.log`. The counts match our earlier runs.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
