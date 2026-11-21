# Major libraries: Wycheproof ML-KEM and ML-DSA vectors on x86_64

Runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-DSA verification and ML-KEM vectors (commit `65ca494727a5`) against the current code of the major libraries on x86_64. Each library is built from its published sources at the commit of its development branch that we tested in November 2026, or at the named release. These are not "the latest release" of each library.

| Argument | Library | Version | ML-DSA verification | ML-KEM |
|---|---|---|---|---|
| `wolfssl` | wolfSSL | development branch at `511ea63482eb` (ML-DSA) and `f10bbcc7a15e` (ML-KEM), `--enable-intelasm` | automatic (`auto`), AVX-512 off (`no-avx512`), AVX-512 and AVX2 off (`no-avx2`) | automatic |
| `openssl` | OpenSSL | development branch at `354f1cf64842` | 44, 65, 87 | 512, 768, 1024 |
| `boringssl` | BoringSSL | development branch at `12cb59022ae9` | 44, 65, 87 | 768, 1024 |
| `aws-lc` | AWS-LC | development branch at `784feabf5fe3` | 44, 65, 87 | 512, 768, 1024 |
| `symcrypt` | SymCrypt | development branch at `286762b7730e` | 44, 65, 87 | 512, 768, 1024 |
| `liboqs` | liboqs | 0.16.0 release (ML-DSA); development branch at `f822b059350a`, which reports version 0.16.0 (ML-KEM) | distribution build (AVX2 chosen at run time) and portable C build | the same two builds |
| `pqclean` | PQClean | `0586a824fc0d` | `clean` | |
| `botan` | Botan | development branch at `3a5a820fa54e` | vectors with an empty context | |
| `go` | Go `crypto/mldsa` and `crypto/mlkem`; CIRCL | Go 1.27.3; CIRCL `31be93db4772` | Go and CIRCL | Go: 768, 1024; CIRCL: 512, 768, 1024 |
| `java` | Bouncy Castle | bcprov-jdk18on 1.87 (Maven Central) | 44, 65, 87 | 512, 768, 1024 |
| `rust` | RustCrypto `ml-dsa` and `ml-kem`; libcrux `libcrux-ml-dsa` and `libcrux-ml-kem` | `8d3230a53453` (ml-dsa 0.1.2), `b26db85a9b44` (ml-kem 0.3.4), `24330863b3d1` (libcrux 0.0.12), pinned in `rust-*/Cargo.toml` | RustCrypto; libcrux automatic, portable and AVX2 | the same |
| `masked` | OpenSSL, AWS-LC, BoringSSL | the builds above | run again with `OPENSSL_ia32cap` masking AVX-512, then AVX2, then AVX | the same |

The C and C++ adapters (`mlkem_*.c`, `mldsa_*.c`, `*.cc`, `*.cpp`) plug into the shared harnesses `mlkem_harness.h` and `mldsa_harness.h`; `wycheproof_mldsa.c` is the stand-alone ML-DSA runner for liboqs and PQClean. The Go (`go-mldsa`, `go-mlkem`), Java (`java/`) and Rust (`rust-mldsa`, `rust-mlkem`) programs apply the same rules and print the same lines. The adapters for OpenSSL, AWS-LC, BoringSSL and liboqs and the Rust programs are the ones in [`tests/processor-paths`](../processor-paths/).

In ML-DSA, a discrepancy is an invalid vector that is accepted (`INVALID ACCEPTED`) or a valid one that is rejected (`valid rejected`); a key or a context that the library does not take counts as a rejection. In ML-KEM there are three kinds of vector: `seed` (key generation from the 64-byte seed, then decapsulation; the shared secret is compared, and the encapsulation key when the library returns it), `encaps` (encapsulation with the given key and randomness; the ciphertext and the shared secret are compared when the randomness can be fixed) and `expanded dk` (decapsulation with the expanded decapsulation key). `valid fails` counts valid vectors that are rejected or give a different result.

What the interfaces do not let us test:

- **Botan** takes no context string when verifying. Its 173, 203 and 234 vectors with an empty context are tested; the other 7 per parameter set are reported as "not applicable".
- **AWS-LC and liboqs** take keys as fixed-length byte strings. In the AWS-LC adapters (ML-DSA and ML-KEM) and the liboqs ML-KEM adapter, a key of another length is counted as rejected without calling the library. For liboqs ML-DSA and PQClean, `wycheproof_mldsa.c` leaves out the vectors whose public key has the wrong length or whose context is longer than 255 bytes, and reports them as "not applicable" (9 per parameter set).
- **BoringSSL and Go** have no ML-KEM-512 and no interface to import an expanded decapsulation key (`no interface`). BoringSSL's ML-KEM-512 line still shows `seed: 20 vectors`: those are the 20 seeds of the wrong length that the harness rejects itself. Go's ML-KEM-512 is not run.
- **Where the randomness cannot be fixed** (encapsulation in BoringSSL and SymCrypt), only acceptance of the key is checked: a valid encapsulation vector passes if the key is accepted, an invalid one if it is rejected. The ciphertext and the shared secret are not compared.
- **RustCrypto `ml-kem`** has no interface to import an expanded decapsulation key (`no interface`).
- **libcrux** separates validation from the operation: it has `validate_public_key` and `validate_private_key`, and the adapter calls them before encapsulating or decapsulating. Code that uses the library without calling them does not get those checks. This is a documented design decision of libcrux, not a defect.
- **`masked`** relies on each library honouring `OPENSSL_ia32cap`, its documented mechanism; we did not check from inside which code path each one took. The masks clear bits 16 to 31 of CPUID leaf 7 EBX (AVX-512 F, DQ, IFMA, CD, BW and VL, and the other bits in that range, among them RDSEED, ADX and SHA), then also bit 5 (AVX2), then also bit 28 of leaf 1 ECX (AVX). OpenSSL also clears the CPUID words that the variable does not give (leaf 7 sub-leaf 1 and later).
- **wolfSSL**'s ML-DSA modes clear the CPU flags in wolfSSL's own run-time detection (`cpuid_clear_flag`) before the first operation.
- The Rust programs are built with `RUSTFLAGS="-C target-cpu=native"`.

The processor variants only mean something on a processor that has the instructions: ours has AVX2 and AVX-512 (the `CPU:` line of the log).

## Requirements

Linux x86_64 with git, curl, python3, gcc, g++, cmake, make, perl, autoconf, automake and libtool; a JDK (javac and java) for `java`; rustup and cargo for `rust`. If the `go` on the PATH is not Go 1.27.3, that release is downloaded from go.dev. Everything is downloaded and built under `$WORK` (default `~/pqc-field-notes-work`). A full run from scratch took 13 minutes and 2.6 GB on a 2-core machine.

## Run

```sh
./run.sh                             # everything
./run.sh openssl aws-lc boringssl    # some of them
./run.sh masked                      # builds OpenSSL, AWS-LC and BoringSSL if needed
```

## Expected output

No discrepancy in any library or variant: `INVALID ACCEPTED=0` and `valid rejected=0` / `valid fails=0` on every line.

- ML-DSA: `vectors=180`, `210` and `241` for ML-DSA-44, -65 and -87. Botan: `173`, `203` and `234` with `(not applicable: 7)`. liboqs and PQClean: `vectors=171 (valid 77, invalid 94, not applicable 9)` for ML-DSA-44 (201 and 232 for -65 and -87).
- ML-KEM: `seed: 200`, `201` and `202` vectors, `encaps: 261`, `265` and `269`, `expanded dk: 9` for ML-KEM-512, -768 and -1024, except where the library has no interface (see above).

`results/run.log` is our run of `./run.sh` on a 2-core x86_64 machine with AVX-512 (a GitHub Codespace). It reused the builds of a first run from an empty `$WORK`, which printed the same counts. The counts match our earlier runs.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
