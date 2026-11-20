# C libraries: Wycheproof ML-KEM and ML-DSA vectors

Runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-KEM and ML-DSA vectors (commit `65ca494727a5`) against five C libraries with their own implementation, built from their published sources:

| Argument | Library | Version | What is tested |
|---|---|---|---|
| `libsodium` | libsodium | 1.0.22 release tarball | ML-KEM-768 |
| `leancrypto` | leancrypto | 1.9.1 tag, default (AVX2) and C-only builds | ML-KEM, ML-DSA (three verification APIs) |
| `linux` | Linux kernel `lib/crypto/mldsa.c` | tags v7.3.5, v7.0, v7.4-rc3 | ML-DSA verification, built in user space with `linux_compat/`, at `-O2` and with ASan/UBSan |
| `strongswan` | strongSwan "ml" plugin | 6.1.0 release tarball | ML-KEM (acceptance of encapsulation keys; the production interface cannot fix the randomness, import a seed or an expanded key) |
| `nettle` | Nettle | master branch at `10d33c60c1c7` (ML-KEM is not in a release yet) | ML-KEM-768 and ML-KEM-1024 |

Each library has a small adapter (`mlkem_*.c`, `mldsa_*.c`) for the shared harnesses `mlkem_harness.h` and `mldsa_harness.h`. The adapters only use the documented public interface; the comments in each one give the return convention it relies on. When an interface cannot express a vector (for example a key of the wrong length for a fixed-size array), the vector is counted as "no interface", not as a rejection.

`linux_compat/` holds stand-in headers so that two unmodified kernel files (`lib/crypto/mldsa.c` and `lib/crypto/sha3.c`) build in user space. They only provide types, attributes, allocation and string helpers; `shake_linux.c` checks the extracted SHA-3/SHAKE against Python's hashlib before the vectors are run.

## Requirements

Linux x86_64 with git, curl, gcc (with AddressSanitizer), make, autoconf, m4, libgmp-dev, pkg-config and python3 with venv (meson and ninja are installed in a virtual environment). Everything is downloaded and built under `$WORK` (default `~/pqc-field-notes-work`).

## Run

```sh
./run.sh                          # all five
./run.sh libsodium nettle         # some of them
```

## Expected output

- libsodium 1.0.22: `expanded dk: 5 vectors, INVALID ACCEPTED=2` (the keys with a corrupted embedded hash or embedded encapsulation key); 44 vectors have a length the fixed-size interface cannot take.
- Nettle master: no error channel in the interface; `encaps: INVALID ACCEPTED=112` (768) and `116` (1024) for the encapsulation keys with unreduced coefficients, and `expanded dk: INVALID ACCEPTED=2` for each parameter set. There is no ML-KEM-512.
- leancrypto 1.9.1, Linux kernel (all three tags) and strongSwan 6.1.0: no invalid vector accepted and no valid vector failed.

`results/run.log` is our run of `./run.sh libsodium nettle`, `./run.sh leancrypto` and `./run.sh linux strongswan`.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
