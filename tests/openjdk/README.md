# OpenJDK: Wycheproof ML-KEM and ML-DSA vectors

Runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-KEM and ML-DSA vectors (commit `65ca494727a5`) against OpenJDK's own implementation (SUN / SunJCE providers), through the public API: `KeyFactory`, `KEM` and `Signature`. `run.sh` downloads Eclipse Temurin builds from api.adoptium.net (the latest GA build of each feature release) and runs `WycheproofJDK.java` as a single-file program in several JVM configurations:

| Mode | Flags | Purpose |
|---|---|---|
| `def` | none, 40 rounds | lets the JIT compiler and the CPU intrinsics kick in |
| `int` | `-Xint` | interpreter only |
| `comp` | `-Xcomp` | everything compiled from the start |
| `avx2` | `-XX:UseAVX=2` | no AVX-512 |
| `sse` | `-XX:UseAVX=0` | no AVX |

Limits of the API: the encapsulation randomness cannot be fixed, so for the encapsulation vectors only acceptance of the key is checked; ML-DSA vectors with a non-empty context are counted as "not applicable".

## Requirements

Linux x86_64 with git, curl, python3 and tar. Everything is downloaded under `$WORK` (default `~/pqc-field-notes-work`).

## Run

```sh
./run.sh 24 25 26 27                                   # modes def, int, comp
MODES="int def comp avx2 sse" ./run.sh 24 25 26 27     # all five modes
```

## Expected output

For every version and mode, no invalid vector accepted and no valid vector failed:

```
OpenJDK ML-KEM-512   | seed: 200 accepted=0 failed=0 | encaps: 261 accepted=0 failed=0 | expanded dk: 9 accepted=0 failed=0
OpenJDK ML-DSA-44    vectors=173 (not applicable 7)   INVALID ACCEPTED=0   valid rejected=0
```

OpenJDK 24 does not take ML-KEM private keys in seed form, so its "seed" column shows 20 vectors and `(no interface 180)` (181 and 182 for ML-KEM-768 and -1024).

`results/run.log` is our run of `MODES=int ./run.sh 25` and `MODES=int ./run.sh 24 26 27` (OpenJDK 24.0.2+12, 25.0.5.1+2, 26.0.2.1+1 and 27.0.1.1+4, interpreter only).

Re-run after translation: all five modes for Java 25 (`results/run_java25_other_modes.log`) and the interpreter mode for 24, 26 and 27. Not re-run after translation: the `def`, `comp`, `avx2` and `sse` modes for 24, 26 and 27; our earlier runs of those gave the same counts.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
