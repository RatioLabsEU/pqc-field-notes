# Small packages: Wycheproof ML-KEM and ML-DSA vectors

Runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-KEM and ML-DSA vectors (commit `65ca494727a5`) against small packages with their own implementation, through their public interface:

| Argument | Packages | Language |
|---|---|---|
| `dart` | `pqcrypto` 0.4.4 (ML-KEM, ML-DSA) and `cipherlib` 0.7.2 (ML-KEM), from pub.dev | Dart |
| `nuget` | `KyberNET` 1.0.3 (ML-KEM), from nuget.org | C# |
| `npm` | `@theqrl/mldsa87` 2.2.0, `noqtis` 0.2.2, `@umbra-privacy/quick-mlkem768` 0.1.1, from npm | JavaScript / WebAssembly |
| `swift` | `SwiftKyber` 3.5.0 and `SwiftDilithium` 3.6.0 (github.com/leif-ibsen) | Swift |
| `php` | `paragonie/pqcrypto_compat` 0.3.4, from Packagist | PHP |
| `analyze` | diagnosis of the vectors that explains the KyberNET result | |

Versions are pinned in each sub-directory; the lock file each tool writes records the checksum of every archive. SwiftKyber, SwiftDilithium and their BigInt dependency call Apple's `SecRandomCopyBytes`, which does not exist on Linux: `swift/shim/SecRandomLinux.swift` provides it from the system generator and is added to each package with `swift package edit`. It does not touch the cryptography; the test uses deterministic paths except for `Encapsulate()`, where only acceptance of the key is checked.

## Requirements

Linux x86_64 with git, curl, unzip, gpg and python3. The Dart SDK 3.14.1 and the Swift 6.4.2 toolchain for Ubuntu 24.04 are downloaded and checked (sha256 and GPG signature). For `nuget`, the .NET 10 SDK; for `npm`, Node.js and npm; for `php`, PHP 8.1 or later and Composer. The sources are copied to `$WORK` (default `~/pqc-field-notes-work`) and everything is downloaded and built there.

## Run

```sh
./run.sh                    # dart nuget npm swift php
./run.sh dart npm analyze
```

## Expected output

- cipherlib 0.7.2 and quick-mlkem768 0.1.1: `expanded dk: 9 vectors, INVALID ACCEPTED=2` (the keys with a corrupted embedded hash or embedded encapsulation key).
- pqcrypto (Dart) 0.4.4: `seed: 200 vectors, INVALID ACCEPTED=1` for ML-KEM-512, the "Private key too short" vector (a 32-byte seed, which the package documents as d with a random z).
- KyberNET 1.0.3: `seed: ... valid fails=30` per parameter set, `RandomBitGenerationException`: the valid vectors whose z is all zeros (`analyze` lists them). The interface takes d and z separately, so the 20 seeds of the wrong length per set are "no interface".
- pqcrypto_compat 0.3.4: no way to import an expanded key (9 vectors per set are "no interface").
- @theqrl/mldsa87, noqtis, SwiftKyber, SwiftDilithium: no invalid vector accepted and no valid vector failed.

`results/run.log` is our run of `./run.sh dart npm analyze`, `./run.sh nuget php` and `./run.sh swift`.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
