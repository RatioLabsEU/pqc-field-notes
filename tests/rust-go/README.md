# Rust and Go libraries: Wycheproof ML-KEM and ML-DSA vectors

Runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-KEM and ML-DSA vectors (commit `65ca494727a5`) against Rust crates and Go modules with their own implementation, through their public interface:

| Argument | Package | Version |
|---|---|---|
| `cryptoxide` | Rust crate `cryptoxide` | 0.6.7 |
| `purecrypto` | Rust crate `purecrypto` | 0.10.6 |
| `macula` | Rust crates `macula-mlkem` and `macula-mldsa` | 0.3.0 |
| `gmsm` | Go module `github.com/emmansun/gmsm` (with its assembly and with `-tags purego`) | v0.45.4 |
| `k2so` | Go module `github.com/symbolicsoft/kyber-k2so` | v1.1.1 |
| `tink` | Go module `github.com/tink-crypto/tink-go/v2`, `signature/mldsa` | v2.9.0 |
| `diag-gmsm` | diagnosis of the gmsm ML-DSA result (a copy of the module without the empty-message check) | |

`rust/common.rs` and `go/common/common.go` hold the shared vector loop; each library has one small program. Rust crates are built in release and in debug (overflow checks on). The `purecrypto` program also runs a control with the non-validating `from_bytes`, which must report invalid keys as accepted.

## Requirements

Linux x86_64 with git, python3 and perl, plus Rust (cargo, edition 2024) and Go 1.26 or later for the parts you run. The sources are copied to `$WORK` (default `~/pqc-field-notes-work`) and all caches and builds stay there.

## Run

```sh
./run.sh                    # cryptoxide purecrypto macula gmsm k2so tink
./run.sh gmsm diag-gmsm
```

## Expected output

- gmsm v0.45.4: `valid rejected=3` for each ML-DSA parameter set, with both builds. The three vectors are the valid ones with an empty message; `diag-gmsm` shows that they pass once the `len(message) == 0` check in `VerifyWithOptions` is removed. ML-KEM conforms.
- tink-go has no way to pass a context: 7 vectors per parameter set are "no interface".
- cryptoxide, purecrypto, macula and kyber-k2so: no invalid vector accepted and no valid vector failed. In the purecrypto control line, `INVALID ACCEPTED=112` and `2` are expected.

`results/run.log` is our run of `./run.sh gmsm k2so tink diag-gmsm` followed by `./run.sh cryptoxide purecrypto macula`.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
