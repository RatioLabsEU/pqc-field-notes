# ML-DSA AVX2 verifier: tests

The tests behind the note [`advisories/2026-mldsa-avx2-verifier`](../../advisories/2026-mldsa-avx2-verifier/). `run.sh` and `run_pqcrypto.sh` are described in that note (liboqs, PQClean, `pqcrypto-mldsa` and `oqs`, with the Wycheproof vectors). The section below covers the crate added on 21 November 2026.

## pqcrypto-dilithium 0.5.0

`run_pqcrypto_dilithium.sh` checks the archived Rust crate `pqcrypto-dilithium` 0.5.0, which ships the same unfixed AVX2 verifier. The crate implements a pre-standard version of Dilithium, so the Wycheproof ML-DSA vectors do not apply to it. The script makes the inputs with the crate's own C code instead (`dilithium_generator.c`):

- `out_of_bound`: 20 signatures per parameter set from the crate's portable signer, patched as in `run.sh` so that it only emits signatures with `γ1 − β ≤ ‖z‖∞ < γ1`, with a key from the crate's own key generation.
- `use_hint`: 2 valid signatures per parameter set that make the verifier compute `UseHint(1, 0)` (an all-zero public key, `z = 0`, one hint or one hint per polynomial, on coefficients where `w = 0`). They are our own construction, not public test vectors. The generator writes one only if the crate's portable verifier accepts it.

`pqcrypto-dilithium-check` then verifies every input through three paths of the crate: its Rust interface (which selects AVX2 at run time when the `avx2` feature is on and the CPU has AVX2), the portable C function (`clean`) and the AVX2 C function. It prints the acceptances per path and each discrepancy between paths. As a control, it first checks 20 key pairs and signatures made through the crate's Rust interface, as made and with one byte changed. It runs twice: with the default features, and with `--no-default-features`.

### Requirements

Linux x86_64 with AVX2, gcc, perl, and rustup with cargo. It does not need `./run.sh` first. Cargo's home and target directories are set under `$WORK/pqcrypto-dilithium` (default `WORK=~/pqc-field-notes-work`); nothing is installed system-wide.

### Run

```sh
./run_pqcrypto_dilithium.sh
```

### Expected output

The same for dilithium2, dilithium3 and dilithium5:

- The controls read `20/20` (`control: the crate's keypair + detached_sign`) and `0/20` (`... with one byte changed`) on every path, and the run ends with `controls correct`.
- With the default features: `out_of_bound ... accepted: API 20/20, clean 0/20, avx2 20/20` and `use_hint ... accepted: API 0/2, clean 2/2, avx2 0/2`.
- Without the `avx2` feature: `API 0/20, clean 0/20` and `API 2/2, clean 2/2`, with no discrepancy.

The output of our run is [`advisories/2026-mldsa-avx2-verifier/results/pqcrypto-dilithium.log`](../../advisories/2026-mldsa-avx2-verifier/results/pqcrypto-dilithium.log), from a run of `./run_pqcrypto_dilithium.sh` as it is here, on 21 November 2026 on a GitHub Codespace (Linux 6.8, x86_64 with AVX2, 2 cores, Intel Xeon Platinum 8573C) with gcc 13.3 and Rust 1.100. Paths under the working directory are shown as `$WORK`.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
