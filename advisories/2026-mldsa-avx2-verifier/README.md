# ML-DSA: an unfixed AVX2 verifier in liboqs 0.12–0.15, PQClean and three Rust crates

**Status:** known and fixed upstream (pq-crystals, 3 June 2026). This note documents software that still carries the unfixed code.

## Summary

The AVX2 implementation of ML-DSA signature verification in the pq-crystals reference software had two defects, both reported by Eric Biggers and fixed upstream on 3 June 2026:

1. **Missing norm check.** The verifier did not check `||z||∞ < γ1 − β` (FIPS 204, Algorithm 8, line 13). It accepts signatures that a conforming verifier rejects. Upstream issue [pq-crystals/dilithium#113](https://github.com/pq-crystals/dilithium/issues/113), fixed in `d35ba3fe54`.
2. **`use_hint_avx()` boundary case.** One class of valid signatures is rejected. Fixed in `bba9534a3c`.

Several projects vendored the AVX2 code before those fixes and never picked them up. We confirmed five by running them:

| Software | Versions | Affected configuration | Fix available |
|---|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | 0.12.0 – 0.15.0 | Default build on x86_64 with AVX2 | Yes: 0.16.0 (replaced the implementation) |
| [PQClean](https://github.com/PQClean/PQClean) | All (archived August 2026) | `crypto_sign/ml-dsa-*/avx2` | No |
| [pqcrypto-mldsa](https://crates.io/crates/pqcrypto-mldsa) (Rust) | 0.1.2 | Default `avx2` feature on x86_64 | No (archived) |
| [oqs](https://crates.io/crates/oqs) (Rust) | 0.11.0, the latest release | Always on x86_64 with AVX2: it builds a bundled liboqs 0.13.0 | No release with liboqs 0.16.0 yet |
| [pqcrypto-dilithium](https://crates.io/crates/pqcrypto-dilithium) (Rust) | 0.5.0 | Default `avx2` feature on x86_64 (a pre-standard version of Dilithium: see [below](#pqcrypto-dilithium-050)) | No (archived, unmaintained) |

In each case the portable implementation shipped alongside is correct. The same library version therefore gives different verification results depending on the CPU.

## Impact

- Producing an accepted out-of-bound signature requires the private key. This is **not** a way to forge someone else's signature.
- A signer can produce a signature that some verifiers accept and others reject. This matters wherever several parties must agree on whether a signature is valid, and it is a FIPS 204 non-conformance.
- The second defect makes an affected verifier reject a signature that is valid.

## Results

Linux x86_64, Intel Xeon Platinum 8573C, gcc 13.3, Rust 1.100. Full logs are in [`results/`](results/).

### Wycheproof ML-DSA verification vectors

[C2SP/wycheproof](https://github.com/C2SP/wycheproof) at `65ca494727a5`: 171, 201 and 232 applicable vectors for ML-DSA-44, -65 and -87.

| Implementation | Build | Invalid vectors accepted (44 / 65 / 87) | Valid vectors rejected (44 / 65 / 87) |
|---|---|---|---|
| liboqs 0.12.0, 0.13.0, 0.14.0, 0.15.0 | default (AVX2 selected at run time) | **37 / 41 / 49** each | **1 / 1 / 1** each |
| liboqs 0.12.0, 0.13.0, 0.14.0, 0.15.0 | portable | 0 / 0 / 0 | 0 / 0 / 0 |
| liboqs 0.16.0 | default | 0 / 0 / 0 | 0 / 0 / 0 |
| liboqs 0.16.0 | portable | 0 / 0 / 0 | 0 / 0 / 0 |
| PQClean | avx2 | **37 / 41 / 49** | **1 / 1 / 1** |
| PQClean | clean | 0 / 0 / 0 | 0 / 0 / 0 |
| pqcrypto-mldsa 0.1.2 | default features (`avx2`) | **37 / 41 / 49** | **1 / 1 / 1** |
| pqcrypto-mldsa 0.1.2 | `avx2` feature disabled | 0 / 0 / 0 | 0 / 0 / 0 |
| oqs 0.11.0 | default | **37 / 41 / 49** | **1 / 1 / 1** |

Every accepted invalid vector is flagged `InfinityNormViolation`. The rejected valid vector is "signature that calls use_hint(1, 0)" (tcId 147, 161, 174).

`pqcrypto-mldsa` was run on the vectors that have an empty context (169, 199 and 230 vectors), through `verify_detached_signature`. Logs: [`results/run.log`](results/run.log), [`results/pqcrypto.log`](results/pqcrypto.log).

### Signatures with an out-of-bound `z`

Twenty signatures per parameter set, produced by a signer patched to emit only signatures with `γ1 − β ≤ ||z||∞ < γ1`.

| Verifier | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|---|---|---|---|
| PQClean avx2 | **20 of 20 accepted** | **20 of 20** | **20 of 20** |
| PQClean clean | 0 | 0 | 0 |
| liboqs 0.12.0 – 0.15.0, default build | **20 of 20 accepted** each | **20 of 20** each | **20 of 20** each |
| liboqs 0.12.0 – 0.15.0, portable | 0 | 0 | 0 |
| liboqs 0.16.0, default and portable | 0 | 0 | 0 |

### pqcrypto-dilithium 0.5.0

[`pqcrypto-dilithium`](https://crates.io/crates/pqcrypto-dilithium) is the archived predecessor of `pqcrypto-mldsa`. Its C code comes from pq-crystals at `918af1a`, a version of Dilithium from before the standard, and its AVX2 verifier has the same two defects. With the default features on x86_64 with AVX2, the crate's Rust interface selects that verifier at run time.

Linux x86_64, Intel Xeon Platinum 8573C, gcc 13.3, Rust 1.100. Per parameter set:

| Verifier | dilithium2 | dilithium3 | dilithium5 |
|---|---|---|---|
| Out-of-bound `z` (20 signatures with `γ1 − β ≤ ‖z‖∞ < γ1`), default features (AVX2) | **20 of 20 accepted** | **20 of 20** | **20 of 20** |
| Out-of-bound `z`, portable code | 0 | 0 | 0 |
| `use_hint` boundary case (2 valid signatures), default features (AVX2) | **2 of 2 rejected** | **2 of 2** | **2 of 2** |
| `use_hint` boundary case, portable code | 0 | 0 | 0 |

With the `avx2` feature disabled, the Rust interface uses the portable code and gives its results. As a control, every path accepted 20 signatures per parameter set made through the crate's own interface, and rejected each of them with one byte changed.

Caveats:

- The crate implements a pre-standard version of the scheme, so the Wycheproof ML-DSA vectors used above do not apply to it.
- The test signatures are built with the crate's own code. The out-of-bound ones come from its portable signer, patched in the same way as PQClean's above, with a key from the crate's own key generation.
- The `use_hint` signatures are our own construction, not public test vectors: an all-zero public key, `z = 0` and hints on coefficients where `w = 0`, so that the verifier has to compute `UseHint(1, 0)`. The crate's portable verifier accepts them.
- As above, creating such signatures for a real public key needs its private key. This is not a way to forge someone else's signature.

Mitigation: build the crate without the `avx2` feature, or move to a maintained implementation. The crate is archived and is marked unmaintained in [RUSTSEC-2024-0380](https://rustsec.org/advisories/RUSTSEC-2024-0380.html); RUSTSEC-2026-0586 covers only `pqcrypto-mldsa`.

To reproduce: `./run_pqcrypto_dilithium.sh` in `tests/mldsa-avx2-verifier` (needs gcc, perl and cargo). Log: [`results/pqcrypto-dilithium.log`](results/pqcrypto-dilithium.log), from our run of this script on 21 November 2026.

## Reproduce

```sh
cd tests/mldsa-avx2-verifier
./run.sh            # downloads Wycheproof, PQClean and liboqs 0.12.0 – 0.16.0, builds them, prints both tables
./run_pqcrypto.sh   # optional, needs cargo: checks the Rust crates pqcrypto-mldsa 0.1.2 and oqs 0.11.0
```

Needs git, cmake, make, gcc, python3 and perl on Linux x86_64 with AVX2. Everything is built under `$WORK` (default `~/pqc-field-notes-work`); nothing is installed system-wide.

## Root cause

In the affected code the verifier unpacks `z` and proceeds under the comment "shortness follows from unpacking". Unpacking only guarantees `|z| ≤ γ1`; the required bound is `γ1 − β`. The portable implementations call the norm check after unpacking.

- liboqs 0.15.0: `src/sig/ml_dsa/pqcrystals-dilithium-standard_ml-dsa-65_avx2/sign.c`
- PQClean: `crypto_sign/ml-dsa-65/avx2/sign.c` and `avx2/rounding.c`

## What to do

- **liboqs:** upgrade to 0.16.0 or later.
- **oqs (Rust):** 0.11.0 builds liboqs 0.13.0. Until a release bundles 0.16.0, link against a system liboqs 0.16.0 instead of the bundled copy.
- **PQClean, pqcrypto-mldsa:** both are archived. Move to a maintained implementation, or build without AVX2 (`pqcrypto-mldsa`: disable the `avx2` feature).
- **Anyone vendoring pq-crystals `avx2` code:** check that your copy includes upstream commits `d35ba3fe54` and `bba9534a3c`. Running the Wycheproof ML-DSA vectors against every optimized code path you ship will tell you.

## Timeline

| Date | Event |
|---|---|
| 3 June 2026 | Eric Biggers reports the missing norm check to pq-crystals; both defects fixed upstream the same day |
| 9 July 2026 | liboqs 0.16.0 released with mldsa-native as the ML-DSA implementation |
| August 2026 | PQClean archived |
| 19–20 November 2026 | We confirm the defects in liboqs 0.12.0 to 0.15.0, PQClean, pqcrypto-mldsa 0.1.2 and oqs 0.11.0 |
| 20 November 2026 | Public issue in liboqs ([#2721](https://github.com/open-quantum-safe/liboqs/issues/2721)); question upstream about a CVE ([pq-crystals/dilithium#113](https://github.com/pq-crystals/dilithium/issues/113)); request for a new release of the `oqs` crate ([liboqs-rust#320](https://github.com/open-quantum-safe/liboqs-rust/issues/320)) |
| 20 November 2026 | RustSec publishes [RUSTSEC-2026-0586](https://rustsec.org/advisories/RUSTSEC-2026-0586.html) for `pqcrypto-mldsa` |
| 21 November 2026 | We confirm both defects in `pqcrypto-dilithium` 0.5.0 |
| 22 November 2026 | RustSec publishes [RUSTSEC-2026-0593](https://rustsec.org/advisories/RUSTSEC-2026-0593.html) for `pqcrypto-dilithium` |

## Credit

The defects were found and reported upstream by Eric Biggers. The test vectors are from Project Wycheproof. This note covers only their presence in downstream software.

## Method

This analysis was designed, implemented and run with AI assistance (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs. The results above do not depend on that: `run.sh` reproduces them from public sources.
