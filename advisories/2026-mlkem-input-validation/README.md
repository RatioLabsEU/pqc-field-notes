# ML-KEM: keys that should be rejected are accepted by liboqs 0.12.0 and pqcrypto-mlkem 0.1.1

**Status:** liboqs fixed this in 0.13.0. `pqcrypto-mlkem` is archived and will not be fixed.

## Summary

FIPS 203 requires an implementation to check its inputs before running ML-KEM:

- **Encapsulation key check** (section 7.2): decoding the key's 12-bit coefficients and encoding them again must give back the same bytes. This rejects keys with coefficients that are not reduced modulo q.
- **Decapsulation key check** (section 7.3): the hash of the encapsulation key stored inside the decapsulation key must match.

Two released packages perform neither check. Both use reference-style ML-KEM code that leaves input checking to the caller, and neither adds the checks itself:

| Software | Versions | Underlying ML-KEM code | Fix |
|---|---|---|---|
| [liboqs](https://github.com/open-quantum-safe/liboqs) | 0.12.0 | pq-crystals reference | 0.13.0 (moved to mlkem-native, which performs both checks) |
| [pqcrypto-mlkem](https://crates.io/crates/pqcrypto-mlkem) (Rust) | 0.1.1 | PQClean | None: archived |

## Impact

- An affected implementation accepts an encapsulation key that is not in canonical form, or a decapsulation key whose embedded hash or public key has been altered. It does not disclose a key or a shared secret to anyone.
- The checks exist so that a key has exactly one valid encoding and all implementations agree on which keys are valid. Without them, an affected implementation and a conforming one can disagree.
- It is a FIPS 203 non-conformance.

## Results

Linux x86_64, gcc 13.3, Rust 1.100. Full log in [`results/`](results/).

[C2SP/wycheproof](https://github.com/C2SP/wycheproof) at `65ca494727a5`. Encapsulation vectors: 261, 265 and 269 for ML-KEM-512, -768 and -1024. Expanded decapsulation key vectors: 9 per parameter set.

| Implementation | Invalid encapsulation keys accepted (512 / 768 / 1024) | Invalid decapsulation keys accepted |
|---|---|---|
| liboqs 0.12.0 | **108 / 112 / 116** | **2** per parameter set |
| liboqs 0.13.0 | 0 / 0 / 0 | 0 |
| pqcrypto-mlkem 0.1.1 | **108 / 112 / 116** | **2** per parameter set |

The accepted encapsulation keys are the vectors flagged `ModulusOverflow` and "Public key not reduced". The accepted decapsulation keys are "Decapsulation key with corrupted hash" and "Decapsulation key with corrupted embedded encapsulation key". Both packages take keys as fixed-length byte strings, so the vectors with a key of the wrong length do not reach the ML-KEM code. Every valid vector is handled correctly.

## Reproduce

```sh
cd tests/mlkem-input-validation
./run.sh
```

Needs git, python3, cmake, make and gcc; cargo for the `pqcrypto-mlkem` part. Everything is built under `$WORK` (default `~/pqc-lab-work`).

## What to do

- **liboqs:** upgrade to 0.13.0 or later for this issue, and to 0.16.0 for the [ML-DSA verifier issue](../2026-mldsa-avx2-verifier/).
- **pqcrypto-mlkem:** move to a maintained implementation.
- **Anyone wrapping reference ML-KEM code:** the reference code does not check its inputs. If the wrapper does not, nothing does. The Wycheproof encapsulation vectors show it in seconds.

## Timeline

| Date | Event |
|---|---|
| April 2025 | liboqs 0.13.0 released with mlkem-native for ML-KEM |
| 2026 | The `pqcrypto` crates are archived |
| 20 November 2026 | We run Wycheproof against released versions and record the results above |

## Credit

The test vectors are from Project Wycheproof.

## Method

This analysis was designed, implemented and run with AI assistance (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs. The results above do not depend on that: `run.sh` reproduces them from public sources.
