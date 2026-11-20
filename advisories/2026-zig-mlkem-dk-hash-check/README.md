# Zig standard library: ML-KEM decapsulation key import skips the hash check
## Summary

`std.crypto.kem.ml_kem` in the Zig standard library implements ML-KEM (FIPS 203). `SecretKey.fromBytes` does not perform the decapsulation key hash check described in FIPS 203 section 7.3: it does not compare the hash stored in the decapsulation key with the hash of the encapsulation key embedded in it. A decapsulation key whose stored hash or embedded encapsulation key has been altered is accepted, and `decaps` returns a shared secret.

Everything else we tested conforms: decapsulation from a seed, encapsulation with fixed randomness (including rejection of non-reduced encapsulation keys), and ML-DSA verification with and without context.

## Affected

| Zig | ML-KEM, expanded decapsulation key vectors |
|---|---|
| 0.16.0 | 2 invalid keys accepted per parameter set |
| 0.17.1 (latest release) | 2 invalid keys accepted per parameter set |
| 0.18.0-dev.1244+b5ffcbd70 | 2 invalid keys accepted per parameter set |

Not tested: 0.14 and 0.15, which have ML-KEM behind an earlier interface.

## How to reproduce

Wycheproof ML-KEM vectors (C2SP/wycheproof at `65ca494727a5`), files `mlkem_{512,768,1024}_semi_expanded_decaps_test.json`. Of the 9 vectors per parameter set, the two marked invalid are accepted:

- "Decapsulation key with corrupted hash"
- "Decapsulation key with corrupted embedded encapsulation key"

The test and the output of our run are in [`tests/zig-std`](../../tests/zig-std/).

## Where

`lib/std/crypto/ml_kem.zig`, `SecretKey.fromBytes` (lines 366–377 in 0.17.1). The function reads `sk`, `pk`, `hpk` and `z` from the buffer and returns. It checks that the embedded encapsulation key is reduced, but it does not compare `hpk` with the hash of `pk`.

## Impact

Low. The decapsulation key is the caller's own secret. FIPS 203 section 7.3 says that ML-KEM.Decaps "shall not be run with a decapsulation key or a ciphertext unless both have been checked", and that the key check "need not be performed by the decapsulating party, nor with every execution". So this is a conformance gap rather than a vulnerability: the library leaves the check to the caller. The other implementations we tested perform the check on import.

## Why there is no upstream report

The Zig project does not accept issues, patches or comments produced with language models. This work is AI-assisted, so we have not filed anything in their tracker. We record the result here instead.

## Method

The research strategy and the test code were designed and written with AI assistance, and the tests were run with AI tooling (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs.
