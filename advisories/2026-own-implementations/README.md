# ML-KEM and ML-DSA outside the large C libraries: 30 implementations

Two of the ten implementations with findings are still in coordinated disclosure and are not in this note. They will be added when their dates pass.

## Summary

Language runtimes and package registries now carry many independent implementations of ML-KEM (FIPS 203) and ML-DSA (FIPS 204). We ran the Wycheproof vectors (C2SP/wycheproof at `65ca494727a5`) against 30 of them through their public interfaces.

Twenty gave the expected result for every vector. Ten did not. All the discrepancies are in current releases, or in code not yet released, and all are low severity: none discloses key material. Eight of the ten are described below.

## Conformant

| Implementation | Version | Notes |
|---|---|---|
| OpenJDK (Eclipse Temurin) | 24.0.2, 25.0.5, 26.0.2, 27.0.1 | Interpreter, default with warm-up, fully compiled, without AVX-512, without AVX |
| Linux kernel, `lib/crypto/mldsa.c` | v7.0, v7.3.5, v7.4-rc3 | Verification only, empty context; built in user space with the kernel's own SHA-3 |
| leancrypto | 1.9.1 | With acceleration and in plain C; also on 64-bit ARM and RISC-V |
| strongSwan, `ml` plugin | 6.1.0 | Only key acceptance can be tested through its interface |
| `cryptoxide` (Rust) | 0.6.7 | |
| `purecrypto` (Rust) | 0.10.6 | |
| `macula-mlkem`, `macula-mldsa` (Rust) | 0.3.0 | As far as the public interface allows |
| `kyber-k2so` (Go) | v1.1.1 | |
| `tink-go`, `signature/mldsa` | v2.9.0 | No context parameter; 7 vectors per set not applicable |
| `kyber-py` (Python) | 1.2.0 | |
| `dilithium-py` (Python) | 1.5.1 | |
| `mlkem` (PyPI) | 0.2.0 | |
| `pykyber` (Python) | 2.0.0 | |
| `pqcrypto` (Dart) | 0.4.4 | Accepts a 32-byte seed by design, generating the other half at random |
| `KyberNET` (NuGet) | 1.0.3 | Rejects all-zero randomness as a generator failure; 30 vectors per set cannot be run |
| `@theqrl/mldsa87` (npm) | 2.2.0 | |
| `noqtis` (npm) | 0.2.2 | |
| SwiftKyber, SwiftDilithium | 3.5.0, 3.6.0 | On Linux, with a platform shim that only supplies system randomness |
| `paragonie/pqcrypto_compat` (PHP) | 0.3.4 | |

## Discrepancies

### 1. The decapsulation key hash check is missing

FIPS 203 section 7.3 asks that the hash of the encapsulation key stored inside the decapsulation key be compared with the hash of the embedded encapsulation key. In each of these, the two Wycheproof vectors per parameter set with a corrupted hash or a corrupted embedded key are accepted and a shared secret is returned.

| Implementation | Version | Where |
|---|---|---|
| libsodium, ML-KEM-768 | 1.0.22 and master | `mlkem768_ref_dec` in `src/libsodium/crypto_kem/mlkem768/ref/kem_mlkem768_ref.c` uses the stored hash without comparing it |
| Zig standard library | 0.16.0, 0.17.1, 0.18.0-dev | `SecretKey.fromBytes` in `lib/std/crypto/ml_kem.zig`; see `2026-zig-mlkem-dk-hash-check` |
| `cipherlib` (Dart) | 0.7.2 | `lib/src/algorithms/mlkem/mlkem.dart`; the source says the check is not done and carries a note to add it |
| `@umbra-privacy/quick-mlkem768` (npm) | 0.1.1 | `decapsulate` in `dist/mlkem768.js` |

FIPS 203 says that ML-KEM.Decaps "shall not be run with a decapsulation key or a ciphertext unless both have been checked", and adds that the key check "need not be performed by the decapsulating party, nor with every execution": the assurance may come from elsewhere. So an implementation that skips the check is leaving it to the caller. The decapsulation key is also the caller's own secret. We therefore describe this as a conformance gap. The other implementations we tested perform the check on import.

### 2. `keeper-mlkem` 1.0.2 (Python): the encapsulation key check cannot fail

`encaps()` accepts 108 / 112 / 116 of the invalid Wycheproof encapsulation keys (ML-KEM-512 / -768 / -1024). The modulus check of FIPS 203 section 7.2 (which the standard requires before a key is used, though it too may be assured by other means) is present in `mlkem/mlkem_core.py`: it decodes the key, encodes it again and compares. But `byteDecodePoly` in `mlkem/fastmathmodule.c` does not reduce the decoded coefficients modulo q, so the round trip always returns its input.

Reading the source shows a check. Running it with an input that must fail shows there is none.

The package is required by Keeper Commander on Python 3.11 and later, where the encapsulation keys come from a table shipped with the program, so a third party cannot supply one.

### 3. Nettle, ML-KEM on the master branch (not yet released)

Commit `10d33c6`. `ml_kem_768_encap`, `ml_kem_768_decap` and the 1024 variants return `void`, so they cannot refuse a key: 112 / 116 invalid encapsulation keys and 2 invalid decapsulation keys per set go through. All valid vectors give the expected result. Reported to the maintainer by mail on 20 November 2026, before the release that will carry this code.

### 4. `gmsm` (Go) v0.45.4

- **ML-DSA refuses the empty message.** `SignMessage` returns an error and `VerifyWithOptions` returns false when the message has length zero. FIPS 204 sets no lower bound. Three valid vectors per parameter set are rejected. [Issue 680](https://github.com/emmansun/gmsm/issues/680).
- **ML-KEM on PowerPC uses a POWER9 instruction.** `mlkem/field_ppc64le.s` uses `MTVSRDD` while the documentation states that POWER8 is enough. Under an emulated POWER8 the program stops with an illegal instruction. Not a cryptographic difference, and not tested on real hardware. [Issue 681](https://github.com/emmansun/gmsm/issues/681).

Everything else in `gmsm` is conformant, with assembly and with the pure Go build, on amd64, arm64, riscv64, ppc64le (POWER9 and later), loong64 and s390x.

### 5. `pqcrypto` 1.0.0 (PyPI): reported by someone else

ML-DSA rejects valid signatures whose context is 254 or 255 bytes long. This was reported on 27 October 2026 in [backbone-hq/pqcrypto-rust#1](https://github.com/backbone-hq/pqcrypto-rust/issues/1), before we ran our tests. We mention it only because it appears in our results; the finding is not ours.

## What repeats

1. The decapsulation key hash check is missing (four implementations here).
2. The encapsulation key check is missing, or present but ineffective.
3. A legitimate edge case is refused: the empty message, the longest context.

## Reports

- `gmsm` was told through public issues, and the Nettle maintainer by mail.
- Zig and libsodium do not accept reports produced with AI assistance. This work is AI-assisted, so we filed nothing with them, and this note is the record.
- Keeper Security takes reports only through a bounty platform that requires an account and its own terms. For a low-severity finding we did not consider that proportionate.
- `cipherlib` documents the gap in its own source; `quick-mlkem768` has no public repository or contact.

Maintainers of any of these projects are welcome to write to us at info@ratiolabs.eu.

## How to reproduce

Each directory has a `run.sh` that downloads the vectors and the software, builds it and prints the tables, and a `results/` directory with the output of our run.

| Directory | Covers |
|---|---|
| [`tests/openjdk`](../../tests/openjdk/) | OpenJDK |
| [`tests/zig-std`](../../tests/zig-std/) | Zig standard library |
| [`tests/c-libraries`](../../tests/c-libraries/) | libsodium, leancrypto, the Linux kernel verifier, strongSwan, Nettle |
| [`tests/rust-go`](../../tests/rust-go/) | `cryptoxide`, `purecrypto`, `macula`, `gmsm`, `kyber-k2so`, `tink-go` |
| [`tests/python`](../../tests/python/) | `keeper-mlkem`, `kyber-py`, `dilithium-py`, `mlkem`, `pykyber`, `pqcrypto` |
| [`tests/small-packages`](../../tests/small-packages/) | The Dart, NuGet, npm, Swift and PHP packages |
| [`tests/other-architectures`](../../tests/other-architectures/) | `gmsm`, leancrypto and Zig under emulation |

## Limits

- ML-DSA vectors test verification only. Signing and key generation were not tested.
- Several interfaces cannot fix the encapsulation randomness or import a key from a seed. There, only key acceptance was checked.
- The architectures other than x86-64 were run under emulation.

## Method

The research strategy and the test code were designed and written with AI assistance, and the tests were run with AI tooling (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs. Findings reported by automated runs were re-checked separately before being recorded here.
