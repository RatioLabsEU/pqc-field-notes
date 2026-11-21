# ML-KEM: encapsulation keys that should be rejected are accepted by @noble/post-quantum before 0.6.0

**Status:** fixed in 0.6.0 (March 2026). This note documents earlier releases, which are still widely installed. The maintainer considers them unsupported and plans no further action.

## Summary

FIPS 203 says that a key must have passed two checks before it is used. The party that uses the key need not be the one that checks it (sections 7.2 and 7.3 allow the assurance to come from elsewhere), but a library that does not check leaves the job to every caller:

- **Encapsulation key check** (section 7.2): decoding the key's 12-bit coefficients and encoding them again must give back the same bytes. This rejects keys with coefficients that are not reduced modulo q.
- **Decapsulation key check** (section 7.3): the hash of the encapsulation key stored inside the decapsulation key must match.

Running the Wycheproof ML-KEM vectors against released versions of `@noble/post-quantum` shows that these checks did not work before 0.6.0:

| Software | Versions | Encapsulation key check | Decapsulation key check | Fixed in |
|---|---|---|---|---|
| [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum) (JavaScript) | 0.5.0 to 0.5.4 | Has no effect | Works | 0.6.0 |
| | 0.4.1 and earlier | Has no effect | Missing | 0.6.0 |

The current release (0.7.1) passes every vector.

## The @noble/post-quantum case: a check that could not fail

The check is present in the source of the affected versions. In 0.5.4, `encapsulate` reads:

```js
const eke = publicKey.subarray(0, 384 * opts.K);
const ek = KPKESecretCoder.encode(KPKESecretCoder.decode(copyBytes(eke)));
if (!equalBytes(ek, eke)) { ... throw new Error('ML-KEM.encapsulate: wrong publicKey modulus'); }
```

The same lines are in 0.6.1. What changed between them is the coder: before 0.6.0 its `decode` did not reduce coefficients, so decoding and re-encoding always returned the input and the comparison could never fail. The 0.6.x source says so in a comment: without the change, the "modulus check in encapsulate() becomes a no-op for malformed coefficients like 4095".

Reading the code is not enough to see this kind of defect, because the check is there. It shows up only when the code is run on an input that must be rejected.

## How widely the affected versions are installed

npm downloads of `@noble/post-quantum` for the week of 12–18 November 2026 (`api.npmjs.org/versions`):

| Versions | Downloads | Share |
|---|---|---|
| All | 1,739,995 | 100 % |
| Before 0.6.0 | 970,881 | 56 % |
| of which 0.5.4 | 872,250 | 50 % |
| Before 0.5.0 | 90,660 | 5 % |

The project's security policy supports only the latest release, and it has no published advisory for this.

## Impact

- An affected implementation accepts an encapsulation key that is not in canonical form. It does not disclose a key or a shared secret to anyone.
- The check exists so that a key has exactly one valid encoding and all implementations agree on which keys are valid. Without it, an affected implementation and a conforming one can disagree.
- The library offers the check and it has no effect: a caller relying on it gets no check at all.

## Results

Node.js 24.19 (the test is pure JavaScript). The full log of our run of 21 November 2026 is in [`results/run.log`](results/run.log).

[C2SP/wycheproof](https://github.com/C2SP/wycheproof) at `65ca494727a5`. Encapsulation vectors: 261, 265 and 269 for ML-KEM-512, -768 and -1024. Expanded decapsulation key vectors: 9 per parameter set.

### @noble/post-quantum

| Version | Released | Invalid encapsulation keys accepted (512 / 768 / 1024) | Invalid decapsulation keys accepted |
|---|---|---|---|
| 0.7.1 | Aug 2026 | 0 / 0 / 0 | 0 |
| 0.6.1 | Apr 2026 | 0 / 0 / 0 | 0 |
| 0.6.0 | Mar 2026 | 0 / 0 / 0 | 0 |
| 0.5.4 | Dec 2025 | **108 / 112 / 116** | 0 |
| 0.5.0 | | **108 / 112 / 116** | 0 |
| 0.4.1 | Apr 2025 | **108 / 112 / 116** | **2** per parameter set |
| 0.3.1 | Jan 2025 | **108 / 112 / 116** | **2** per parameter set |
| 0.2.1 | Nov 2024 | **108 / 112 / 116** | **2** per parameter set |

The accepted encapsulation keys are the vectors flagged `ModulusOverflow` and "Public key not reduced". The accepted decapsulation keys are "Decapsulation key with corrupted hash" and "Decapsulation key with corrupted embedded encapsulation key". Every valid vector gives the expected ciphertext and shared secret in every version.

## Reproduce

```sh
cd tests/noble-mlkem-modulus-check
./run.sh
```

Needs git, python3, node and npm. Everything is downloaded under `$WORK` (default `~/pqc-field-notes-work`).

## What to do

- **@noble/post-quantum:** upgrade to 0.6.0 or later. If a dependency pins an older version, check which one with `npm ls @noble/post-quantum`.
- **Anyone shipping ML-KEM:** run the Wycheproof encapsulation vectors against the exact build you ship. A check that is present in the source can still be ineffective.

## Timeline

| Date | Event |
|---|---|
| March 2026 | @noble/post-quantum 0.6.0 released; the coder now reduces coefficients, which makes the check effective |
| 20 November 2026 | We find the defect in earlier releases while running Wycheproof against released versions, and report it to the maintainer privately |
| 20 November 2026 | The maintainer replies that it is low severity, affects only unsupported versions, and that no action will be taken; the project's security policy supports only the latest release |

## Credit

The test vectors are from Project Wycheproof. The fix in @noble/post-quantum was made by its maintainer before we looked; this note covers only the releases that predate it.

## Method

The research strategy and the test code were designed and written with AI assistance, and the tests were run with AI tooling (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs. The results above do not depend on that: `run.sh` reproduces them from public sources.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
