# ML-KEM: `mlkem` (npm) before 2.7.2 did not check the hash inside the decapsulation key

**Status:** fixed in 3.0.0 and 2.7.2 (22 November 2026), two days after our report.

## Summary

FIPS 203 says that a decapsulation key must have passed a check before it is used (section 7.3): the hash of the encapsulation key that is stored inside the decapsulation key must match a hash recomputed from the encapsulation key embedded in it. The party that uses the key need not be the one that checks it, but a library that does not check leaves the job to every caller.

In the npm package [`mlkem`](https://www.npmjs.com/package/mlkem) (repository `dajiaji/crystals-kyber-js`) up to 2.7.1, `decap(ct, sk)` checked the lengths of its inputs and not that hash. A decapsulation key whose stored hash, or whose embedded encapsulation key, had been altered was accepted and a shared secret was returned.

The encapsulation key check (section 7.2) was already implemented and worked: every Wycheproof vector with a non-reduced encapsulation key is rejected by all the versions we tested.

| Versions | Decapsulation key check | Encapsulation key check |
|---|---|---|
| 3.0.0, 2.7.2 | Works | Works |
| 2.7.1, 2.7.0, 2.5.0 | Missing | Works |

We did not test versions between 2.5.0 and 2.7.0, or before 2.5.0.

## Impact

Low. The decapsulation key is the caller's own secret, so in normal use this is not something a remote party can reach, and nothing is disclosed. The check exists to detect a corrupted or inconsistent key before it is used.

## Results

[C2SP/wycheproof](https://github.com/C2SP/wycheproof) at `65ca494727a5`, Node.js 24.19. Per parameter set (ML-KEM-512 / -768 / -1024): 200 / 201 / 202 vectors that generate the key from a seed and decapsulate, 261 / 265 / 269 encapsulation vectors, and 9 vectors with an expanded decapsulation key.

| Version | Released | Invalid decapsulation keys accepted | Any other discrepancy |
|---|---|---|---|
| 3.0.0 | 22 Nov 2026 | 0 | None |
| 2.7.2 | 22 Nov 2026 | 0 | None |
| 2.7.1 | 17 Nov 2026 | **2** per parameter set | None |
| 2.7.0 | Mar 2026 | **2** per parameter set | None |
| 2.5.0 | Aug 2025 | **2** per parameter set | None |

The two accepted vectors are "Decapsulation key with corrupted hash" and "Decapsulation key with corrupted embedded encapsulation key". Every valid vector gives the expected ciphertext and shared secret in every version in the table. Full log: [`results/run.log`](results/run.log).

## Reproduce

```sh
cd tests/mlkem-npm-dk-hash-check
./run.sh
```

## What to do

Upgrade to 3.0.0, or to 2.7.2 if you cannot move to version 3 yet. `npm ls mlkem` shows whether a dependency pins an older one.

## Timeline

| Date | Event |
|---|---|
| 20 November 2026 | We find it in 2.7.1, then the current release, with the Wycheproof vectors, and report it privately to the maintainer by mail and as a GitHub security advisory |
| 21 November 2026 | The maintainer confirms it, rates it as low impact as we did, and opens a public pull request with the fix and regression tests |
| 22 November 2026 | 3.0.0 and 2.7.2 are released with the fix; the advisory is closed |
| 25 November 2026 | We run the same vectors against the fixed releases: no discrepancy |

## Credit

The test vectors are from Project Wycheproof. The fix is by the maintainer of `mlkem`, who handled the report within two days.

## Method

The research strategy and the test code were designed and written with AI assistance, and the tests were run with AI tooling (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs. The results above do not depend on that: `run.sh` reproduces them from public sources.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
