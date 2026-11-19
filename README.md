# RatioLabs PQC Lab

Notes and reproducible tests from our review of post-quantum cryptography implementations (ML-KEM, ML-DSA).

We look for one thing: places where an implementation's behaviour departs from the standard. Our method is variant analysis and differential testing. We take a defect that has already been fixed somewhere, describe it as a pattern, and check whether the same pattern survives in other libraries, in other code paths of the same library, or in copies that were never updated.

Every result here comes with the code that produced it.

## Notes

| Date | Note | Summary |
|---|---|---|
| 2026-11 | [ML-DSA: an unfixed AVX2 verifier in liboqs 0.12–0.15, PQClean and pqcrypto-mldsa](advisories/2026-mldsa-avx2-verifier/) | Two verifier defects fixed upstream in June 2026 are still present in three downstream projects. Confirmed with the Wycheproof vectors |

## Tests

| Directory | What it does |
|---|---|
| [`tests/mldsa-avx2-verifier`](tests/mldsa-avx2-verifier/) | Runs the Wycheproof ML-DSA verification vectors, and signatures with an out-of-bound `z`, against liboqs, PQClean and pqcrypto-mldsa |

## How we handle findings

- We test only local builds of open-source code. We do not test other people's systems.
- A finding is reported to the maintainers first, through the channel their security policy names.
- If a project's policy asks for public reports (for example, for issues that only affect unsupported versions), we follow it.
- We publish what is needed to reproduce a result and nothing aimed at exploiting a deployed system.
- When a defect was found by someone else, we say so and link to the original report.

## Contact

info@ratiolabs.eu

## License

Code in this repository is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu)
