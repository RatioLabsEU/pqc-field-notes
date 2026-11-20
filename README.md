# PQC field notes · RatioLabs

Notes and reproducible tests from our review of post-quantum cryptography implementations (ML-KEM, ML-DSA).

We look for one thing: places where an implementation's behaviour departs from the standard. Our method is variant analysis and differential testing. We take a defect that has already been fixed somewhere, describe it as a pattern, and check whether the same pattern survives in other libraries, in other code paths of the same library, or in copies that were never updated.

Both notes so far say the same thing: a defect was fixed in one place, and releases that are still installed elsewhere never received the fix or an advisory.

Every result here comes with the code that produced it.

## Notes

| Date | Note | Summary |
|---|---|---|
| 2026-11 | [ML-DSA: an unfixed AVX2 verifier in liboqs 0.12–0.15, PQClean and two Rust crates](advisories/2026-mldsa-avx2-verifier/) | Two verifier defects fixed upstream in June 2026 are still present in downstream projects that copied the code earlier. Confirmed with the Wycheproof vectors |
| 2026-11 | [ML-KEM: keys that should be rejected are accepted by liboqs 0.12.0 and pqcrypto-mlkem 0.1.1](advisories/2026-mlkem-input-validation/) | Two packages built on reference ML-KEM code perform none of the FIPS 203 input checks |

## Tests

| Directory | What it does |
|---|---|
| [`tests/mldsa-avx2-verifier`](tests/mldsa-avx2-verifier/) | Runs the Wycheproof ML-DSA verification vectors, and signatures with an out-of-bound `z`, against liboqs, PQClean, pqcrypto-mldsa and oqs |
| [`tests/mlkem-input-validation`](tests/mlkem-input-validation/) | Runs the Wycheproof ML-KEM vectors against liboqs and pqcrypto-mlkem |

## How this work is done

The research strategy and the test code were designed and written with AI assistance, and the tests were run with AI tooling (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs.

We do not ask anyone to take an AI-assisted result on trust. Every claim in this repository is backed by a script that downloads the public sources, builds them and prints the numbers we report, and the logs of our own runs are included.

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
