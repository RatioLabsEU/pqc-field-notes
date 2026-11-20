# Python packages: Wycheproof ML-KEM and ML-DSA vectors

Runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-KEM and ML-DSA vectors (commit `65ca494727a5`) against PyPI packages with their own implementation, through their public interface:

| Argument | Package | Version |
|---|---|---|
| `pqcrypto` | `pqcrypto` (ML-KEM and ML-DSA) | 1.0.0 |
| `keeper` | `keeper-mlkem` | 1.0.2 |
| `dilithium` | `dilithium-py` | 1.5.1 |
| `kyber` | `kyber-py` | 1.2.0 |
| `mlkem` | `mlkem` | 0.2.0 |
| `pykyber` | `pykyber` | 2.0.0 |
| `diagnose` | checks that explain the pqcrypto and keeper-mlkem results (run after those two and dilithium-py) | |

Each package is installed in its own virtual environment from the prebuilt wheel pip picks (`--only-binary`). For packages without key generation from a seed, the "seed" vectors are decapsulated with an expanded key derived from the seed by kyber-py (its encapsulation key is checked against the vector first); this is marked `seed (derived dk)`. `sampling_bytes.py` is part of the diagnosis: it computes how many SHAKE128 bytes SampleNTT needs for each key in the vectors.

## Requirements

Linux x86_64 with git, curl and python3 with venv. keeper-mlkem 1.0.2 only ships wheels up to CPython 3.13, so a CPython 3.13 is needed for it: set `PYTHON313` to its path (default `python3.13`). Everything is downloaded under `$WORK` (default `~/pqc-field-notes-work`).

## Run

```sh
./run.sh                                  # the six packages
PYTHON313=/usr/bin/python3.13 ./run.sh keeper kyber
./run.sh pqcrypto keeper dilithium diagnose
```

## Expected output

- keeper-mlkem 1.0.2: `encaps: ... INVALID ACCEPTED=108` (512), `112` (768) and `116` (1024): every encapsulation key with an unreduced coefficient is accepted. The diagnosis shows why: the module decodes the key without reducing it, so re-encoding always gives back the same bytes.
- pqcrypto 1.0.0: `valid rejected=1` per ML-DSA parameter set, the "longest context" vector (255 bytes). The diagnosis shows that its verifier rejects contexts of 254 and 255 bytes.
- dilithium-py, kyber-py, mlkem and pykyber: no invalid vector accepted and no valid vector failed.

`results/run.log` is our run of `./run.sh keeper kyber` followed by `./run.sh pqcrypto dilithium mlkem pykyber diagnose`.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
