# `mlkem` (npm): Wycheproof ML-KEM vectors against released versions

The test behind the note [`advisories/2026-mlkem-npm-dk-hash-check`](../../advisories/2026-mlkem-npm-dk-hash-check/). It installs several released versions of the npm package [`mlkem`](https://www.npmjs.com/package/mlkem) side by side and runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-KEM vectors (commit `65ca494727a5`) through the public interface of each: `deriveKeyPair`, `encap` with fixed randomness, and `decap`.

## Requirements

git, python3, node and npm. Everything is downloaded under `$WORK` (default `~/pqc-field-notes-work`).

## Run

```sh
./run.sh
MLKEM_VERSIONS="3.0.0 2.7.1" ./run.sh
```

## Expected output

One line per version and parameter set. 3.0.0 and 2.7.2: `INVALID ACCEPTED=0` and `VALID FAILED=0` everywhere. 2.7.1, 2.7.0 and 2.5.0: `expanded dk: 9 vectors, INVALID ACCEPTED=2`, the two vectors being "Decapsulation key with corrupted hash" and "Decapsulation key with corrupted embedded encapsulation key"; everything else as in the fixed versions.

Version 2.0.0 is not in the default list: its `deriveKeyPair` does not give the keys of the Wycheproof seed vectors, so the control (valid vectors must pass) fails for it and we draw no conclusion from that version. We did not investigate why.

The log of our run of 25 November 2026 (Node.js 24.19) is in [`advisories/2026-mlkem-npm-dk-hash-check/results/run.log`](../../advisories/2026-mlkem-npm-dk-hash-check/results/run.log).

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
