# Zig standard library: Wycheproof ML-KEM and ML-DSA vectors

Runs the [Wycheproof](https://github.com/C2SP/wycheproof) ML-KEM and ML-DSA vectors (commit `65ca494727a5`) against `std.crypto.kem.ml_kem` and `std.crypto.sign.mldsa`. `run.sh` downloads each Zig release from ziglang.org (checking the sha256 given by the download index), builds `wycheproof.zig` with the vectors embedded (`@embedFile`) and runs it.

## Requirements

Linux x86_64 with git, curl, python3 and tar (xz). Everything is downloaded under `$WORK` (default `~/pqc-field-notes-work`).

## Run

```sh
./run.sh                    # Zig 0.17.1 and 0.16.0, ReleaseSafe, -mcpu=native
./run.sh master             # the current development build
MODES="ReleaseSafe ReleaseFast Debug" CPUS="native baseline" ./run.sh 0.17.1
```

Zig 0.15.2 and earlier do not build the program (their ML-KEM API is different, and 0.13.0 has no ML-KEM).

## Expected output

For Zig 0.16.0 and 0.17.1, and for the development build 0.18.0-dev.1244 that we also tested, the decapsulation key import (`SecretKey.fromBytes`) accepts the two Wycheproof keys whose embedded hash or embedded encapsulation key was altered; everything else conforms:

```
Zig std ML-KEM-512   | seed: 200 accepted=0 failed=0 | encaps: 261 accepted=0 failed=0 | expanded dk: 9 accepted=2 failed=0
Zig std ML-DSA-44    vectors=180   INVALID ACCEPTED=0   valid rejected=0
      3   INVALID ACCEPTED  [expanded dk]   Decapsulation key with corrupted embedded encapsulation key InvalidDecapsulationKey
      3   INVALID ACCEPTED  [expanded dk]   Decapsulation key with corrupted hash InvalidDecapsulationKey
```

`results/run.log` is our run of `./run.sh 0.17.1 0.16.0`.

Not re-run after translation: the development build (`master`), which changes every day.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
