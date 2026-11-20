# Other architectures: Wycheproof ML-KEM and ML-DSA vectors under qemu-user

Runs the same test programs as on x86_64 on other processor architectures, with cross compilation and user-mode emulation (qemu-user), to reach the architecture-specific code paths:

| Argument | Library | Architectures and CPU models |
|---|---|---|
| `gmsm` | Go module `github.com/emmansun/gmsm` v0.45.4, with its assembly and with `-tags purego` | arm64; riscv64 (V with VLEN 128 and 256, built with `GORISCV64=rva23u64`, and a CPU without V); ppc64le (POWER10, POWER9, POWER8); loong64 (la464); s390x as a big-endian control |
| `leancrypto` | leancrypto 1.9.1, default and C-only builds | aarch64 (`max` and Cortex-A53); riscv64 (V with VLEN 128 and 256, and a CPU without V) |
| `zig` | Zig 0.17.1 standard library | aarch64; riscv64 (rv64gc and rv64gc+v); s390x (with and without the vector facility) |

The programs (`go/`, `mlkem_leancrypto.c`, `mldsa_leancrypto.c` with `mlkem_harness.h` / `mldsa_harness.h`, `wycheproof.zig`) are the ones in `../rust-go`, `../c-libraries` and `../zig-std`, unmodified. Every run goes through `qemu -d in_asm`, and the trace is used to list which architecture-specific functions actually ran (gmsm `.s` functions, leancrypto armv8/RVV functions, vector instructions in the Zig code).

## Requirements

Linux x86_64 with git, curl, python3 with venv, perl, Go 1.27 or later (gmsm's riscv64 ML-KEM assembly is behind a `go1.27` build tag), qemu-user (`qemu-aarch64`, `qemu-riscv64`, `qemu-ppc64le`, `qemu-loongarch64`, `qemu-s390x`), `gcc-aarch64-linux-gnu` and `gcc-riscv64-linux-gnu` with their `libc6-dev-*-cross`, and `binutils-aarch64-linux-gnu`, `binutils-riscv64-linux-gnu`, `binutils-s390x-linux-gnu`. On Ubuntu 24.04 these are packages of the same names (`qemu-user` for qemu). Everything is downloaded and built under `$WORK` (default `~/pqc-field-notes-work`).

## Run

```sh
./run.sh                    # gmsm leancrypto zig
ARCHS="arm64 s390x" ./run.sh gmsm
```

## Expected output

- gmsm: the same result as on x86_64 on every architecture and CPU model (`valid rejected=3` per ML-DSA set, the empty-message vectors), except ppc64le with `-cpu power8`: the assembly build stops with `SIGILL: illegal instruction` at `MTVSRDD` (`field_ppc64le.s`), a POWER9 instruction, although Go's default target is POWER8. The `purego` build runs on POWER8.
- leancrypto: no invalid vector accepted and no valid vector failed, on every build and CPU model.
- Zig: the same result as on x86_64 (`expanded dk: 9 accepted=2` per ML-KEM set; ML-DSA conforms) on every target, including big-endian s390x.

Re-run after translation; the output is in `results/run.log`. The counts match our earlier run.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
