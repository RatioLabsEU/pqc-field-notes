# SLH-DSA interoperability: libbitcoinpqc, btx and PQMagic against OpenSSL

Checks whether SLH-DSA (FIPS 205) signatures made by a library verify with a conforming implementation, and the other way round, and runs the NIST [ACVP](https://github.com/usnistgov/ACVP-Server) SLH-DSA vectors (commit `975de31eb83d`) through the library's public interface. The conforming implementation is OpenSSL at commit `354f1cf64842` of its development branch (version string 4.2.0-dev), built from source. The `openssl` step runs the same vectors through OpenSSL with the same harness, as a check of the vectors and of the harness.

| Argument | Library | Commit | Parameter sets |
|---|---|---|---|
| `openssl` | OpenSSL | `354f1cf64842` | the 12 of FIPS 205 |
| `bitcoinpqc` | libbitcoinpqc (`cryptoquick/libbitcoinpqc`), and a CONTROL build of it | `fc08c05214d8`, `main`, 3 November 2026 | SLH-DSA-SHA2-128s, the only one it offers |
| `btx` | the copy of libbitcoinpqc in btx (`btxchain/btx`, `src/libbitcoinpqc`) | `074dac167c26`, 15 November 2026 | SLH-DSA-SHAKE-128s, the only one it offers |
| `pqmagic` | PQMagic (`pqcrypto-cn/PQMagic`), built with SLH-DSA only and the "simple" thash | `42f5b6e6fe7e`, `main`, 29 October 2026 | the 12 of FIPS 205 (its SM3 sets are not part of FIPS 205 and are left out) |

The programs, all on the public interface of each library:

- **`interop_slhdsa.c`**, built with an adapter (`adapter_bitcoinpqc.h`, `adapter_btx.h`, `adapter_pqmagic.h`). For each parameter set and three messages (empty, `abc`, 200 fixed bytes), each with a new key from the library:
  - controls: the library verifies its own signature (`C1`) and rejects it with one byte changed (`C1n`); OpenSSL verifies its own signature made with its own key (`C2`). If a control fails, the program says that the result is not valid. `C2k` (OpenSSL signs with the library's private key and verifies with the library's public key) depends on the library's key format and is not a pure control.
  - the questions: OpenSSL verifies the library's signature as pure SLH-DSA with an empty context (`I1`); the library verifies OpenSSL's pure signature (`I3`); OpenSSL, given the seed of the library's key (SK.seed ‖ SK.prf ‖ PK.seed), generates the same public and private key (`K1`).
  - diagnostics: OpenSSL verifies the library's signature through its internal interface, with no prefix (`I2`); the library verifies a signature that OpenSSL made through its internal interface (`I4`); the library verifies OpenSSL's pure signature when the message is given to it as `0x00 ‖ 0x00 ‖ M` (`I5`). If these pass while `I1` and `I3` fail, the only difference is the FIPS 205 prefix `0x00 ‖ len(ctx) ‖ ctx`. If they fail too, the signature core differs from FIPS 205.
- **`acvp_lib.c`** with the harness `slhdsa_harness.h` and the same adapters: the ACVP keyGen and sigVer vectors, converted to text by `acvp_to_text.py`. In mode `direct`, the internal-interface sigVer vectors are passed to the library's verification as given, and the external pure ones only when their context is empty. In mode `emulated`, every external pure sigVer vector is passed with the prefix `0x00 ‖ len(ctx) ‖ ctx` built by the program in front of the message: this measures whether the core is the FIPS 205 one even though the library does not add the prefix.
- **`slhdsa_openssl.c`**: the OpenSSL adapter for the harness.

**CONTROL** is a copy of libbitcoinpqc with one line changed: line 59 of `sphincsplus/ref/fors.c` is replaced by the corresponding line of sphincsplus' `bas/fips205` branch (`ef36d20ff358`), which reads the FORS indices in the FIPS 205 bit order. It is not the published library. It shows that the test programs are not what fails, and it attributes the difference to that line.

**btx** takes a flag in its signing and verification functions that selects the FIPS 205 FORS order, and its node adds the prefix `0x00 ‖ 0x00` when the corresponding rule is active. The adapter has three modes (`BTX_MODE`): `legacy` (flag off, message as given), `fips205` (flag on, prefix added as the node does) and `fips205-core` (flag on, message as given, for the ACVP vectors).

What the interfaces do not let us test:

- None of the three libraries lets the caller fix the signing randomness, so the ACVP sigGen vectors are not run.
- None takes a context string. In `direct` mode, external pure vectors with a non-empty context count as `no interface`. The pre-hash (HashSLH-DSA) vectors count as `no interface` everywhere, including OpenSSL, whose documentation says it does not support pre-hash SLH-DSA.
- In `direct` mode, the external pure line uses the single vector of the group that has an empty context, passed without the prefix. For a library that does not add the prefix, the result only reflects whether that vector is valid or invalid; the `emulated` mode is the meaningful one for external pure.
- PQMagic's key generation from a seed (`..._sign_seed_keypair`) is exported by the library and declared in `sig/slh_dsa/std/api.h`, but not in its public header `include/pqmagic_api.h`. The keyGen vectors use it.
- libbitcoinpqc's key generation takes 128 bytes of randomness, of which the first 3n are the FIPS 205 seed. The adapter passes the seed followed by zeros.
- PQMagic's header says its verification returns 0 or 1; it returns 0 for a valid signature and −1 otherwise. The adapters take 0 as valid, and each interop block prints the value returned for a good and for an altered signature.

## Requirements

Linux x86_64 with git, cmake (with ctest), make, gcc, perl and python3, and network access: libbitcoinpqc's CMake build downloads libsecp256k1 v0.7.1 itself. Everything is downloaded and built under `$WORK/slhdsa-interop` (default `WORK=~/pqc-field-notes-work`); nothing is installed system-wide.

## Run

```sh
./run.sh                       # openssl bitcoinpqc btx pqmagic
./run.sh bitcoinpqc pqmagic    # some of them; the fetch and build steps always run, and reuse what is built
```

## Expected output

- `openssl`: in each of the 12 parameter sets, `keyGen NIST vectors=10 correct=10`, and `sigVer external/pure NIST` and `sigVer internal/none NIST` with `vectors=14 correct=14`. The pre-hash group shows `no interface=14`.
- `bitcoinpqc`: controls `3/3`, `K1 3/3`, and `0/3` for `I1`, `I3`, `I2`, `I4` and `I5`. ACVP: `keyGen ... correct=10`; `sigVer internal/none ... valid rejected=2` (direct) and `sigVer external/pure ... valid rejected=2` (emulated), no invalid vector accepted. CONTROL: `I2`, `I4` and `I5` at `3/3`, `I1` and `I3` still `0/3`, and `correct=14` in both ACVP modes.
- `btx`: mode `legacy` behaves like libbitcoinpqc (`I1` and `I3` `0/3`; ACVP `valid rejected=2`). Mode `fips205`: `I1 3/3` and `I3 3/3`. Mode `fips205-core`: `sigVer internal/none ... correct=14` (direct) and `sigVer external/pure ... correct=14` (emulated).
- `pqmagic`: in each of the 12 parameter sets, controls `3/3`, `K1 3/3`, `I1` and `I3` `0/3`, `I2`, `I4` and `I5` `3/3`; ACVP `keyGen ... correct=10`, `sigVer internal/none ... correct=14` (direct) and `sigVer external/pure ... correct=14` (emulated).

## Results

`results/` holds the logs of a run of the code in this directory, `./run.sh` with no arguments, on 21 November 2026 on a GitHub Codespace (Linux 6.8, x86_64).

- `results/build.log`: the fetch and build steps.
- `results/run.log`: the tests, as `run.sh` prints them.
- `results/outputs.log`: the full output of each test program (the files in `$WORK/slhdsa-interop/outputs`), one after the other.

The run was on a 2-core x86_64 machine (Intel Xeon Platinum 8573C) with gcc 13.3. Paths under the working directory are shown as `$WORK/slhdsa-interop`.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
