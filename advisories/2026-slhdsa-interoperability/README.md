# SLH-DSA: libbitcoinpqc and PQMagic do not interoperate with FIPS 205 implementations

**Status:** present in the code tested, the `main` branch of each library (neither has released versions). This is not a security weakness: it is a matter of interoperability and of labelling.

## Summary

Two libraries document their signature scheme as SLH-DSA (FIPS 205). Neither interoperates with a conforming implementation: their signatures do not verify with OpenSSL, and OpenSSL's signatures do not verify with them.

| Library | Code tested | What its documentation says | What it implements |
|---|---|---|---|
| [libbitcoinpqc](https://github.com/cryptoquick/libbitcoinpqc) | `main` at `fc08c052` (3 November 2026) | README: "**SLH-DSA-SHA2-128s** (FIPS 205, formerly SPHINCS+)" and "Both PQC algorithms are FIPS-certified" | SPHINCS+ 3.1, which reads the FORS indices in the bit order used before the standard, and no context prefix |
| [PQMagic](https://github.com/pqcrypto-cn/PQMagic) | `main` at `42f5b6e6` (29 October 2026) | Its README states that it implements FIPS 203, 204 and 205 | A FIPS 205 core, exposed only through the internal interface: no `0x00 ‖ len(ctx) ‖ ctx` prefix and no context parameter |

This is not a weakness in either scheme as implemented. Each library verifies its own signatures, rejects them when altered, and generates the same keys as FIPS 205 from the same seed. The problem is the name: a signature made with one of these libraries cannot be verified by a conforming SLH-DSA implementation, and the other way round.

[btx](https://github.com/btxchain/btx), which derives from libbitcoinpqc, has a FIPS 205 mode that does interoperate: 3 of 3 signatures verify in each direction, and it passes the ACVP vectors.

## Reference

OpenSSL at commit `354f1cf64842` of its development branch (version string 4.2.0-dev), built from source. With the same harness it passes the NIST ACVP SLH-DSA vectors ([usnistgov/ACVP-Server](https://github.com/usnistgov/ACVP-Server) at `975de31eb83d`) in all 12 parameter sets: keyGen 10 of 10, sigVer 14 of 14 for the external pure interface and 14 of 14 for the internal interface. OpenSSL does not support pre-hash SLH-DSA, so those vectors were not run.

## How we tested

For each parameter set the library offers, three messages (empty, `abc`, 200 fixed bytes), each with a new key from the library:

- **Controls.** The library verifies its own signature and rejects it with one byte changed; OpenSSL verifies its own signature. All controls passed in every run.
- **Key generation.** OpenSSL is given the seed of the library's key (SK.seed ‖ SK.prf ‖ PK.seed) and must produce the same public and private key.
- **Interoperability.** OpenSSL verifies the library's signature as pure SLH-DSA with an empty context, and the library verifies OpenSSL's.
- **Diagnosis.** The same through OpenSSL's internal interface, which has no prefix; and OpenSSL's pure signature given to the library with `0x00 ‖ 0x00` put in front of the message by hand. If these pass while the pure ones fail, the only difference is the prefix. If they fail too, the signature core differs.

We also ran the ACVP keyGen and sigVer vectors through each library's public interface: the internal-interface vectors as given, and the external pure vectors with the prefix `0x00 ‖ len(ctx) ‖ ctx` built by the test program in front of the message.

## Results

Linux x86_64 (Intel Xeon Platinum 8573C), gcc 13.3, 21 November 2026.

### Interoperability with OpenSSL

| Test (3 messages) | libbitcoinpqc, SLH-DSA-SHA2-128s | CONTROL: libbitcoinpqc with one line of `fors.c` changed | PQMagic, each of the 12 parameter sets |
|---|---|---|---|
| Controls | 3/3 each | 3/3 each | 3/3 each |
| Same keys from the same seed | 3/3 | 3/3 | 3/3 |
| Library's signature verified by OpenSSL (pure, empty context) | **0/3** | 0/3 | **0/3** |
| OpenSSL's signature (pure, empty context) verified by the library | **0/3** | 0/3 | **0/3** |
| Library's signature verified by OpenSSL's internal interface | 0/3 | 3/3 | 3/3 |
| OpenSSL's internal-interface signature verified by the library | 0/3 | 3/3 | 3/3 |
| OpenSSL's pure signature verified by the library, prefix added by hand | 0/3 | 3/3 | 3/3 |

### ACVP vectors

Each sigVer group has 14 vectors, of which 2 are valid. No library accepted an invalid vector.

| Library | keyGen | sigVer, internal interface | sigVer, external pure, prefix built by the test |
|---|---|---|---|
| libbitcoinpqc | 10/10 | 12/14: both valid signatures rejected | 12/14: both valid signatures rejected |
| CONTROL build | 10/10 | 14/14 | 14/14 |
| PQMagic, each of the 12 parameter sets | 10/10 | 14/14 | 14/14 |

### btx

btx (`btxchain/btx` at `074dac16`, 15 November 2026) carries its own copy of libbitcoinpqc in `src/libbitcoinpqc`. Its signing and verification functions take a flag that selects the FIPS 205 FORS order, and btx adds the prefix for an empty context (`0x00 ‖ 0x00`) when its `SCRIPT_VERIFY_SLHDSA_FIPS205` flag is active. With both, SLH-DSA-SHAKE-128s interoperates with OpenSSL: 3 of 3 signatures verify in each direction, and the ACVP vectors pass (internal interface 14 of 14; external pure with the prefix, 14 of 14). Without them it behaves like libbitcoinpqc: 0 of 3 in each direction, and both valid ACVP signatures rejected. There is nothing to report for btx.

## Causes

### libbitcoinpqc

The library carries the `master` branch of the sphincsplus reference code, which is SPHINCS+ 3.1. FIPS 205 changed the order in which the FORS indices are read from the message digest; sphincsplus has the FIPS 205 version on its `bas/fips205` branch. The difference is one line of `sphincsplus/ref/fors.c` (line 59):

```c
/* libbitcoinpqc fc08c052 (SPHINCS+ 3.1) */
indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 1u) << j;
/* sphincsplus bas/fips205, ef36d20ff358 (FIPS 205) */
indices[i] ^= ((m[offset >> 3] >> (~offset & 0x7)) & 1u) << (SPX_FORS_HEIGHT-1-j);
```

With that line changed (the CONTROL build, which is not the published library), the internal interface matches OpenSSL and the ACVP vectors pass. Pure SLH-DSA still does not interoperate, because the library also does not put the FIPS 205 prefix `0x00 ‖ len(ctx) ‖ ctx` in front of the message: its signing and verification functions take no context and use the message as given.

libbitcoinpqc is the library associated with the BIP-360 proposal. It has no released versions. An open issue (#32, opened by someone else on 1 November 2026) proposes adding OpenSSL test vectors to its tests; the results above show that the current code would not pass them.

### PQMagic

The SLH-DSA core follows FIPS 205: through OpenSSL's internal interface, and with the prefix added by hand, everything matches, and the ACVP vectors pass in all 12 parameter sets. But the functions PQMagic exposes (`pqmagic_slh_dsa_<hash>_<level><s|f>_simple_std_sign_signature` and `..._sign_verify`) are the internal functions of FIPS 205 (Algorithms 19 and 20) applied to the caller's message. They do not add the prefix `0x00 ‖ len(ctx) ‖ ctx` that the external interface (Algorithms 22 and 24) puts in front of the message, and they have no context parameter. PQMagic has no released versions.

A smaller point: the header comment says that verification returns 0 or 1 ("return 0/1 if verification failed/success"). It returns 0 for a valid signature and −1 for an invalid one.

## Limits

- Three messages per direction and parameter set.
- Each ACVP sigVer group has only 2 valid signatures, so "both valid signatures rejected" is 2 of 2.
- Only the `main` branch of each library was examined. Neither has released versions.
- libbitcoinpqc offers only SLH-DSA-SHA2-128s, and btx only SLH-DSA-SHAKE-128s. PQMagic was built with SLH-DSA only and its "simple" thash.
- ACVP sigGen was not run: none of the libraries lets the caller fix the signing randomness. Pre-hash SLH-DSA was not covered.
- PQMagic's ACVP keyGen used its seed-based key generation function, which the library exports but does not declare in its public header.
- Only x86_64.

## How to reproduce

[`tests/slhdsa-interoperability`](../../tests/slhdsa-interoperability/) has `run.sh`, which downloads the libraries at the commits above, OpenSSL and the ACVP vectors, builds them and prints the results, and a `results/` directory with the output of our run.

## Timeline

| Date | Event |
|---|---|
| 29 October 2026 | PQMagic `main` at `42f5b6e6`, the code tested |
| 1 November 2026 | An issue (#32) in libbitcoinpqc proposes adding OpenSSL test vectors |
| 3 November 2026 | libbitcoinpqc `main` at `fc08c052`, the code tested |
| 21 November 2026 | We run the tests and record the results above |
| 21 November 2026 | Reported to libbitcoinpqc (comment on its open issue 32) and to PQMagic (public issue); neither project has a private channel |

## Credit

The test vectors are from NIST's ACVP-Server.

## Method

The research strategy and the test code were designed and written with AI assistance, and the tests were run with AI tooling (Claude Fable 5.2, by Anthropic), under the direction of RatioLabs.

Copyright 2026 [RatioLabs](https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
