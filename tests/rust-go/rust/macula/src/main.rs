//! Wycheproof vectors against the `macula-mlkem` and `macula-mldsa` crates (macula-pqc project).
//! Usage:  wycheproof-macula <directory with mlkem_512.txt … mldsa_87.txt>
//!
//! API used (macula-mlkem 0.3.0 and macula-mldsa 0.3.0, src/lib.rs and internal.rs):
//!   ML-KEM, normal public interface: encaps(p, ek) -> Result<(c, K)> with m taken from the system, so for the
//!           "E" vectors only acceptance or rejection of the ek can be checked; decaps(p, dk, c) -> Result<K>
//!           (Err if the lengths are wrong or the FIPS 203 §7.3 check fails).
//!           There is no key generation from a seed: the "D" vectors are left as "no interface".
//!   ML-KEM, with the `internal` feature (documented "for testing", for NIST vectors):
//!           internal::key_gen(p, &d, &z) -> (ek, dk); internal::encaps(p, ek, &m) -> Result<(c, K)>
//!           (it performs the same FIPS 203 §7.2 check as encaps).
//!   ML-DSA: verify(p, pk, message, signature, context) -> Result<bool>; Ok(true) = signature accepted, Err only
//!           if the context is longer than 255 bytes (counted as a rejection).
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

#[path = "../../common.rs"]
mod common;

use common::{Lib, run_dsa, run_kem};
use macula_mldsa as dsa;
use macula_mlkem as kem;

fn kem_internal(name: &str, p: kem::ParameterSet, file: &str) {
    run_kem(
        &Lib {
            name,
            seed: &|seed, c| {
                let (d, z): (&[u8; 32], &[u8; 32]) = (seed[..32].try_into().unwrap(), seed[32..].try_into().unwrap());
                let (ek, dk) = kem::internal::key_gen(p, d, z);
                match kem::decaps(p, &dk, c) {
                    Ok(k) => Some(Some((ek, k.to_vec()))),
                    Err(_) => Some(None),
                }
            },
            encaps: &|ek, m| match kem::internal::encaps(p, ek, m.try_into().unwrap()) {
                Ok((c, k)) => Some(Some((c, k.to_vec()))),
                Err(_) => Some(None),
            },
            dk: &|dk, c| match kem::decaps(p, dk, c) {
                Ok(k) => Some(Some((Vec::new(), k.to_vec()))),
                Err(_) => Some(None),
            },
        },
        file,
    );
}

fn kem_public(name: &str, p: kem::ParameterSet, file: &str) {
    run_kem(
        &Lib {
            name,
            seed: &|_, _| None,
            // the library chooses m: an empty c = only acceptance of the ek is checked
            encaps: &|ek, _| match kem::encaps(p, ek) {
                Ok(_) => Some(Some((Vec::new(), Vec::new()))),
                Err(_) => Some(None),
            },
            dk: &|dk, c| match kem::decaps(p, dk, c) {
                Ok(k) => Some(Some((Vec::new(), k.to_vec()))),
                Err(_) => Some(None),
            },
        },
        file,
    );
}

fn main() {
    common::silence_panic_messages();
    let d = std::env::args().nth(1).expect("usage: wycheproof-macula <directory>");
    let f = |p: &str| format!("{d}/{p}.txt");
    println!("== macula-mlkem 0.3.0 and macula-mldsa 0.3.0 (crates.io), {}", std::env::consts::ARCH);

    for (n, p) in [("512", kem::ML_KEM_512), ("768", kem::ML_KEM_768), ("1024", kem::ML_KEM_1024)] {
        kem_internal(&format!("macula ML-KEM-{n} (internal)"), p, &f(&format!("mlkem_{n}")));
        kem_public(&format!("macula ML-KEM-{n} (public only)"), p, &f(&format!("mlkem_{n}")));
    }
    for (n, p) in [("44", dsa::ML_DSA_44), ("65", dsa::ML_DSA_65), ("87", dsa::ML_DSA_87)] {
        run_dsa(&format!("macula ML-DSA-{n}"), &f(&format!("mldsa_{n}")), &|pk, msg, ctx, sig| {
            Some(dsa::verify(p, pk, msg, sig, ctx).unwrap_or(false))
        });
    }
}
