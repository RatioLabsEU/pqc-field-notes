//! Wycheproof vectors (ML-KEM and ML-DSA) against the `purecrypto` crate.
//! Usage:  wycheproof-purecrypto <directory with mlkem_512.txt … mldsa_87.txt>
//!
//! Public API used (purecrypto 0.10.6, src/mlkem/mod.rs and src/mldsa/mod.rs):
//!   ML-KEM: MlKemNDecapsKey::from_seeds(&d, &z) -> (dk, ek) ("intended for testing");
//!           MlKemNEncapsKey::from_bytes_validated([u8; N]) -> Result (FIPS 203 §7.2);
//!           ek.encapsulate_deterministic(&m) -> (c, K) ("intended for testing");
//!           MlKemNDecapsKey::from_bytes_validated([u8; N]) -> Result (FIPS 203 §7.3, plus §7.2 on the embedded
//!           ek); dk.decapsulate(&c) -> K (implicit rejection, never fails).
//!           The non-validating `from_bytes` exist, but their documentation says not to use them with untrusted
//!           data, so the `_validated` variants are the ones tested.
//!   ML-DSA: MlDsaNPublicKey::from_bytes(&[u8]) -> Result (length only); pk.verify(signature, message,
//!           context) -> bool (true = signature accepted).
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

#[path = "../../common.rs"]
mod common;

use common::{Lib, run_dsa, run_kem};
use purecrypto::{mldsa, mlkem};

macro_rules! kem {
    ($name:literal, $ek:ident, $dk:ident, $ct:ident, $f:expr) => {{
        run_kem(
            &Lib {
                name: $name,
                // the Wycheproof seed is d || z
                seed: &|seed, c| {
                    let d: [u8; 32] = seed[..32].try_into().unwrap();
                    let z: [u8; 32] = seed[32..].try_into().unwrap();
                    let (dk, ek) = mlkem::$dk::from_seeds(&d, &z);
                    let Ok(ct) = c.try_into() else { return Some(None) };
                    let k = dk.decapsulate(&mlkem::$ct::from_bytes(ct));
                    Some(Some((ek.to_bytes().to_vec(), k.to_vec())))
                },
                encaps: &|ek, m| {
                    let Ok(ek) = ek.try_into() else { return Some(None) };
                    let Ok(ek) = mlkem::$ek::from_bytes_validated(ek) else { return Some(None) };
                    let (ct, k) = ek.encapsulate_deterministic(m.try_into().unwrap());
                    Some(Some((ct.to_bytes().to_vec(), k.to_vec())))
                },
                dk: &|dk, c| {
                    let Ok(dk) = dk.try_into() else { return Some(None) };
                    let Ok(dk) = mlkem::$dk::from_bytes_validated(dk) else { return Some(None) };
                    let Ok(ct) = c.try_into() else { return Some(None) };
                    Some(Some((Vec::new(), dk.decapsulate(&mlkem::$ct::from_bytes(ct)).to_vec())))
                },
            },
            &$f,
        );
    }};
}

/// Control of the test program (not a finding): with the NON-validating `from_bytes`, which the library documents
/// as "No validation", the program must count the invalid keys as accepted. It shows that the program detects an
/// "INVALID ACCEPTED" when there is one.
macro_rules! kem_control {
    ($name:literal, $ek:ident, $dk:ident, $ct:ident, $f:expr) => {{
        run_kem(
            &Lib {
                name: $name,
                seed: &|_, _| None,
                encaps: &|ek, m| {
                    let Ok(ek) = ek.try_into() else { return Some(None) };
                    let (ct, k) = mlkem::$ek::from_bytes(ek).encapsulate_deterministic(m.try_into().unwrap());
                    Some(Some((ct.to_bytes().to_vec(), k.to_vec())))
                },
                dk: &|dk, c| {
                    let Ok(dk) = dk.try_into() else { return Some(None) };
                    let Ok(ct) = c.try_into() else { return Some(None) };
                    Some(Some((Vec::new(), mlkem::$dk::from_bytes(dk).decapsulate(&mlkem::$ct::from_bytes(ct)).to_vec())))
                },
            },
            &$f,
        );
    }};
}

macro_rules! dsa {
    ($name:literal, $pk:ident, $f:expr) => {{
        run_dsa($name, &$f, &|pk, msg, ctx, sig| {
            let Ok(pk) = mldsa::$pk::from_bytes(pk) else { return Some(false) };
            Some(pk.verify(sig, msg, ctx))
        });
    }};
}

fn main() {
    common::silence_panic_messages();
    let d = std::env::args().nth(1).expect("usage: wycheproof-purecrypto <directory>");
    let f = |p: &str| format!("{d}/{p}.txt");
    println!("== purecrypto 0.10.6 (crates.io), {}", std::env::consts::ARCH);

    kem!("purecrypto ML-KEM-512", MlKem512EncapsKey, MlKem512DecapsKey, MlKem512Ciphertext, f("mlkem_512"));
    kem!("purecrypto ML-KEM-768", MlKem768EncapsKey, MlKem768DecapsKey, MlKem768Ciphertext, f("mlkem_768"));
    kem!("purecrypto ML-KEM-1024", MlKem1024EncapsKey, MlKem1024DecapsKey, MlKem1024Ciphertext, f("mlkem_1024"));

    println!("-- program control: non-validating from_bytes (invalid keys are expected to be accepted)");
    kem_control!("CONTROL purecrypto ML-KEM-768", MlKem768EncapsKey, MlKem768DecapsKey, MlKem768Ciphertext, f("mlkem_768"));
    println!("-- end of control");

    dsa!("purecrypto ML-DSA-44", MlDsa44PublicKey, f("mldsa_44"));
    dsa!("purecrypto ML-DSA-65", MlDsa65PublicKey, f("mldsa_65"));
    dsa!("purecrypto ML-DSA-87", MlDsa87PublicKey, f("mldsa_87"));
}
