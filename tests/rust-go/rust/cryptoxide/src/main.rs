//! Wycheproof vectors (ML-KEM and ML-DSA) against the `cryptoxide` crate (pure Rust, no assembly).
//! Usage:  wycheproof-cryptoxide <directory with mlkem_512.txt … mldsa_87.txt>
//!
//! Public API used (cryptoxide 0.6.7, src/mlkem/mod.rs and src/mldsa/mod.rs):
//!   ML-KEM: keypairN(&d, &z) -> (ek, dk); encapsulateN(&ek, &m) -> (c, K); decapsulateN(&dk, &c) -> K
//!           (never fails: implicit rejection). The types are built with TryFrom<&[u8]>, which gives
//!           Err(InvalidLength) if the length is wrong, Err(InvalidModulus) for the ek (FIPS 203 §7.2)
//!           and Err(InvalidHash) for the dk (FIPS 203 §7.3).
//!   ML-DSA: VerifyingKeyN::from_bytes([u8; LEN]) (checks nothing), SignatureN::from_bytes([u8; LEN]),
//!           vk.verify(message, context, &signature) -> bool (true = signature accepted).
//! A key or signature of a different length does not fit the fixed-length type: it is counted as a rejection.
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

#[path = "../../common.rs"]
mod common;

use common::{Lib, run_dsa, run_kem};
use cryptoxide::{mldsa, mlkem};

macro_rules! kem {
    ($name:literal, $ek:ident, $dk:ident, $ct:ident, $par:ident, $enc:ident, $dec:ident, $f:expr) => {{
        run_kem(
            &Lib {
                name: $name,
                // the Wycheproof seed is d || z (FIPS 203, ML-KEM.KeyGen_internal(d, z))
                seed: &|seed, c| {
                    let d: [u8; 32] = seed[..32].try_into().unwrap();
                    let z: [u8; 32] = seed[32..].try_into().unwrap();
                    let (ek, dk) = mlkem::$par(&d, &z);
                    let Ok(ct) = mlkem::$ct::try_from(c) else { return Some(None) };
                    let k = mlkem::$dec(&dk, &ct);
                    Some(Some((ek.as_ref().to_vec(), k.as_ref().to_vec())))
                },
                encaps: &|ek, m| {
                    let Ok(ek) = mlkem::$ek::try_from(ek) else { return Some(None) };
                    let (ct, k) = mlkem::$enc(&ek, m.try_into().unwrap());
                    Some(Some((ct.as_ref().to_vec(), k.as_ref().to_vec())))
                },
                dk: &|dk, c| {
                    let Ok(dk) = mlkem::$dk::try_from(dk) else { return Some(None) };
                    let Ok(ct) = mlkem::$ct::try_from(c) else { return Some(None) };
                    Some(Some((Vec::new(), mlkem::$dec(&dk, &ct).as_ref().to_vec())))
                },
            },
            &$f,
        );
    }};
}

macro_rules! dsa {
    ($name:literal, $vk:ident, $sig:ident, $f:expr) => {{
        run_dsa($name, &$f, &|pk, msg, ctx, sig| {
            let Ok(pk) = <[u8; mldsa::$vk::LENGTH]>::try_from(pk) else { return Some(false) };
            let Ok(sig) = <[u8; mldsa::$sig::LENGTH]>::try_from(sig) else { return Some(false) };
            Some(mldsa::$vk::from_bytes(pk).verify(msg, ctx, &mldsa::$sig::from_bytes(sig)))
        });
    }};
}

fn main() {
    common::silence_panic_messages();
    let d = std::env::args().nth(1).expect("usage: wycheproof-cryptoxide <directory>");
    let f = |p: &str| format!("{d}/{p}.txt");
    println!("== cryptoxide 0.6.7 (crates.io), {}", std::env::consts::ARCH);

    kem!("cryptoxide ML-KEM-512", EncapsulationKey512, DecapsulationKey512, Ciphertext512, keypair512, encapsulate512, decapsulate512, f("mlkem_512"));
    kem!("cryptoxide ML-KEM-768", EncapsulationKey768, DecapsulationKey768, Ciphertext768, keypair768, encapsulate768, decapsulate768, f("mlkem_768"));
    kem!("cryptoxide ML-KEM-1024", EncapsulationKey1024, DecapsulationKey1024, Ciphertext1024, keypair1024, encapsulate1024, decapsulate1024, f("mlkem_1024"));

    dsa!("cryptoxide ML-DSA-44", VerifyingKey44, Signature44, f("mldsa_44"));
    dsa!("cryptoxide ML-DSA-65", VerifyingKey65, Signature65, f("mldsa_65"));
    dsa!("cryptoxide ML-DSA-87", VerifyingKey87, Signature87, f("mldsa_87"));
}
