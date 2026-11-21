//! pqcrypto-dilithium 0.5.0 (archived crate; its C code is PQClean's Dilithium, a version from before the standard).
//!
//! Compares three verification paths of the crate on the same inputs:
//!   API    `dilithiumN::verify_detached_signature`, the Rust interface: with the `avx2` feature (the default) and a CPU
//!          with AVX2 it selects the AVX2 implementation at run time (src/dilithiumN.rs); without it, "clean".
//!   clean  `ffi::PQCLEAN_DILITHIUMN_CLEAN_crypto_sign_verify`, the portable implementation (the crate's README says
//!          that the alternative implementations are exposed "as ffi methods only").
//!   avx2   `ffi::PQCLEAN_DILITHIUMN_AVX2_crypto_sign_verify` (only present with the `avx2` feature on x86_64).
//! Convention of the C functions: 0 = valid signature, -1 = not valid (sign.c, "Returns 0 if signature could be
//! verified correctly and -1 otherwise"); the API returns Ok(()) or Err.
//!
//! Inputs:
//!   1. Control: keys and signatures made by the crate through its Rust interface (`keypair`, `detached_sign`), 20 per
//!      parameter set. All three paths must accept them, and reject them with one byte changed. If not, this program
//!      is what is broken.
//!   2. The file written by dilithium_generator.c: "out_of_bound" (20 signatures per parameter set with
//!      γ1 − β ≤ ‖z‖∞ < γ1, the same kind of input as oob_z.c) and "use_hint" (valid signatures built by hand that make
//!      the verifier compute UseHint(1, 0); our own construction).
//! Usage: pqcrypto-dilithium-check <cases.txt>
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

use pqcrypto_dilithium::ffi;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len() % 2 == 0, "hexadecimal of odd length");
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).expect("hexadecimal")).collect()
}

/// Result of one path: true = accepts.
type VerifyFn = fn(&[u8], &[u8], &[u8]) -> bool;

macro_rules! paths {
    ($m:ident, $clean:ident, $avx2:ident) => {{
        fn api(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            use pqcrypto_dilithium::$m as m;
            match (m::PublicKey::from_bytes(pk), m::DetachedSignature::from_bytes(sig)) {
                (Ok(pk), Ok(sig)) => m::verify_detached_signature(&sig, msg, &pk).is_ok(),
                _ => false,
            }
        }
        fn clean(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            unsafe { ffi::$clean(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), pk.as_ptr()) == 0 }
        }
        #[cfg(feature = "avx2")]
        fn avx2(pk: &[u8], msg: &[u8], sig: &[u8]) -> bool {
            unsafe { ffi::$avx2(sig.as_ptr(), sig.len(), msg.as_ptr(), msg.len(), pk.as_ptr()) == 0 }
        }
        #[cfg(feature = "avx2")]
        let v: Vec<(&str, VerifyFn)> = vec![("API", api as VerifyFn), ("clean", clean as VerifyFn), ("avx2", avx2 as VerifyFn)];
        #[cfg(not(feature = "avx2"))]
        let v: Vec<(&str, VerifyFn)> = vec![("API", api as VerifyFn), ("clean", clean as VerifyFn)];
        v
    }};
}

/// Runs a list of cases (pk, msg, sig) through the paths; counts acceptances per path and discrepancies between paths.
fn compare(label: &str, paths: &[(&str, VerifyFn)], cases: &[(Vec<u8>, Vec<u8>, Vec<u8>)]) -> (Vec<usize>, usize) {
    let mut accepted = vec![0usize; paths.len()];
    let mut discrepancies = 0usize;
    for (i, (pk, msg, sig)) in cases.iter().enumerate() {
        let r: Vec<bool> = paths.iter().map(|(_, f)| f(pk, msg, sig)).collect();
        for (k, ok) in r.iter().enumerate() {
            if *ok {
                accepted[k] += 1;
            }
        }
        if r.iter().any(|x| *x != r[0]) {
            discrepancies += 1;
            let txt: Vec<String> = paths.iter().zip(r.iter()).map(|((n, _), ok)| format!("{n}={}", if *ok { "accepts" } else { "rejects" })).collect();
            println!("    DISCREPANCY {label} case {i}: {}", txt.join(" "));
        }
    }
    (accepted, discrepancies)
}

fn print_line(var: &str, what: &str, paths: &[(&str, VerifyFn)], total: usize, accepted: &[usize], discrepancies: usize) {
    let txt: Vec<String> = paths.iter().zip(accepted.iter()).map(|((n, _), a)| format!("{n} {a}/{total}")).collect();
    println!("{var:<11} {what:<58} accepted: {}   DISCREPANCIES between paths: {discrepancies}", txt.join(", "));
}

macro_rules! param_set {
    ($var:literal, $m:ident, $clean:ident, $avx2:ident, $cases:expr) => {{
        use pqcrypto_dilithium::$m as m;
        let paths = paths!($m, $clean, $avx2);
        // 1. Control with the crate's own key generation and signing (Rust interface).
        let mut good = Vec::new();
        let mut bad = Vec::new();
        for i in 0..20 {
            let (pk, sk) = m::keypair();
            let msg = format!("control {} {}", $var, i).into_bytes();
            let sig = m::detached_sign(&msg, &sk);
            let mut altered = sig.as_bytes().to_vec();
            let pos = altered.len() / 2;
            altered[pos] ^= 0x01;
            good.push((pk.as_bytes().to_vec(), msg.clone(), sig.as_bytes().to_vec()));
            bad.push((pk.as_bytes().to_vec(), msg, altered));
        }
        let (a, d) = compare(concat!($var, " control"), &paths, &good);
        print_line($var, "control: the crate's keypair + detached_sign", &paths, 20, &a, d);
        let control_ok = a.iter().all(|x| *x == 20);
        let (a, d) = compare(concat!($var, " control altered"), &paths, &bad);
        print_line($var, "control: the same signature with one byte changed", &paths, 20, &a, d);
        let control_ok = control_ok && a.iter().all(|x| *x == 0);
        // 2. Cases from the file, by origin.
        for origin in ["out_of_bound", "use_hint"] {
            let list: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = $cases
                .iter()
                .filter(|c: &&Vec<String>| c[0] == $var && c[1] == origin)
                .map(|c| (unhex(&c[2]), unhex(&c[3]), unhex(&c[4])))
                .collect();
            let what = match origin {
                "out_of_bound" => "out_of_bound: γ1−β ≤ ‖z‖∞ < γ1 (must be rejected)",
                _ => "use_hint: zero pk, UseHint(1, 0) (valid, must be accepted)",
            };
            let (a, d) = compare(&format!("{} {}", $var, origin), &paths, &list);
            print_line($var, what, &paths, list.len(), &a, d);
        }
        control_ok
    }};
}

fn main() {
    let file = std::env::args().nth(1).expect("usage: pqcrypto-dilithium-check <cases.txt>");
    let text = std::fs::read_to_string(&file).expect("cases file");
    let cases: Vec<Vec<String>> = text
        .lines()
        .filter(|l| !l.is_empty())
        .map(|l| l.splitn(6, '|').map(|s| s.to_string()).collect::<Vec<String>>())
        .filter(|c| c.len() == 6)
        .collect();
    let cpu_avx2 = std::is_x86_feature_detected!("avx2");
    println!(
        "pqcrypto-dilithium 0.5.0; avx2 feature: {}; CPU with AVX2: {}; the API uses: {}",
        cfg!(feature = "avx2"),
        cpu_avx2,
        if cfg!(feature = "avx2") && cpu_avx2 { "AVX2" } else { "clean" }
    );
    println!("cases read from {file}: {}", cases.len());
    let mut ok = true;
    ok &= param_set!("dilithium2", dilithium2, PQCLEAN_DILITHIUM2_CLEAN_crypto_sign_verify, PQCLEAN_DILITHIUM2_AVX2_crypto_sign_verify, cases);
    ok &= param_set!("dilithium3", dilithium3, PQCLEAN_DILITHIUM3_CLEAN_crypto_sign_verify, PQCLEAN_DILITHIUM3_AVX2_crypto_sign_verify, cases);
    ok &= param_set!("dilithium5", dilithium5, PQCLEAN_DILITHIUM5_CLEAN_crypto_sign_verify, PQCLEAN_DILITHIUM5_AVX2_crypto_sign_verify, cases);
    if !ok {
        println!("CONTROLS FAILED: the result is not valid");
        std::process::exit(2);
    }
    println!("controls correct");
}
