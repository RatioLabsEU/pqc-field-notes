//! Run Wycheproof ML-DSA verification vectors against two Rust crates:
//! `pqcrypto-mldsa` (which wraps PQClean) and `oqs` (which builds a bundled copy of liboqs).
//!
//! Only vectors with an empty context are used, through `verify_detached_signature`.
//! Usage:  pqcrypto-check <dir with mldsa_44.txt, mldsa_65.txt, mldsa_87.txt>
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

macro_rules! run {
    ($label:literal, $m:ident, $file:expr) => {{
        use pqcrypto_mldsa::$m as m;
        let text = std::fs::read_to_string($file).expect("vector file");
        let (mut total, mut bad_accept, mut bad_reject, mut skipped) = (0, 0, 0, 0);
        for line in text.lines() {
            let c: Vec<&str> = line.splitn(7, '|').collect();
            if c.len() < 7 {
                continue;
            }
            if !c[4].is_empty() {
                skipped += 1;
                continue;
            }
            let (pk, sig) = (m::PublicKey::from_bytes(&unhex(c[2])), m::DetachedSignature::from_bytes(&unhex(c[5])));
            let expected = c[1] == "valid";
            let ok = match (pk, sig) {
                (Ok(pk), Ok(sig)) => m::verify_detached_signature(&sig, &unhex(c[3]), &pk).is_ok(),
                (Err(_), _) => {
                    skipped += 1;
                    continue;
                }
                _ => false,
            };
            total += 1;
            if ok && !expected {
                bad_accept += 1;
                println!("  INVALID ACCEPTED  tcId={}  {}", c[0], c[6]);
            }
            if !ok && expected {
                bad_reject += 1;
                println!("  VALID REJECTED    tcId={}  {}", c[0], c[6]);
            }
        }
        println!(
            "pqcrypto-mldsa 0.1.2 {:<10} vectors={} (not applicable {})   INVALID ACCEPTED={}   VALID REJECTED={}",
            $label, total, skipped, bad_accept, bad_reject
        );
    }};
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: pqcrypto-check <vector dir>");
    println!("avx2 feature: {}", cfg!(feature = "avx2"));
    run!("ML-DSA-44", mldsa44, format!("{dir}/mldsa_44.txt"));
    run!("ML-DSA-65", mldsa65, format!("{dir}/mldsa_65.txt"));
    run!("ML-DSA-87", mldsa87, format!("{dir}/mldsa_87.txt"));
    oqs_run(&dir);
}

/// The `oqs` crate. All vectors are used, including those with a context string.
fn oqs_run(dir: &str) {
    oqs::init();
    for (label, alg, p) in [
        ("ML-DSA-44", oqs::sig::Algorithm::MlDsa44, "44"),
        ("ML-DSA-65", oqs::sig::Algorithm::MlDsa65, "65"),
        ("ML-DSA-87", oqs::sig::Algorithm::MlDsa87, "87"),
    ] {
        let sg = oqs::sig::Sig::new(alg).expect("algorithm");
        let text = std::fs::read_to_string(format!("{dir}/mldsa_{p}.txt")).expect("vector file");
        let (mut total, mut bad_accept, mut bad_reject) = (0, 0, 0);
        for line in text.lines() {
            let c: Vec<&str> = line.splitn(7, '|').collect();
            if c.len() < 7 {
                continue;
            }
            let (pk, msg, ctx, sig) = (unhex(c[2]), unhex(c[3]), unhex(c[4]), unhex(c[5]));
            let expected = c[1] == "valid";
            let ok = match (sg.public_key_from_bytes(&pk), sg.signature_from_bytes(&sig)) {
                (Some(pk), Some(sig)) if ctx.is_empty() => sg.verify(&msg, sig, pk).is_ok(),
                (Some(pk), Some(sig)) if ctx.len() <= 255 => sg.verify_with_ctx_str(&msg, sig, &ctx, pk).is_ok(),
                _ => false,
            };
            total += 1;
            if ok && !expected {
                bad_accept += 1;
                println!("  INVALID ACCEPTED  tcId={}  {}", c[0], c[6]);
            }
            if !ok && expected {
                bad_reject += 1;
                println!("  VALID REJECTED    tcId={}  {}", c[0], c[6]);
            }
        }
        println!("oqs 0.11.0 (liboqs 0.13.0) {label:<10} vectors={total}   INVALID ACCEPTED={bad_accept}   VALID REJECTED={bad_reject}");
    }
}
