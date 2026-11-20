//! Wycheproof ML-DSA verification vectors against RustCrypto `ml-dsa` and libcrux `libcrux-ml-dsa`
//! (automatic, portable and AVX2 / NEON paths).
//! Usage:  wycheproof-mldsa <directory with mldsa_44.txt, mldsa_65.txt, mldsa_87.txt>
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

fn run(name: &str, file: &str, v: &dyn Fn(&[u8], &[u8], &[u8], &[u8]) -> bool) -> bool {
    let text = std::fs::read_to_string(file).expect("vector file");
    let (mut total, mut bad_accepted, mut bad_rejected) = (0, 0, 0);
    for line in text.lines() {
        let c: Vec<&str> = line.splitn(7, '|').collect();
        if c.len() < 7 {
            continue;
        }
        let (pk, msg, ctx, sig) = (hex(c[2]), hex(c[3]), hex(c[4]), hex(c[5]));
        total += 1;
        let expected = c[1] == "valid";
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| v(&pk, &msg, &ctx, &sig))).unwrap_or(false);
        if ok && !expected {
            bad_accepted += 1;
            println!("  INVALID ACCEPTED  tcId={}  {}", c[0], c[6]);
        }
        if !ok && expected {
            bad_rejected += 1;
            println!("  valid rejected    tcId={}  {}", c[0], c[6]);
        }
    }
    println!("{name:<34} vectors={total}   INVALID ACCEPTED={bad_accepted}   valid rejected={bad_rejected}");
    bad_accepted == 0 && bad_rejected == 0
}

macro_rules! rustcrypto {
    ($p:ty) => {
        &|pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]| -> bool {
            let Ok(ek) = ml_dsa::EncodedVerifyingKey::<$p>::try_from(pk) else { return false };
            let Ok(es) = ml_dsa::EncodedSignature::<$p>::try_from(sig) else { return false };
            let vk = ml_dsa::VerifyingKey::<$p>::decode(&ek);
            let Some(s) = ml_dsa::Signature::<$p>::decode(&es) else { return false };
            vk.verify_with_context(msg, ctx, &s)
        }
    };
}

macro_rules! libcrux {
    ($($m:ident)::+) => {
        &|pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]| -> bool {
            use libcrux_ml_dsa::$($m)::+ as m;
            let Ok(k) = pk.try_into() else { return false };
            let Ok(s) = sig.try_into() else { return false };
            let k = libcrux_ml_dsa::MLDSAVerificationKey::new(k);
            let s = libcrux_ml_dsa::MLDSASignature::new(s);
            m::verify(&k, msg, ctx, &s).is_ok()
        }
    };
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let d = std::env::args().nth(1).expect("usage: wycheproof-mldsa <directory>");
    let f = |p: &str| format!("{d}/mldsa_{p}.txt");
    let mut good = true;

    good &= run("RustCrypto ml-dsa ML-DSA-44", &f("44"), rustcrypto!(ml_dsa::MlDsa44));
    good &= run("RustCrypto ml-dsa ML-DSA-65", &f("65"), rustcrypto!(ml_dsa::MlDsa65));
    good &= run("RustCrypto ml-dsa ML-DSA-87", &f("87"), rustcrypto!(ml_dsa::MlDsa87));

    use libcrux_ml_dsa::{ml_dsa_44, ml_dsa_65, ml_dsa_87};
    good &= run("libcrux ML-DSA-44 (auto)", &f("44"), libcrux!(ml_dsa_44));
    good &= run("libcrux ML-DSA-65 (auto)", &f("65"), libcrux!(ml_dsa_65));
    good &= run("libcrux ML-DSA-87 (auto)", &f("87"), libcrux!(ml_dsa_87));
    good &= run("libcrux ML-DSA-44 (portable)", &f("44"), libcrux!(ml_dsa_44::portable));
    good &= run("libcrux ML-DSA-65 (portable)", &f("65"), libcrux!(ml_dsa_65::portable));
    good &= run("libcrux ML-DSA-87 (portable)", &f("87"), libcrux!(ml_dsa_87::portable));
    #[cfg(target_arch = "x86_64")]
    {
        good &= run("libcrux ML-DSA-44 (avx2)", &f("44"), libcrux!(ml_dsa_44::avx2));
    }
    #[cfg(target_arch = "aarch64")]
    {
        good &= run("libcrux ML-DSA-44 (neon)", &f("44"), libcrux!(ml_dsa_44::neon));
    }
    #[cfg(target_arch = "x86_64")]
    {
        good &= run("libcrux ML-DSA-65 (avx2)", &f("65"), libcrux!(ml_dsa_65::avx2));
    }
    #[cfg(target_arch = "aarch64")]
    {
        good &= run("libcrux ML-DSA-65 (neon)", &f("65"), libcrux!(ml_dsa_65::neon));
    }
    #[cfg(target_arch = "x86_64")]
    {
        good &= run("libcrux ML-DSA-87 (avx2)", &f("87"), libcrux!(ml_dsa_87::avx2));
    }
    #[cfg(target_arch = "aarch64")]
    {
        good &= run("libcrux ML-DSA-87 (neon)", &f("87"), libcrux!(ml_dsa_87::neon));
    }

    let _ = (ml_dsa_44::verify, ml_dsa_65::verify, ml_dsa_87::verify);
    std::process::exit(if good { 0 } else { 1 });
}
