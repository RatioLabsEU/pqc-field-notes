//! Wycheproof ML-KEM vectors against RustCrypto `ml-kem` and libcrux `libcrux-ml-kem`
//! (automatic, portable and AVX2 / NEON paths).
//! Usage:  wycheproof-mlkem <directory with mlkem_512.txt, mlkem_768.txt, mlkem_1024.txt>
//!
//! Each operation returns None if the library has no interface for it, Some(None) if it rejects the input and
//! Some(Some(data)) if it accepts it.
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

type Out = Option<Option<(Vec<u8>, Vec<u8>)>>; // (first, K): first = ek or c, depending on the operation

fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

struct Lib<'a> {
    name: &'a str,
    seed: &'a dyn Fn(&[u8], &[u8]) -> Out,
    encaps: &'a dyn Fn(&[u8], &[u8]) -> Out,
    dk: &'a dyn Fn(&[u8], &[u8]) -> Out,
}

fn run(l: &Lib, file: &str) {
    let text = std::fs::read_to_string(file).expect("vector file");
    let kinds = ["seed", "encaps", "expanded dk"];
    let (mut n, mut accepted, mut failed, mut na) = ([0; 3], [0; 3], [0; 3], [0; 3]);
    for line in text.lines() {
        let x: Vec<&str> = line.splitn(8, '|').collect();
        if x.len() < 8 {
            continue;
        }
        let expected = x[2] == "valid";
        let (t, r, good): (usize, Out, Box<dyn Fn(&(Vec<u8>, Vec<u8>)) -> bool>) = match x[0] {
            "D" => {
                let (seed, ek, c, k) = (hex(x[3]), hex(x[4]), hex(x[5]), hex(x[6]));
                let r = if seed.len() != 64 { Some(None) } else { std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (l.seed)(&seed, &c))).unwrap_or(Some(None)) };
                (0, r, Box::new(move |o| o.1 == k && (o.0.is_empty() || ek.is_empty() || o.0 == ek)))
            }
            "E" => {
                let (m, ek, c, k) = (hex(x[3]), hex(x[4]), hex(x[5]), hex(x[6]));
                let r = if m.len() != 32 { Some(None) } else { std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (l.encaps)(&ek, &m))).unwrap_or(Some(None)) };
                (1, r, Box::new(move |o| o.0.is_empty() || (o.0 == c && o.1 == k)))
            }
            "X" => {
                let (dk, c, k) = (hex(x[3]), hex(x[4]), hex(x[5]));
                let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| (l.dk)(&dk, &c))).unwrap_or(Some(None));
                (2, r, Box::new(move |o| o.1 == k))
            }
            _ => continue,
        };
        let Some(r) = r else {
            na[t] += 1;
            continue;
        };
        n[t] += 1;
        let ok = r.is_some();
        if expected && !r.as_ref().map(|o| good(o)).unwrap_or(false) {
            failed[t] += 1;
            println!("  valid fails       [{}] tcId={}  {}", kinds[t], x[1], x[7]);
        }
        if !expected && ok {
            accepted[t] += 1;
            println!("  INVALID ACCEPTED  [{}] tcId={}  {}", kinds[t], x[1], x[7]);
        }
    }
    print!("{:<30}", l.name);
    for t in 0..3 {
        if n[t] == 0 && na[t] > 0 {
            print!(" | {}: no interface", kinds[t]);
        } else {
            print!(" | {}: {} vectors, INVALID ACCEPTED={}, valid fails={}", kinds[t], n[t], accepted[t], failed[t]);
        }
    }
    println!();
}

macro_rules! libcrux {
    ($name:literal, $($m:ident)::+, $ekn:literal, $dkn:literal, $ctn:literal, $f:expr) => {{
        use libcrux_ml_kem::$($m)::+ as m;
        use libcrux_ml_kem::{MlKemCiphertext, MlKemPrivateKey, MlKemPublicKey};
        run(
            &Lib {
                name: $name,
                seed: &|seed, c| {
                    let kp = m::generate_key_pair(seed.try_into().unwrap());
                    let Ok(c) = <[u8; $ctn]>::try_from(c) else { return Some(None) };
                    let k = m::decapsulate(kp.private_key(), &MlKemCiphertext::<$ctn>::from(c));
                    Some(Some((kp.pk().to_vec(), k.to_vec())))
                },
                encaps: &|ek, mm| {
                    let Ok(ek) = <[u8; $ekn]>::try_from(ek) else { return Some(None) };
                    let pk = MlKemPublicKey::<$ekn>::from(ek);
                    if !m::validate_public_key(&pk) {
                        return Some(None);
                    }
                    let (c, k) = m::encapsulate(&pk, mm.try_into().unwrap());
                    Some(Some((c.as_slice().to_vec(), k.to_vec())))
                },
                dk: &|dk, c| {
                    let Ok(dk) = <[u8; $dkn]>::try_from(dk) else { return Some(None) };
                    let Ok(c) = <[u8; $ctn]>::try_from(c) else { return Some(None) };
                    let (sk, ct) = (MlKemPrivateKey::<$dkn>::from(dk), MlKemCiphertext::<$ctn>::from(c));
                    if !m::validate_private_key(&sk, &ct) {
                        return Some(None);
                    }
                    Some(Some((Vec::new(), m::decapsulate(&sk, &ct).to_vec())))
                },
            },
            &$f,
        );
    }};
}

macro_rules! rustcrypto {
    ($name:literal, $p:ty, $f:expr) => {{
        use ml_kem::kem::Decapsulate;
        run(
            &Lib {
                name: $name,
                seed: &|seed, c| {
                    let dk = ml_kem::DecapsulationKey::<$p>::from_seed(seed.try_into().unwrap());
                    let Ok(c) = ml_kem::Ciphertext::<$p>::try_from(c) else { return Some(None) };
                    Some(Some((Vec::new(), dk.decapsulate(&c).to_vec())))
                },
                encaps: &|ek, mm| {
                    let Ok(ek) = ek.try_into() else { return Some(None) };
                    let Ok(ek) = ml_kem::EncapsulationKey::<$p>::new(&ek) else { return Some(None) };
                    let (c, k) = ek.encapsulate_deterministic(&mm.try_into().unwrap());
                    Some(Some((c.to_vec(), k.to_vec())))
                },
                dk: &|_, _| None,
            },
            &$f,
        );
    }};
}

fn main() {
    std::panic::set_hook(Box::new(|_| {}));
    let d = std::env::args().nth(1).expect("usage: wycheproof-mlkem <directory>");
    let f = |p: &str| format!("{d}/mlkem_{p}.txt");

    rustcrypto!("RustCrypto ML-KEM-512", ml_kem::MlKem512, f("512"));
    rustcrypto!("RustCrypto ML-KEM-768", ml_kem::MlKem768, f("768"));
    rustcrypto!("RustCrypto ML-KEM-1024", ml_kem::MlKem1024, f("1024"));

    libcrux!("libcrux ML-KEM-512 (auto)", mlkem512, 800, 1632, 768, f("512"));
    libcrux!("libcrux ML-KEM-768 (auto)", mlkem768, 1184, 2400, 1088, f("768"));
    libcrux!("libcrux ML-KEM-1024 (auto)", mlkem1024, 1568, 3168, 1568, f("1024"));
    libcrux!("libcrux ML-KEM-512 (portable)", mlkem512::portable, 800, 1632, 768, f("512"));
    libcrux!("libcrux ML-KEM-768 (portable)", mlkem768::portable, 1184, 2400, 1088, f("768"));
    libcrux!("libcrux ML-KEM-1024 (portable)", mlkem1024::portable, 1568, 3168, 1568, f("1024"));
    #[cfg(target_arch = "x86_64")]
    libcrux!("libcrux ML-KEM-512 (avx2)", mlkem512::avx2, 800, 1632, 768, f("512"));
    #[cfg(target_arch = "aarch64")]
    libcrux!("libcrux ML-KEM-512 (neon)", mlkem512::neon, 800, 1632, 768, f("512"));
    #[cfg(target_arch = "x86_64")]
    libcrux!("libcrux ML-KEM-768 (avx2)", mlkem768::avx2, 1184, 2400, 1088, f("768"));
    #[cfg(target_arch = "aarch64")]
    libcrux!("libcrux ML-KEM-768 (neon)", mlkem768::neon, 1184, 2400, 1088, f("768"));
    #[cfg(target_arch = "x86_64")]
    libcrux!("libcrux ML-KEM-1024 (avx2)", mlkem1024::avx2, 1568, 3168, 1568, f("1024"));
    #[cfg(target_arch = "aarch64")]
    libcrux!("libcrux ML-KEM-1024 (neon)", mlkem1024::neon, 1568, 3168, 1568, f("1024"));
}
