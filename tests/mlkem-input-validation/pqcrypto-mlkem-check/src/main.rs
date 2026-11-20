//! Run the Wycheproof ML-KEM vectors that carry an explicit key against the `pqcrypto-mlkem` crate
//! (which wraps PQClean).
//!
//!   E  encapsulation with a given encapsulation key (invalid keys must be rejected)
//!   X  decapsulation with a given expanded decapsulation key (invalid keys must be rejected)
//!
//! Usage:  pqcrypto-mlkem-check <dir with mlkem_512.txt, mlkem_768.txt, mlkem_1024.txt>
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

use pqcrypto_traits::kem::{Ciphertext, PublicKey, SecretKey, SharedSecret};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

macro_rules! run {
    ($label:literal, $m:ident, $file:expr) => {{
        use pqcrypto_mlkem::$m as m;
        let text = std::fs::read_to_string($file).expect("vector file");
        let kinds = ["encaps", "expanded dk"];
        let (mut n, mut accepted, mut failed) = ([0; 2], [0; 2], [0; 2]);
        for line in text.lines() {
            let x: Vec<&str> = line.splitn(8, '|').collect();
            if x.len() < 8 {
                continue;
            }
            let expected = x[2] == "valid";
            let (t, ok, good) = match x[0] {
                "E" => {
                    // Randomness cannot be fixed through this API: only acceptance is checked.
                    let ok = unhex(x[3]).len() == 32 && m::PublicKey::from_bytes(&unhex(x[4])).map(|pk| m::encapsulate(&pk)).is_ok();
                    (0, ok, ok)
                }
                "X" => match (m::SecretKey::from_bytes(&unhex(x[3])), m::Ciphertext::from_bytes(&unhex(x[4]))) {
                    (Ok(sk), Ok(ct)) => (1, true, m::decapsulate(&ct, &sk).as_bytes() == unhex(x[5]).as_slice()),
                    _ => (1, false, false),
                },
                _ => continue,
            };
            n[t] += 1;
            if expected && !good {
                failed[t] += 1;
                println!("  VALID FAILED      [{}] tcId={}  {}", kinds[t], x[1], x[7]);
            }
            if !expected && ok {
                accepted[t] += 1;
                println!("  INVALID ACCEPTED  [{}] tcId={}  {}", kinds[t], x[1], x[7]);
            }
        }
        print!("pqcrypto-mlkem 0.1.1 {:<12}", $label);
        for t in 0..2 {
            print!(" | {}: {} vectors, INVALID ACCEPTED={}, VALID FAILED={}", kinds[t], n[t], accepted[t], failed[t]);
        }
        println!();
    }};
}

fn main() {
    let dir = std::env::args().nth(1).expect("usage: pqcrypto-mlkem-check <vector dir>");
    run!("ML-KEM-512", mlkem512, format!("{dir}/mlkem_512.txt"));
    run!("ML-KEM-768", mlkem768, format!("{dir}/mlkem_768.txt"));
    run!("ML-KEM-1024", mlkem1024, format!("{dir}/mlkem_1024.txt"));
}
