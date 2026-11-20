//! Shared part of the Rust test programs (rust/*).
//! Reads the Wycheproof vectors already converted to text (by mlkem_to_text.py and wycheproof_to_text.py)
//! and counts, per vector type, how many invalid vectors the library accepts and how many valid ones it fails.
//!
//! Convention for each library's functions:
//!   None              = the library has no public interface for that operation ("no interface");
//!   Some(None)        = the library rejects the input (error, or a fixed-length type that does not fit);
//!   Some(Some(data))  = the library accepts the input and returns (first, K): first = ek or c.
//! A panic in the library counts as a rejection, but it is reported separately with the word PANIC.
//!
//! Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
#![allow(dead_code)]

use std::panic::{AssertUnwindSafe, catch_unwind};

pub type Out = Option<Option<(Vec<u8>, Vec<u8>)>>;

pub fn hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

/// Calls `f` catching a panic; if there is one, it is reported and counted as a rejection.
fn guard<T>(kind: &str, tc: &str, comment: &str, rejection: T, f: impl FnOnce() -> T) -> T {
    match catch_unwind(AssertUnwindSafe(f)) {
        Ok(r) => r,
        Err(_) => {
            println!("  PANIC             [{kind}] tcId={tc}  {comment}");
            rejection
        }
    }
}

pub struct Lib<'a> {
    pub name: &'a str,
    /// (64-byte seed d||z, c) -> (generated ek, K)
    pub seed: &'a dyn Fn(&[u8], &[u8]) -> Out,
    /// (ek, 32-byte m) -> (c, K)
    pub encaps: &'a dyn Fn(&[u8], &[u8]) -> Out,
    /// (expanded dk, c) -> (empty, K)
    pub dk: &'a dyn Fn(&[u8], &[u8]) -> Out,
}

/// Runs an mlkem_<n>.txt file through the three operations of the library.
pub fn run_kem(l: &Lib, file: &str) {
    let text = std::fs::read_to_string(file).expect("vector file");
    let kinds = ["seed", "encaps", "expanded dk"];
    let (mut n, mut accepted, mut failed, mut na) = ([0; 3], [0; 3], [0; 3], [0; 3]);
    // Is there a seed interface? (so that seeds of the wrong length are not counted as "rejected" if there is none)
    let with_seed = catch_unwind(AssertUnwindSafe(|| (l.seed)(&[0u8; 64], &[]))).map(|r| r.is_some()).unwrap_or(true);
    for line in text.lines() {
        let x: Vec<&str> = line.splitn(8, '|').collect();
        if x.len() < 8 {
            continue;
        }
        let expected = x[2] == "valid";
        let (tc, comment) = (x[1], x[7]);
        let (t, r, good): (usize, Out, Box<dyn Fn(&(Vec<u8>, Vec<u8>)) -> bool>) = match x[0] {
            "D" => {
                let (seed, ek, c, k) = (hex(x[3]), hex(x[4]), hex(x[5]), hex(x[6]));
                // no seed interface: "no interface"; a seed that is not 64 bytes long fits no interface: it is
                // counted as a rejection
                let r = if !with_seed {
                    None
                } else if seed.len() != 64 {
                    Some(None)
                } else {
                    guard(&format!("{} · {}", l.name, kinds[0]), tc, comment, Some(None), || (l.seed)(&seed, &c))
                };
                // K must match; so must the generated ek, if the library returns it and the vector carries it
                (0, r, Box::new(move |o| o.1 == k && (o.0.is_empty() || ek.is_empty() || o.0 == ek)))
            }
            "E" => {
                let (m, ek, c, k) = (hex(x[3]), hex(x[4]), hex(x[5]), hex(x[6]));
                let r = if m.len() != 32 { Some(None) } else { guard(&format!("{} · {}", l.name, kinds[1]), tc, comment, Some(None), || (l.encaps)(&ek, &m)) };
                // if the library does not let the caller fix m (it returns an empty c), only acceptance of the ek can be checked
                (1, r, Box::new(move |o| o.0.is_empty() || (o.0 == c && o.1 == k)))
            }
            "X" => {
                let (dk, c, k) = (hex(x[3]), hex(x[4]), hex(x[5]));
                let r = guard(&format!("{} · {}", l.name, kinds[2]), tc, comment, Some(None), || (l.dk)(&dk, &c));
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
            let why = if ok { "different result" } else { "rejected" };
            println!("  valid fails       [{} · {}] tcId={}  {}  ({why})", l.name, kinds[t], tc, comment);
        }
        if !expected && ok {
            accepted[t] += 1;
            println!("  INVALID ACCEPTED  [{} · {}] tcId={}  {}", l.name, kinds[t], tc, comment);
        }
    }
    print!("{:<34}", l.name);
    for t in 0..3 {
        if n[t] == 0 && na[t] > 0 {
            print!(" | {}: no interface", kinds[t]);
        } else {
            print!(" | {}: {} vectors, INVALID ACCEPTED={}, valid fails={}", kinds[t], n[t], accepted[t], failed[t]);
        }
    }
    println!();
}

/// ML-DSA verifier: (public key, message, context, signature) -> Some(accepts) or None if there is no interface
/// (for example, a non-empty context in a library that does not take one).
pub type Verifier<'a> = &'a dyn Fn(&[u8], &[u8], &[u8], &[u8]) -> Option<bool>;

/// Runs an mldsa_<n>.txt file through the library's verification.
pub fn run_dsa(name: &str, file: &str, v: Verifier) {
    let text = std::fs::read_to_string(file).expect("vector file");
    let (mut total, mut bad_accepted, mut bad_rejected, mut na) = (0, 0, 0, 0);
    for line in text.lines() {
        let c: Vec<&str> = line.splitn(7, '|').collect();
        if c.len() < 7 {
            continue;
        }
        let (pk, msg, ctx, sig) = (hex(c[2]), hex(c[3]), hex(c[4]), hex(c[5]));
        let expected = c[1] == "valid";
        let Some(ok) = guard(name, c[0], c[6], Some(false), || v(&pk, &msg, &ctx, &sig)) else {
            na += 1;
            continue;
        };
        total += 1;
        if ok && !expected {
            bad_accepted += 1;
            println!("  INVALID ACCEPTED  [{name}] tcId={}  {}", c[0], c[6]);
        }
        if !ok && expected {
            bad_rejected += 1;
            println!("  valid rejected    [{name}] tcId={}  {}", c[0], c[6]);
        }
    }
    let none = if na > 0 { format!("   no interface={na}") } else { String::new() };
    println!("{name:<34} vectors={total}   INVALID ACCEPTED={bad_accepted}   valid rejected={bad_rejected}{none}");
}

/// Silences panic messages (they are counted separately by guard).
pub fn silence_panic_messages() {
    std::panic::set_hook(Box::new(|_| {}));
}
