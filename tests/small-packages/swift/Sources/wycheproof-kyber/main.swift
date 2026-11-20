// Wycheproof ML-KEM vectors against SwiftKyber (github.com/leif-ibsen/SwiftKyber), through its public interface.
// Usage:  wycheproof-kyber <directory with mlkem_*.txt>
//
// Format (hex, fields separated by "|"), produced by mlkem_to_text.py:
//   D|tcId|result|seed d||z|ek|c|K|comment     generate the key from the seed and decapsulate c
//   E|tcId|result|m|ek|c|K|comment             encapsulate with ek and the randomness m
//   X|tcId|result|dk|c|K||comment              decapsulate with the expanded decapsulation key
//
// Public interface used (Sources/SwiftKyber/*.swift, version 3.5.0):
//   Kyber.DeriveKeyPair(kind:ikm:) throws -> (encap, decap); ikm = 64-byte d||z (throws if it is not 64 bytes).
//   EncapsulationKey(keyBytes:) throws: picks the parameter set from the length and does the FIPS 203 modulus check.
//   EncapsulationKey.Encapsulate() -> (K, ct) with internal randomness: there is no public way to fix m, so for the
//     E vectors only acceptance of the key is checked ("no interface" for comparing c and K).
//   DecapsulationKey(keyBytes:) throws: picks the parameter set from the length, checks H(ek) and the embedded ek.
//   DecapsulationKey.Decapsulate(ct:) throws -> K; throws if the length of ct is not that of the parameter set.
// If an init(keyBytes:) accepts a key whose length is that of ANOTHER parameter set, it is counted as a rejection (it
// is what a caller who knows which set it expects would do) and recorded separately.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import Foundation
import SwiftKyber

func hex(_ s: Substring) -> [UInt8] {
    var b = [UInt8](); b.reserveCapacity(s.count / 2)
    var i = s.startIndex
    while i < s.endIndex {
        let j = s.index(i, offsetBy: 2)
        b.append(UInt8(s[i ..< j], radix: 16)!)
        i = j
    }
    return b
}

struct Res { var ok: Bool; var ek: [UInt8]? = nil; var K: [UInt8]? = nil; var err: String = ""; var other = false }

let dir = CommandLine.arguments[1]
let kinds = ["seed", "encaps", "expanded dk"]
let sets: [(String, Kind, Int, Int)] = [("512", .K512, 800, 1632), ("768", .K768, 1184, 2400), ("1024", .K1024, 1568, 3168)]

for (p, kind, ekLen, dkLen) in sets {
    var n = [0, 0, 0], acc = [0, 0, 0], fail = [0, 0, 0], other = 0
    let text = try! String(contentsOfFile: "\(dir)/mlkem_\(p).txt", encoding: .utf8)
    for line in text.split(separator: "\n") {
        let x = line.split(separator: "|", omittingEmptySubsequences: false)
        if x.count < 8 { continue }
        let t = x[0] == "D" ? 0 : x[0] == "E" ? 1 : 2
        let valid = x[2] == "valid"
        var r: Res
        var good = false
        do {
            if t == 0 {
                let (encap, decap) = try Kyber.DeriveKeyPair(kind: kind, ikm: hex(x[3]))
                r = Res(ok: true, ek: encap.keyBytes, K: try decap.Decapsulate(ct: hex(x[5])))
                good = r.K! == hex(x[6]) && (x[4].isEmpty || r.ek! == hex(x[4]))
            } else if t == 1 {
                let ek = try EncapsulationKey(keyBytes: hex(x[4]))
                if ek.keyBytes.count != ekLen { r = Res(ok: false, err: "ek of another set", other: true) }
                else { _ = ek.Encapsulate(); r = Res(ok: true); good = true }   // for the valid ones, only that it does not fail
            } else {
                let dk = try DecapsulationKey(keyBytes: hex(x[3]))
                if dk.keyBytes.count != dkLen { r = Res(ok: false, err: "dk of another set", other: true) }
                else { r = Res(ok: true, K: try dk.Decapsulate(ct: hex(x[4]))); good = r.K! == hex(x[5]) }
            }
        } catch {
            r = Res(ok: false, err: "\(error)")
        }
        if r.other { other += 1 }
        n[t] += 1
        if valid && !good { fail[t] += 1; print("  valid fails       [\(kinds[t])] tcId=\(x[1]) (\(r.ok ? "different result" : "error " + r.err))  \(x[7])") }
        if !valid && r.ok { acc[t] += 1; print("  INVALID ACCEPTED  [\(kinds[t])] tcId=\(x[1])  \(x[7])") }
    }
    var s = "SwiftKyber 3.5.0 ML-KEM-\(p)".padding(toLength: 30, withPad: " ", startingAt: 0)
    for t in 0 ..< 3 {
        s += " | \(kinds[t])\(t == 1 ? " (key acceptance only)" : ""): \(n[t]) vectors, INVALID ACCEPTED=\(acc[t]), valid fails=\(fail[t])"
    }
    if other > 0 { s += " | (init(keyBytes:) gave another parameter set \(other) times; counted as rejections)" }
    print(s)
}
