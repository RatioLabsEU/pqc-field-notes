// Wycheproof ML-DSA vectors against SwiftDilithium (github.com/leif-ibsen/SwiftDilithium), through its public interface.
// Usage:  wycheproof-dilithium <directory with mldsa_*.txt>
//
// Format (hex, fields separated by "|"), produced by wycheproof_to_text.py:
//   tcId|result|public key|message|context|signature|comment
//
// Public interface used (Sources/SwiftDilithium/PublicKey.swift, version 3.6.0):
//   PublicKey(keyBytes:) throws: picks the parameter set from the length (throws if it matches none).
//   PublicKey.Verify(message:signature:context:) -> Bool: true = valid signature; false if the signature does not have
//     the right length or the context is longer than 255 bytes. Empty context = [] (the same as
//     Verify(message:signature:), which passes []).
// If PublicKey(keyBytes:) accepts a key whose length is that of ANOTHER parameter set, it is counted as a rejection and
// recorded separately.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import Foundation
import SwiftDilithium

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

let dir = CommandLine.arguments[1]
for (p, pkLen) in [("44", 1312), ("65", 1952), ("87", 2592)] {
    var total = 0, acc = 0, rej = 0, other = 0
    let text = try! String(contentsOfFile: "\(dir)/mldsa_\(p).txt", encoding: .utf8)
    for line in text.split(separator: "\n") {
        let x = line.split(separator: "|", omittingEmptySubsequences: false)
        if x.count < 7 { continue }
        let valid = x[1] == "valid"
        var ok = false
        var err = ""
        do {
            let pk = try PublicKey(keyBytes: hex(x[2]))
            if pk.keyBytes.count != pkLen { other += 1; err = "key of another set" }
            else { ok = pk.Verify(message: hex(x[3]), signature: hex(x[5]), context: hex(x[4])) }
        } catch {
            err = "\(error)"
        }
        total += 1
        if ok && !valid { acc += 1; print("  INVALID ACCEPTED  tcId=\(x[0])  \(x[6])") }
        if !ok && valid { rej += 1; print("  valid rejected    tcId=\(x[0]) (\(err.isEmpty ? "false" : "error " + err))  \(x[6])") }
    }
    var s = "SwiftDilithium 3.6.0 ML-DSA-\(p)".padding(toLength: 34, withPad: " ", startingAt: 0)
    s += "  vectors=\(total)   INVALID ACCEPTED=\(acc)   valid rejected=\(rej)"
    if other > 0 { s += "   (PublicKey(keyBytes:) gave another parameter set \(other) times; counted as rejections)" }
    print(s)
}
