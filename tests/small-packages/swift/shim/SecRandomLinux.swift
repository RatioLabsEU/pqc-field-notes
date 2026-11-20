// Platform patch to build SwiftKyber, SwiftDilithium and their dependency BigInt (by Leif Ibsen) on Linux.
// All three call SecRandomCopyBytes(kSecRandomDefault, n, &buf) == errSecSuccess, which belongs to Apple's
// Security.framework and does not exist in Linux Foundation. run.sh copies this file into each of them
// (swift package edit). It does not touch the cryptography: it only gives system randomness (SystemRandomNumberGenerator
// uses getrandom on Linux) to the functions that generate keys or encapsulate at random. The Wycheproof test uses
// deterministic paths (DeriveKeyPair, Decapsulate, Verify) except Encapsulate(), where only acceptance of the key is
// checked.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
#if os(Linux)
let kSecRandomDefault: OpaquePointer? = nil
let errSecSuccess: Int32 = 0

func SecRandomCopyBytes(_ rnd: OpaquePointer?, _ count: Int, _ bytes: UnsafeMutableRawPointer) -> Int32 {
    var g = SystemRandomNumberGenerator()
    for i in 0 ..< count {
        bytes.storeBytes(of: UInt8.random(in: 0 ... 255, using: &g), toByteOffset: i, as: UInt8.self)
    }
    return errSecSuccess
}
#endif
