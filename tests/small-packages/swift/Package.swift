// swift-tools-version: 5.9
// Wycheproof vectors against SwiftKyber (ML-KEM) and SwiftDilithium (ML-DSA) by Leif Ibsen, through their public interface.
// Versions pinned with "exact" so that the log says exactly what was tested.
// One executable per package: both modules export types with the same names (Bytes, Kind, Exception).
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import PackageDescription

let package = Package(
    name: "WycheproofSwift",
    dependencies: [
        .package(url: "https://github.com/leif-ibsen/SwiftKyber", exact: "3.5.0"),
        .package(url: "https://github.com/leif-ibsen/SwiftDilithium", exact: "3.6.0"),
    ],
    targets: [
        .executableTarget(name: "wycheproof-kyber", dependencies: [.product(name: "SwiftKyber", package: "SwiftKyber")]),
        .executableTarget(name: "wycheproof-dilithium", dependencies: [.product(name: "SwiftDilithium", package: "SwiftDilithium")]),
    ]
)
