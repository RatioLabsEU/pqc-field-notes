// Go test programs: Wycheproof vectors against Go implementations of ML-KEM / ML-DSA.
// Exact versions tested; run.sh generates go.sum with "go mod tidy" in a copy of this directory.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
module wycheproof

go 1.26.0

require (
	github.com/emmansun/gmsm v0.45.4
	github.com/symbolicsoft/kyber-k2so v1.1.1
	github.com/tink-crypto/tink-go/v2 v2.9.0
)
