// Wycheproof vectors (ML-KEM) against github.com/symbolicsoft/kyber-k2so.
// Usage:  go run ./k2so <directory with mlkem_512.txt, mlkem_768.txt, mlkem_1024.txt>
//
// Public API used (kyber-k2so v1.1.1, kem.go). All functions work with fixed-length arrays, so an input of a
// different length does not fit the interface and is counted as a rejection:
//
//	KemKeypairDerandN(d||z [64]byte) -> (sk, pk, error)
//	KemEncryptDerandN(pk, m [32]byte) -> (c, K, error); error ErrInvalidEncapsulationKey if the
//	    FIPS 203 §7.2 modulus check fails
//	KemDecryptN(c, sk) -> (K, error); error ErrInvalidDecapsulationKey if the FIPS 203 §7.3 hash
//	    check fails
//
// That what is tested is ML-KEM and not round-3 Kyber can be seen in the code (indcpa.go: G(d||k) in key
// generation; kem.go: K = G(m||H(ek)) without hashing m or c, implicit rejection with SHAKE256(z||c)) and in
// the fact that the valid Wycheproof vectors (which are ML-KEM vectors) must come out equal.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
package main

import (
	"fmt"
	"os"
	"runtime"

	k2so "github.com/symbolicsoft/kyber-k2so"

	"wycheproof/common"
)

// fits copies b into dst (a fixed-length array seen as a slice); false if the length does not match.
func fits(dst, b []byte) bool {
	if len(b) != len(dst) {
		return false
	}
	copy(dst, b)
	return true
}

func main() {
	d := os.Args[1]
	fmt.Printf("== kyber-k2so v1.1.1, Go %s %s\n", runtime.Version(), runtime.GOARCH)

	common.RunKEM(common.KEM{
		Name: "kyber-k2so ML-KEM-512",
		Seed: func(seed, c []byte) ([]byte, []byte, bool, bool) {
			sk, pk, err := k2so.KemKeypairDerand512([64]byte(seed))
			if err != nil {
				return nil, nil, false, true
			}
			var ct [k2so.Kyber512CTBytes]byte
			ok := fits(ct[:], c)
			if !ok {
				return nil, nil, false, true
			}
			K, err := k2so.KemDecrypt512(ct, sk)
			return pk[:], K[:], err == nil, true
		},
		Encaps: func(ek, m []byte) ([]byte, []byte, bool, bool) {
			var pk [k2so.Kyber512PKBytes]byte
			ok := fits(pk[:], ek)
			if !ok {
				return nil, nil, false, true
			}
			c, K, err := k2so.KemEncryptDerand512(pk, [32]byte(m))
			return c[:], K[:], err == nil, true
		},
		DK: func(dk, c []byte) ([]byte, bool, bool) {
			var sk [k2so.Kyber512SKBytes]byte
			ok1 := fits(sk[:], dk)
			var ct [k2so.Kyber512CTBytes]byte
			ok2 := fits(ct[:], c)
			if !ok1 || !ok2 {
				return nil, false, true
			}
			K, err := k2so.KemDecrypt512(ct, sk)
			return K[:], err == nil, true
		},
	}, d+"/mlkem_512.txt")

	common.RunKEM(common.KEM{
		Name: "kyber-k2so ML-KEM-768",
		Seed: func(seed, c []byte) ([]byte, []byte, bool, bool) {
			sk, pk, err := k2so.KemKeypairDerand768([64]byte(seed))
			if err != nil {
				return nil, nil, false, true
			}
			var ct [k2so.Kyber768CTBytes]byte
			ok := fits(ct[:], c)
			if !ok {
				return nil, nil, false, true
			}
			K, err := k2so.KemDecrypt768(ct, sk)
			return pk[:], K[:], err == nil, true
		},
		Encaps: func(ek, m []byte) ([]byte, []byte, bool, bool) {
			var pk [k2so.Kyber768PKBytes]byte
			ok := fits(pk[:], ek)
			if !ok {
				return nil, nil, false, true
			}
			c, K, err := k2so.KemEncryptDerand768(pk, [32]byte(m))
			return c[:], K[:], err == nil, true
		},
		DK: func(dk, c []byte) ([]byte, bool, bool) {
			var sk [k2so.Kyber768SKBytes]byte
			ok1 := fits(sk[:], dk)
			var ct [k2so.Kyber768CTBytes]byte
			ok2 := fits(ct[:], c)
			if !ok1 || !ok2 {
				return nil, false, true
			}
			K, err := k2so.KemDecrypt768(ct, sk)
			return K[:], err == nil, true
		},
	}, d+"/mlkem_768.txt")

	common.RunKEM(common.KEM{
		Name: "kyber-k2so ML-KEM-1024",
		Seed: func(seed, c []byte) ([]byte, []byte, bool, bool) {
			sk, pk, err := k2so.KemKeypairDerand1024([64]byte(seed))
			if err != nil {
				return nil, nil, false, true
			}
			var ct [k2so.Kyber1024CTBytes]byte
			ok := fits(ct[:], c)
			if !ok {
				return nil, nil, false, true
			}
			K, err := k2so.KemDecrypt1024(ct, sk)
			return pk[:], K[:], err == nil, true
		},
		Encaps: func(ek, m []byte) ([]byte, []byte, bool, bool) {
			var pk [k2so.Kyber1024PKBytes]byte
			ok := fits(pk[:], ek)
			if !ok {
				return nil, nil, false, true
			}
			c, K, err := k2so.KemEncryptDerand1024(pk, [32]byte(m))
			return c[:], K[:], err == nil, true
		},
		DK: func(dk, c []byte) ([]byte, bool, bool) {
			var sk [k2so.Kyber1024SKBytes]byte
			ok1 := fits(sk[:], dk)
			var ct [k2so.Kyber1024CTBytes]byte
			ok2 := fits(ct[:], c)
			if !ok1 || !ok2 {
				return nil, false, true
			}
			K, err := k2so.KemDecrypt1024(ct, sk)
			return K[:], err == nil, true
		},
	}, d+"/mlkem_1024.txt")
}
