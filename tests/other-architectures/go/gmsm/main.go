// Wycheproof vectors (ML-KEM and ML-DSA) against the mlkem and mldsa packages of github.com/emmansun/gmsm.
// Usage:  go run [-tags purego] ./gmsm <directory with mlkem_512.txt … mldsa_87.txt>
//
// Without tags, on amd64 the hand-written assembly is used (AVX2 if the CPU has it: variable useAVX2 in
// mlkem/field_amd64.go and mldsa/field_amd64.go). With -tags purego only the generic Go code is used.
//
// Public API used (gmsm v0.45.4):
//
//	ML-KEM: NewDecapsulationKeyFromSeedN(d||z) -> dk; dk.Decapsulate(c) -> (K, error), error only if the
//	        length of c is wrong; NewEncapsulationKeyN(ek) -> (ek, error), error if the length or the
//	        modulus is wrong; ek.EncapsulateInternal(&m) -> (K, c), exported fixed-randomness variant
//	        ("exclusively for use in tests"); NewDecapsulationKeyN(expanded dk) -> (dk, error).
//	ML-DSA: NewPublicKeyN(pk) -> (pk, error); pk.VerifyWithOptions(signature, message, &Options{Context})
//	        -> bool (true = signature accepted).
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/emmansun/gmsm/mldsa"
	"github.com/emmansun/gmsm/mlkem"

	"wycheproof/common"
)

type dkI interface {
	Decapsulate(c []byte) ([]byte, error)
}

type ekI interface {
	Bytes() []byte
	EncapsulateInternal(m *[32]byte) (sharedKey, ciphertext []byte)
}

// kem builds the three operations of a parameter set from its public functions.
func kem[DK dkI, EK ekI](name string, fromSeed func([]byte) (DK, error), ekOf func(DK) EK,
	newEK func([]byte) (EK, error), newDK func([]byte) (DK, error)) common.KEM {
	return common.KEM{
		Name: name,
		Seed: func(seed, c []byte) ([]byte, []byte, bool, bool) {
			dk, err := fromSeed(seed)
			if err != nil {
				return nil, nil, false, true
			}
			K, err := dk.Decapsulate(c)
			return ekOf(dk).Bytes(), K, err == nil, true
		},
		Encaps: func(ek, m []byte) ([]byte, []byte, bool, bool) {
			k, err := newEK(ek)
			if err != nil {
				return nil, nil, false, true
			}
			K, c := k.EncapsulateInternal((*[32]byte)(m))
			return c, K, true, true
		},
		DK: func(dkb, c []byte) ([]byte, bool, bool) {
			dk, err := newDK(dkb)
			if err != nil {
				return nil, false, true
			}
			K, err := dk.Decapsulate(c)
			return K, err == nil, true
		},
	}
}

func main() {
	d := os.Args[1]
	fmt.Printf("== gmsm v0.45.4, Go %s %s, variant=%s\n", runtime.Version(), runtime.GOARCH, variant)
	v := " (" + variant + ")"

	common.RunKEM(kem("gmsm ML-KEM-512"+v, mlkem.NewDecapsulationKeyFromSeed512,
		(*mlkem.DecapsulationKey512).EncapsulationKey, mlkem.NewEncapsulationKey512, mlkem.NewDecapsulationKey512), d+"/mlkem_512.txt")
	common.RunKEM(kem("gmsm ML-KEM-768"+v, mlkem.NewDecapsulationKeyFromSeed768,
		(*mlkem.DecapsulationKey768).EncapsulationKey, mlkem.NewEncapsulationKey768, mlkem.NewDecapsulationKey768), d+"/mlkem_768.txt")
	common.RunKEM(kem("gmsm ML-KEM-1024"+v, mlkem.NewDecapsulationKeyFromSeed1024,
		(*mlkem.DecapsulationKey1024).EncapsulationKey, mlkem.NewEncapsulationKey1024, mlkem.NewDecapsulationKey1024), d+"/mlkem_1024.txt")

	common.RunDSA("gmsm ML-DSA-44"+v, d+"/mldsa_44.txt", func(pk, msg, ctx, sig []byte) (bool, bool) {
		k, err := mldsa.NewPublicKey44(pk)
		if err != nil {
			return false, true
		}
		return k.VerifyWithOptions(sig, msg, &mldsa.Options{Context: ctx}), true
	})
	common.RunDSA("gmsm ML-DSA-65"+v, d+"/mldsa_65.txt", func(pk, msg, ctx, sig []byte) (bool, bool) {
		k, err := mldsa.NewPublicKey65(pk)
		if err != nil {
			return false, true
		}
		return k.VerifyWithOptions(sig, msg, &mldsa.Options{Context: ctx}), true
	})
	common.RunDSA("gmsm ML-DSA-87"+v, d+"/mldsa_87.txt", func(pk, msg, ctx, sig []byte) (bool, bool) {
		k, err := mldsa.NewPublicKey87(pk)
		if err != nil {
			return false, true
		}
		return k.VerifyWithOptions(sig, msg, &mldsa.Options{Context: ctx}), true
	})
}
