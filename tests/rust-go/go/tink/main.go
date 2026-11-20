// Wycheproof ML-DSA verification vectors against the signature/mldsa package of
// github.com/tink-crypto/tink-go/v2.
// Usage:  go run ./tink <directory with mldsa_44.txt, mldsa_65.txt, mldsa_87.txt>
//
// Public API used (tink-go v2.9.0): mldsa.NewParameters(instance, VariantNoPrefix) ->
// mldsa.NewPublicKey(key, 0, parameters) (error if the length is wrong) -> keyset.NewManager().AddKey
// -> SetPrimary -> Handle -> signature.NewVerifier(handle) -> Verify(signature, message) (nil = accepted).
// Tink does not let the caller pass a context: verifier.go calls Verify(data, signature, nil). Vectors with a
// non-empty context are left as "no interface".
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
package main

import (
	"fmt"
	"os"
	"runtime"

	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/signature"
	"github.com/tink-crypto/tink-go/v2/signature/mldsa"

	"wycheproof/common"
)

func verifier(inst mldsa.Instance) common.Verifier {
	return func(pk, msg, ctx, sig []byte) (bool, bool) {
		if len(ctx) > 0 {
			return false, false
		}
		par, err := mldsa.NewParameters(inst, mldsa.VariantNoPrefix)
		if err != nil {
			panic(err) // a fault of this program, not of the library
		}
		k, err := mldsa.NewPublicKey(pk, 0, par)
		if err != nil {
			return false, true
		}
		km := keyset.NewManager()
		id, err := km.AddKey(k)
		if err != nil {
			panic(err)
		}
		if err := km.SetPrimary(id); err != nil {
			panic(err)
		}
		h, err := km.Handle()
		if err != nil {
			panic(err)
		}
		v, err := signature.NewVerifier(h)
		if err != nil {
			panic(err)
		}
		return v.Verify(sig, msg) == nil, true
	}
}

func main() {
	d := os.Args[1]
	fmt.Printf("== tink-go v2.9.0 signature/mldsa, Go %s %s\n", runtime.Version(), runtime.GOARCH)
	common.RunDSA("tink-go ML-DSA-44", d+"/mldsa_44.txt", verifier(mldsa.MLDSA44))
	common.RunDSA("tink-go ML-DSA-65", d+"/mldsa_65.txt", verifier(mldsa.MLDSA65))
	common.RunDSA("tink-go ML-DSA-87", d+"/mldsa_87.txt", verifier(mldsa.MLDSA87))
}
