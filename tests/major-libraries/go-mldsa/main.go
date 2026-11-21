// Wycheproof ML-DSA verification vectors against Go (crypto/mldsa) and CIRCL.
// Usage:  go run . <directory with mldsa_44.txt, mldsa_65.txt, mldsa_87.txt>
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
package main

import (
	"bufio"
	"crypto/mldsa"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
)

type verifier func(pk, msg, ctx, sig []byte) bool

// safe turns a panic in the library into a rejection.
func safe(v verifier, pk, msg, ctx, sig []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	return v(pk, msg, ctx, sig)
}

func std(p mldsa.Parameters) verifier {
	return func(pk, msg, ctx, sig []byte) bool {
		k, err := mldsa.NewPublicKey(p, pk)
		if err != nil {
			return false
		}
		return mldsa.Verify(k, msg, sig, &mldsa.Options{Context: string(ctx)}) == nil
	}
}

func run(name, file string, v verifier) bool {
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("cannot open", file)
		return false
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	total, badAccepted, badRejected := 0, 0, 0
	for sc.Scan() {
		c := strings.SplitN(sc.Text(), "|", 7)
		if len(c) < 7 {
			continue
		}
		pk, _ := hex.DecodeString(c[2])
		msg, _ := hex.DecodeString(c[3])
		ctx, _ := hex.DecodeString(c[4])
		sig, _ := hex.DecodeString(c[5])
		total++
		expected := c[1] == "valid"
		ok := safe(v, pk, msg, ctx, sig)
		if ok && !expected {
			badAccepted++
			fmt.Printf("  INVALID ACCEPTED  tcId=%s  %s\n", c[0], c[6])
		}
		if !ok && expected {
			badRejected++
			fmt.Printf("  valid rejected    tcId=%s  %s\n", c[0], c[6])
		}
	}
	fmt.Printf("%-34s vectors=%d   INVALID ACCEPTED=%d   valid rejected=%d\n", name, total, badAccepted, badRejected)
	return badAccepted == 0 && badRejected == 0
}

func main() {
	d := os.Args[1]
	fmt.Println("Go", runtime.Version(), runtime.GOARCH)
	good := true
	good = run("Go crypto/mldsa ML-DSA-44", d+"/mldsa_44.txt", std(mldsa.MLDSA44())) && good
	good = run("Go crypto/mldsa ML-DSA-65", d+"/mldsa_65.txt", std(mldsa.MLDSA65())) && good
	good = run("Go crypto/mldsa ML-DSA-87", d+"/mldsa_87.txt", std(mldsa.MLDSA87())) && good
	good = run("CIRCL ML-DSA-44", d+"/mldsa_44.txt", func(pk, msg, ctx, sig []byte) bool {
		var k mldsa44.PublicKey
		return k.UnmarshalBinary(pk) == nil && mldsa44.Verify(&k, msg, ctx, sig)
	}) && good
	good = run("CIRCL ML-DSA-65", d+"/mldsa_65.txt", func(pk, msg, ctx, sig []byte) bool {
		var k mldsa65.PublicKey
		return k.UnmarshalBinary(pk) == nil && mldsa65.Verify(&k, msg, ctx, sig)
	}) && good
	good = run("CIRCL ML-DSA-87", d+"/mldsa_87.txt", func(pk, msg, ctx, sig []byte) bool {
		var k mldsa87.PublicKey
		return k.UnmarshalBinary(pk) == nil && mldsa87.Verify(&k, msg, ctx, sig)
	}) && good
	if !good {
		os.Exit(1)
	}
}
