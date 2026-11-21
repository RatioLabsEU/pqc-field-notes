// Wycheproof ML-KEM vectors against Go (crypto/mlkem) and CIRCL.
// Usage:  go run . <directory with mlkem_512.txt, mlkem_768.txt, mlkem_1024.txt>
//
// Each operation returns (output..., ok, supported): ok = the library performed the operation (it accepted the input);
// supported = false when the library has no interface for it. Go's crypto/mlkem has no ML-KEM-512 and no import of
// expanded decapsulation keys; fixed-randomness encapsulation comes from crypto/mlkem/mlkemtest.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
package main

import (
	"bufio"
	"bytes"
	"crypto/mlkem"
	"crypto/mlkem/mlkemtest"
	"encoding/hex"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/cloudflare/circl/kem"
	"github.com/cloudflare/circl/kem/schemes"
)

type lib struct {
	name   string
	seed   func(seed, c []byte) (ek, K []byte, ok, supported bool)
	encaps func(ek, m []byte) (c, K []byte, ok, supported bool)
	dk     func(dk, c []byte) (K []byte, ok, supported bool)
}

func h(s string) []byte { b, _ := hex.DecodeString(s); return b }

func run(l lib, file string) {
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("cannot open", file)
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	var n, accepted, failed, na [3]int
	kinds := []string{"seed", "encaps", "expanded dk"}
	for sc.Scan() {
		x := strings.SplitN(sc.Text(), "|", 8)
		if len(x) < 8 {
			continue
		}
		expected := x[2] == "valid"
		var t int
		var ok, supported, good bool
		func() {
			defer func() {
				if recover() != nil { // a panic in the library counts as a rejection
					ok, supported, good = false, true, false
				}
			}()
			switch x[0] {
			case "D":
				t = 0
				seed, ekExp, c, kExp := h(x[3]), h(x[4]), h(x[5]), h(x[6])
				if len(seed) != 64 {
					ok, supported = false, true
					return
				}
				var ek, K []byte
				ek, K, ok, supported = l.seed(seed, c)
				good = ok && bytes.Equal(K, kExp) && (len(ek) == 0 || len(ekExp) == 0 || bytes.Equal(ek, ekExp))
			case "E":
				t = 1
				m, ek, cExp, kExp := h(x[3]), h(x[4]), h(x[5]), h(x[6])
				if len(m) != 32 {
					ok, supported = false, true
					return
				}
				var c, K []byte
				c, K, ok, supported = l.encaps(ek, m)
				good = ok && (len(c) == 0 || (bytes.Equal(c, cExp) && bytes.Equal(K, kExp)))
			case "X":
				t = 2
				var K []byte
				K, ok, supported = l.dk(h(x[3]), h(x[4]))
				good = ok && bytes.Equal(K, h(x[5]))
			}
		}()
		if !supported {
			na[t]++
			continue
		}
		n[t]++
		if expected && !good {
			failed[t]++
			fmt.Printf("  valid fails       [%s] tcId=%s  %s\n", kinds[t], x[1], x[7])
		}
		if !expected && ok {
			accepted[t]++
			fmt.Printf("  INVALID ACCEPTED  [%s] tcId=%s  %s\n", kinds[t], x[1], x[7])
		}
	}
	fmt.Printf("%-30s", l.name)
	for t := 0; t < 3; t++ {
		if n[t] == 0 && na[t] > 0 {
			fmt.Printf(" | %s: no interface", kinds[t])
		} else {
			fmt.Printf(" | %s: %d vectors, INVALID ACCEPTED=%d, valid fails=%d", kinds[t], n[t], accepted[t], failed[t])
		}
	}
	fmt.Println()
}

func circl(name string) lib {
	s := schemes.ByName(name)
	return lib{
		name: "CIRCL " + name,
		seed: func(seed, c []byte) ([]byte, []byte, bool, bool) {
			pk, sk := s.DeriveKeyPair(seed)
			ek, _ := pk.MarshalBinary()
			K, err := s.Decapsulate(sk, c)
			return ek, K, err == nil, true
		},
		encaps: func(ek, m []byte) ([]byte, []byte, bool, bool) {
			var pk kem.PublicKey
			pk, err := s.UnmarshalBinaryPublicKey(ek)
			if err != nil {
				return nil, nil, false, true
			}
			c, K, err := s.EncapsulateDeterministically(pk, m)
			return c, K, err == nil, true
		},
		dk: func(dk, c []byte) ([]byte, bool, bool) {
			sk, err := s.UnmarshalBinaryPrivateKey(dk)
			if err != nil {
				return nil, false, true
			}
			K, err := s.Decapsulate(sk, c)
			return K, err == nil, true
		},
	}
}

func main() {
	d := os.Args[1]
	fmt.Println("Go", runtime.Version(), runtime.GOARCH)
	noDK := func(dk, c []byte) ([]byte, bool, bool) { return nil, false, false }
	run(lib{"Go crypto/mlkem ML-KEM-768",
		func(seed, c []byte) ([]byte, []byte, bool, bool) {
			dk, err := mlkem.NewDecapsulationKey768(seed)
			if err != nil {
				return nil, nil, false, true
			}
			K, err := dk.Decapsulate(c)
			return dk.EncapsulationKey().Bytes(), K, err == nil, true
		},
		func(ek, m []byte) ([]byte, []byte, bool, bool) {
			k, err := mlkem.NewEncapsulationKey768(ek)
			if err != nil {
				return nil, nil, false, true
			}
			K, c, err := mlkemtest.Encapsulate768(k, m)
			return c, K, err == nil, true
		}, noDK}, d+"/mlkem_768.txt")
	run(lib{"Go crypto/mlkem ML-KEM-1024",
		func(seed, c []byte) ([]byte, []byte, bool, bool) {
			dk, err := mlkem.NewDecapsulationKey1024(seed)
			if err != nil {
				return nil, nil, false, true
			}
			K, err := dk.Decapsulate(c)
			return dk.EncapsulationKey().Bytes(), K, err == nil, true
		},
		func(ek, m []byte) ([]byte, []byte, bool, bool) {
			k, err := mlkem.NewEncapsulationKey1024(ek)
			if err != nil {
				return nil, nil, false, true
			}
			K, c, err := mlkemtest.Encapsulate1024(k, m)
			return c, K, err == nil, true
		}, noDK}, d+"/mlkem_1024.txt")
	run(circl("ML-KEM-512"), d+"/mlkem_512.txt")
	run(circl("ML-KEM-768"), d+"/mlkem_768.txt")
	run(circl("ML-KEM-1024"), d+"/mlkem_1024.txt")
}
