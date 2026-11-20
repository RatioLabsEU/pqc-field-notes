// Package common is the shared part of the Go test programs (go/*).
// It reads the Wycheproof vectors already converted to text (by mlkem_to_text.py and wycheproof_to_text.py)
// and counts, per vector type, how many invalid vectors the library accepts and how many valid ones it fails.
//
// Convention for each library's functions: they return (data..., ok, sop). sop = false if the library has no
// public interface for that operation ("no interface"); ok = the library accepted the input and returned data.
// A panic in the library counts as a rejection, but it is reported separately with the word PANIC.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
package common

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func h(s string) []byte { b, _ := hex.DecodeString(s); return b }

// KEM gathers the three operations that are tested in an ML-KEM library.
type KEM struct {
	Name   string
	Seed   func(seed, c []byte) (ek, K []byte, ok, sop bool) // 64-byte seed d||z
	Encaps func(ek, m []byte) (c, K []byte, ok, sop bool)    // 32-byte m
	DK     func(dk, c []byte) (K []byte, ok, sop bool)       // expanded decapsulation key
}

func lines(file string) []string {
	f, err := os.Open(file)
	if err != nil {
		fmt.Println("could not open", file)
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<22)
	var r []string
	for sc.Scan() {
		r = append(r, sc.Text())
	}
	return r
}

// RunKEM runs an mlkem_<n>.txt file through the three operations of the library.
func RunKEM(l KEM, file string) {
	var n, accepted, failed, na [3]int
	kinds := []string{"seed", "encaps", "expanded dk"}
	// Is there a seed interface? (so that seeds of the wrong length are not counted as "rejected" if there is none)
	withSeed := func() (sop bool) {
		defer func() {
			if recover() != nil {
				sop = true
			}
		}()
		_, _, _, sop = l.Seed(make([]byte, 64), nil)
		return sop
	}()
	for _, line := range lines(file) {
		x := strings.SplitN(line, "|", 8)
		if len(x) < 8 {
			continue
		}
		expected := x[2] == "valid"
		var t int
		var ok, sop, good bool
		func() {
			defer func() {
				if recover() != nil {
					fmt.Printf("  PANIC             [%s · %s] tcId=%s  %s\n", l.Name, kinds[t], x[1], x[7])
					ok, sop, good = false, true, false
				}
			}()
			switch x[0] {
			case "D":
				t = 0
				seed, ekExp, c, kExp := h(x[3]), h(x[4]), h(x[5]), h(x[6])
				if !withSeed {
					sop = false
					return
				}
				if len(seed) != 64 { // a seed of another length fits no interface: rejection
					ok, sop = false, true
					return
				}
				var ek, K []byte
				ek, K, ok, sop = l.Seed(seed, c)
				good = ok && bytes.Equal(K, kExp) && (len(ek) == 0 || len(ekExp) == 0 || bytes.Equal(ek, ekExp))
			case "E":
				t = 1
				m, ek, cExp, kExp := h(x[3]), h(x[4]), h(x[5]), h(x[6])
				if len(m) != 32 {
					ok, sop = false, true
					return
				}
				var c, K []byte
				c, K, ok, sop = l.Encaps(ek, m)
				good = ok && bytes.Equal(c, cExp) && bytes.Equal(K, kExp)
			case "X":
				t = 2
				var K []byte
				K, ok, sop = l.DK(h(x[3]), h(x[4]))
				good = ok && bytes.Equal(K, h(x[5]))
			default:
				t = -1
			}
		}()
		if t < 0 {
			continue
		}
		if !sop {
			na[t]++
			continue
		}
		n[t]++
		if expected && !good {
			failed[t]++
			why := "rejected"
			if ok {
				why = "different result"
			}
			fmt.Printf("  valid fails       [%s · %s] tcId=%s  %s  (%s)\n", l.Name, kinds[t], x[1], x[7], why)
		}
		if !expected && ok {
			accepted[t]++
			fmt.Printf("  INVALID ACCEPTED  [%s · %s] tcId=%s  %s\n", l.Name, kinds[t], x[1], x[7])
		}
	}
	fmt.Printf("%-34s", l.Name)
	for t := 0; t < 3; t++ {
		if n[t] == 0 && na[t] > 0 {
			fmt.Printf(" | %s: no interface", kinds[t])
		} else {
			fmt.Printf(" | %s: %d vectors, INVALID ACCEPTED=%d, valid fails=%d", kinds[t], n[t], accepted[t], failed[t])
		}
	}
	fmt.Println()
}

// Verifier for ML-DSA: returns (accepts, sop); sop = false if there is no interface for that vector.
type Verifier func(pk, msg, ctx, sig []byte) (ok, sop bool)

// RunDSA runs an mldsa_<n>.txt file through the library's verification.
func RunDSA(name, file string, v Verifier) {
	total, badAccepted, badRejected, na := 0, 0, 0, 0
	for _, line := range lines(file) {
		c := strings.SplitN(line, "|", 7)
		if len(c) < 7 {
			continue
		}
		pk, msg, ctx, sig := h(c[2]), h(c[3]), h(c[4]), h(c[5])
		expected := c[1] == "valid"
		var ok, sop bool
		func() {
			defer func() {
				if recover() != nil {
					fmt.Printf("  PANIC             [%s] tcId=%s  %s\n", name, c[0], c[6])
					ok, sop = false, true
				}
			}()
			ok, sop = v(pk, msg, ctx, sig)
		}()
		if !sop {
			na++
			continue
		}
		total++
		if ok && !expected {
			badAccepted++
			fmt.Printf("  INVALID ACCEPTED  [%s] tcId=%s  %s\n", name, c[0], c[6])
		}
		if !ok && expected {
			badRejected++
			fmt.Printf("  valid rejected    [%s] tcId=%s  %s\n", name, c[0], c[6])
		}
	}
	none := ""
	if na > 0 {
		none = fmt.Sprintf("   no interface=%d", na)
	}
	fmt.Printf("%-34s vectors=%d   INVALID ACCEPTED=%d   valid rejected=%d%s\n", name, total, badAccepted, badRejected, none)
}
