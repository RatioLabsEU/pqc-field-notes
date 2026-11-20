#!/usr/bin/env python3
"""Diagnosis (not a library test): how many SHAKE128 bytes SampleNTT (FIPS 203, algorithm 7) needs for each entry of
the matrix A of every encapsulation key in the ML-KEM vectors, and how many keys exceed a given limit. It shows
whether a package that asks for a fixed number of bytes (e.g. 840) falls short.

Usage:  python sampling_bytes.py <mlkem_<p>.txt file> <512|768|1024> [limit=840]

Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
"""
import sys
from hashlib import shake_128

Q = 3329


def bytes_needed(rho, i, j, cap=1 << 16):
    """Bytes of SHAKE128(rho||j||i) that SampleNTT consumes until it has 256 coefficients (3 bytes at a time)."""
    stream = shake_128(rho + bytes([j, i])).digest(cap)
    n = pos = 0
    while n < 256:
        c0, c1, c2 = stream[pos], stream[pos + 1], stream[pos + 2]
        d1 = c0 + 256 * (c1 % 16)
        d2 = c1 // 16 + 16 * c2
        if d1 < Q:
            n += 1
        if d2 < Q and n < 256:
            n += 1
        pos += 3
    return pos


def main():
    path, p = sys.argv[1], int(sys.argv[2])
    limit = int(sys.argv[3]) if len(sys.argv) > 3 else 840
    k = {512: 2, 768: 3, 1024: 4}[p]
    seen = {}
    for line in open(path, encoding="utf-8"):
        x = line.rstrip("\r\n").split("|")
        if len(x) < 8 or x[0] not in "DE" or len(x[4]) != 2 * (384 * k + 32):
            continue
        rho = bytes.fromhex(x[4])[-32:]
        if rho not in seen:
            seen[rho] = max(bytes_needed(rho, i, j) for i in range(k) for j in range(k))
        if seen[rho] > limit:
            print(f"  {x[0]} tcId={x[1]} {x[2]}: needs {seen[rho]} bytes (> {limit})  {x[7]}")
    print(f"ML-KEM-{p}: {len(seen)} distinct rho values; maximum bytes needed = {max(seen.values())}; "
          f"rho values above {limit} bytes = {sum(1 for v in seen.values() if v > limit)}")


if __name__ == "__main__":
    main()
