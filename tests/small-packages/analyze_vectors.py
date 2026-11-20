#!/usr/bin/env python3
"""Diagnosis of a feature of the ML-KEM vectors that explains the KyberNET result: valid D vectors whose seed has d or
z set to zero (KyberNET rejects all-zero randomness when it generates the key).

Usage:  python3 -I analyze_vectors.py <directory with mlkem_*.txt>

Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
"""
import sys

for p in (512, 768, 1024):
    zeros = {}
    for line in open(f"{sys.argv[1]}/mlkem_{p}.txt", encoding="utf-8"):
        x = line.rstrip("\n").split("|")
        if x[0] == "D" and x[2] == "valid":
            s = bytes.fromhex(x[3])
            d0, z0 = s[:32] == bytes(32), s[32:] == bytes(32)
            if d0 or z0:
                key = ("d=0 " if d0 else "") + ("z=0 " if z0 else "") + x[7]
                zeros[key] = zeros.get(key, 0) + 1
    print(f"== ML-KEM-{p}")
    for c, n in sorted(zeros.items()):
        print(f"   valid D with a zero seed half: {n:3d}  {c}")
