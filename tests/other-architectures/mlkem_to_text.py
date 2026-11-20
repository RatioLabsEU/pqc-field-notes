#!/usr/bin/env python3
"""Convert the Wycheproof ML-KEM vector files (JSON) to one test per line.

Line types (bytes in hex):
  D|tcId|result|seed|ek|c|K|comment     decapsulation with a key generated from a seed
  E|tcId|result|m|ek|c|K|comment        encapsulation with randomness m
  X|tcId|result|dk|c|K||comment         decapsulation with an expanded decapsulation key
Usage:  mlkem_to_text.py <testvectors_v1 dir> <512|768|1024> > mlkem_768.txt

Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
"""
import json
import os
import sys

folder, p = sys.argv[1], sys.argv[2]


def tests(name):
    path = os.path.join(folder, name)
    if not os.path.exists(path):
        return
    for g in json.load(open(path, encoding="utf-8"))["testGroups"]:
        for t in g["tests"]:
            comment = (t.get("comment", "") + " " + ",".join(t.get("flags", []))).replace("|", "/").strip()
            yield t, comment


for t, c in tests(f"mlkem_{p}_test.json"):
    print("|".join(["D", str(t["tcId"]), t["result"], t.get("seed", ""), t.get("ek", ""), t.get("c", ""), t.get("K", ""), c]))
for t, c in tests(f"mlkem_{p}_encaps_test.json"):
    print("|".join(["E", str(t["tcId"]), t["result"], t.get("m", ""), t.get("ek", ""), t.get("c", ""), t.get("K", ""), c]))
for t, c in tests(f"mlkem_{p}_semi_expanded_decaps_test.json"):
    print("|".join(["X", str(t["tcId"]), t["result"], t.get("dk", ""), t.get("c", ""), t.get("K", ""), "", c]))
