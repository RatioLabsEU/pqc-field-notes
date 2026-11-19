#!/usr/bin/env python3
"""Convert a Wycheproof ML-DSA verification vector file (JSON) to one test per line.

Line format (bytes in hex):  tcId|result|publicKey|msg|ctx|sig|comment
Usage:  wycheproof_to_text.py mldsa_65_verify_test.json > mldsa_65.txt
"""
import json
import sys

data = json.load(open(sys.argv[1], encoding="utf-8"))
for group in data["testGroups"]:
    pk = group.get("publicKey", "")
    for t in group["tests"]:
        comment = (t.get("comment", "") + " " + ",".join(t.get("flags", []))).replace("|", "/").strip()
        print("|".join([str(t["tcId"]), t["result"], pk, t.get("msg", ""), t.get("ctx", ""), t.get("sig", ""), comment]))
