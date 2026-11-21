#!/usr/bin/env python3
"""SLH-DSA (FIPS 205): converts the ACVP internalProjection.json files to text, one line per vector.

Usage:  python3 -I acvp_to_text.py <gen-val/json-files directory> <output directory>

Reads SLH-DSA-keyGen-FIPS205, SLH-DSA-sigGen-FIPS205 and SLH-DSA-sigVer-FIPS205 (internalProjection.json, which holds
the inputs and the expected results; in sigVer, "testPassed" and "reason") and writes one file per parameter set,
<output>/SLH-DSA-SHA2-128s.txt and so on, with the three kinds of vector mixed (the first column says which).

Format of each line (17 fields separated by "|", binary fields in hexadecimal, empty = empty string):
   1 type        kg (keyGen) | sg (sigGen) | sv (sigVer)
   2 tcId
   3 set         SLH-DSA-SHA2-128s ...
   4 interface   external | internal | -            (signatureInterface)
   5 prehash     pure | preHash | none | -          (preHash of the group)
   6 det         1 deterministic | 0 with additional randomness | -
   7 hashAlg     none | SHA2-256 | ... | SHAKE-256
   8 expected    valid | invalid   (ACVP kg and sg: valid; sv: testPassed)
   9 sk          private key (4n)
  10 pk          public key (2n)
  11 seed        SK.seed || SK.prf || PK.seed (kg only)
  12 addrnd      additionalRandomness (sg/sv that are not deterministic only)
  13 msg         message (for the internal interface, M' as ACVP gives it)
  14 ctx         context
  15 ph          PH(M), computed here with hashlib for the preHash groups (FIPS 205, Algorithm 23, lines 7-27:
                 SHAKE128 gives 256 bits and SHAKE256 gives 512); empty for the others
  16 sig         expected signature (sg) or signature to verify (sv)
  17 comment     "ACVP keyGen tg=N", "ACVP sigGen tg=N" or the sigVer "reason" with "tg=N"

Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
"""
import hashlib
import json
import os
import sys

# Pre-hash functions of FIPS 205, section 10.2.2 (the ones ACVP uses), with the output length that Algorithm 23 sets for
# the XOFs.
PREHASH = {
    "SHA2-224": ("sha224", None), "SHA2-256": ("sha256", None), "SHA2-384": ("sha384", None),
    "SHA2-512": ("sha512", None), "SHA2-512/224": ("sha512_224", None), "SHA2-512/256": ("sha512_256", None),
    "SHA3-224": ("sha3_224", None), "SHA3-256": ("sha3_256", None), "SHA3-384": ("sha3_384", None),
    "SHA3-512": ("sha3_512", None), "SHAKE-128": ("shake_128", 32), "SHAKE-256": ("shake_256", 64),
}


def ph(name, message_hex):
    alg, length = PREHASH[name]
    h = hashlib.new(alg, bytes.fromhex(message_hex))
    return (h.hexdigest(length) if length else h.hexdigest()).upper()


def check_hashlib():
    # sha512_224 and sha512_256 depend on the OpenSSL that Python was built with: if they are missing, stop here.
    for name in PREHASH:
        ph(name, "00")


def line(fields):
    for f in fields:
        if "|" in str(f) or "\n" in str(f):
            raise ValueError("field contains a separator: %r" % f)
    return "|".join(str(f) for f in fields) + "\n"


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    source, target = sys.argv[1], sys.argv[2]
    check_hashlib()
    os.makedirs(target, exist_ok=True)
    output = {}  # parameter set -> list of lines
    count = {}

    def put(pset, kind, fields):
        output.setdefault(pset, []).append(line(fields))
        count[(kind, pset)] = count.get((kind, pset), 0) + 1

    data = json.load(open(os.path.join(source, "SLH-DSA-keyGen-FIPS205", "internalProjection.json")))
    for g in data["testGroups"]:
        pset = g["parameterSet"]
        for t in g["tests"]:
            seed = t["skSeed"] + t["skPrf"] + t["pkSeed"]
            put(pset, "kg", ["kg", t["tcId"], pset, "-", "-", "-", "none", "valid", t["sk"], t["pk"], seed, "", "", "",
                             "", "", "ACVP keyGen tg=%d" % g["tgId"]])

    for name, kind in (("SLH-DSA-sigGen-FIPS205", "sg"), ("SLH-DSA-sigVer-FIPS205", "sv")):
        data = json.load(open(os.path.join(source, name, "internalProjection.json")))
        for g in data["testGroups"]:
            pset = g["parameterSet"]
            interface = g["signatureInterface"]
            pre = g.get("preHash", "none")
            for t in g["tests"]:
                # In sigVer the group has no "deterministic": the signature is already made, and how does not matter.
                det = ("1" if g["deterministic"] else "0") if kind == "sg" else "-"
                hash_alg = t.get("hashAlg", "none")
                digest = ph(hash_alg, t["message"]) if pre == "preHash" else ""
                if pre == "preHash" and hash_alg == "none":
                    raise ValueError("preHash group without hashAlg: tcId %s" % t["tcId"])
                if kind == "sv":
                    expected = "valid" if t["testPassed"] else "invalid"
                    comment = "%s tg=%d" % (t["reason"], g["tgId"])
                else:
                    expected = "valid"
                    comment = "ACVP sigGen tg=%d" % g["tgId"]
                addrnd = t.get("additionalRandomness", "") if (kind == "sv" or det == "0") else ""
                put(pset, kind, [kind, t["tcId"], pset, interface, pre, det, hash_alg, expected, t["sk"], t["pk"], "",
                                 addrnd, t["message"], t.get("context", ""), digest, t["signature"], comment])

    for pset, lines in sorted(output.items()):
        with open(os.path.join(target, pset + ".txt"), "w") as f:
            f.writelines(lines)
        print("%-20s keyGen=%d sigGen=%d sigVer=%d" % (pset, count.get(("kg", pset), 0), count.get(("sg", pset), 0),
                                                      count.get(("sv", pset), 0)))


if __name__ == "__main__":
    main()
