#!/usr/bin/env python3
"""Wycheproof ML-KEM and ML-DSA vectors against PyPI packages with their own implementation.

Usage:
  python wycheproof_py.py <package> <vector file> <512|768|1024|44|65|87> [file of derived dks]
  python wycheproof_py.py derive <mlkem_<p>.txt file> <512|768|1024>     (in the kyber-py environment)

Packages: pqcrypto, keeper (keeper-mlkem), kyber (kyber-py), dilithium (dilithium-py), mlkem, pykyber.
Each package is tested in its own virtual environment: keeper-mlkem and mlkem are both imported as "mlkem".

Vector format (hex, fields separated by "|"), produced by mlkem_to_text.py and wycheproof_to_text.py:
  D|tcId|result|seed d||z|ek|c|K|comment      generate the key from the seed and decapsulate c
  E|tcId|result|m|ek|c|K|comment              encapsulate with ek and the randomness m
  X|tcId|result|dk|c|K||comment               decapsulate with the expanded decapsulation key
  tcId|result|public key|message|context|signature|comment      (ML-DSA, verify)

Each adapter returns, as in the C harnesses: 1 = operation succeeded, 0 = error or input rejected,
-1 = the package has no public interface for this. An exception from the library counts as a rejection (0).

Limits of the public interface, which the test respects (no internal functions with a leading underscore are called):
  - pqcrypto, keeper-mlkem and mlkem do not generate keys from a seed and do not let the caller fix the
    encapsulation randomness. For the E vectors only acceptance of the encapsulation key is checked. For the D
    vectors, if the file of derived dks is given (expanded key computed from the seed with kyber-py, checking that
    its ek matches the one in the vector), c is decapsulated with that dk through the public interface and compared
    with K: this tests decapsulation and implicit rejection. Seeds of the wrong length have no derived dk and count
    as "no interface".
  - kyber-py: key_derive(seed) is public. To fix m in encaps() the public attribute random_bytes is replaced (the
    same mechanism set_drbg_seed uses); the key check is still the one in encaps().
  - pykyber: ML_KEM_xxx(seed) is public; encapsulate() does not let the caller fix the randomness.

Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
"""
import importlib
import importlib.metadata
import sys

KEM = (512, 768, 1024)
DSA = (44, 65, 87)
KIND = ("seed", "encaps", "expanded dk")
# Faults of this program, not of the library: they are not counted as rejections, they are let through.
OWN = (AttributeError, NameError, ImportError, AssertionError)


def h(s):
    return bytes.fromhex(s)


def version(dist):
    try:
        return importlib.metadata.version(dist)
    except importlib.metadata.PackageNotFoundError:
        return "?"


class Adapter:
    """By default there is no interface for anything."""

    name = "?"

    def seed(self, p, seed, c):             # -> (r, ek or None, K)
        return -1, None, None

    def encaps(self, p, ek, m):             # -> (r, c or None if the randomness cannot be fixed, K)
        return -1, None, None

    def decaps_dk(self, p, dk, c):          # -> (r, K)
        return -1, None

    def verify(self, p, pk, msg, ctx, sig):  # -> 1 accepted, 0 rejected, -1 no interface
        return -1


class PQCrypto(Adapter):
    """pqcrypto 1.x (backbone-hq): plain functions in pqcrypto.kem.ml_kem_<p> and pqcrypto.sign.ml_dsa_<p>.
    encaps(pk) -> (ct, ss); decaps(sk, ct) -> ss; both raise ValueError when they reject.
    verify(pk, msg, sig, context=None, hash_algorithm=None) -> None if the signature is valid; otherwise it raises
    InvalidSignatureError (a subclass of ValueError) or ValueError (malformed key or signature)."""

    def __init__(self, p):
        self.name = "pqcrypto " + version("pqcrypto")
        sub = f"pqcrypto.kem.ml_kem_{p}" if p in KEM else f"pqcrypto.sign.ml_dsa_{p}"
        importlib.import_module("pqcrypto.kem" if p in KEM else "pqcrypto.sign")
        self.m = sys.modules[sub]

    def encaps(self, p, ek, m):
        ct, ss = self.m.encaps(ek)          # internal randomness: only acceptance of the key is checked
        return 1, None, None

    def decaps_dk(self, p, dk, c):
        return 1, self.m.decaps(dk, c)

    def verify(self, p, pk, msg, ctx, sig):
        self.m.verify(pk, msg, sig, context=ctx)    # empty context = b"", as FIPS 204 requires
        return 1


class Keeper(Adapter):
    """keeper-mlkem (module "mlkem"): ML_KEM(parameters).encaps(ek) -> (K, c) with internal randomness;
    decaps(dk, c) -> K. They raise ValueError when they reject."""

    def __init__(self, p):
        import mlkem
        self.name = "keeper-mlkem " + version("keeper-mlkem")
        par = {512: mlkem.MLKEM_512_PARAMETERS, 768: mlkem.MLKEM_768_PARAMETERS, 1024: mlkem.MLKEM_1024_PARAMETERS}[p]
        self.kem = mlkem.ML_KEM(par)

    def encaps(self, p, ek, m):
        K, c = self.kem.encaps(ek)
        return 1, None, None

    def decaps_dk(self, p, dk, c):
        return 1, self.kem.decaps(dk, c)


class KyberPy(Adapter):
    """kyber-py (ML-KEM, not Kyber): key_derive(seed) -> (ek, dk); encaps(ek) -> (K, c); decaps(dk, c) -> K.
    They raise ValueError when they reject."""

    def __init__(self, p):
        from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
        self.name = "kyber-py " + version("kyber-py")
        self.kem = {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}[p]

    def seed(self, p, seed, c):
        ek, dk = self.kem.key_derive(seed)
        return 1, ek, self.kem.decaps(dk, c)

    def encaps(self, p, ek, m):
        original = self.kem.random_bytes

        def fixed(n):
            assert n == 32
            return m

        self.kem.random_bytes = fixed
        try:
            K, c = self.kem.encaps(ek)
        finally:
            self.kem.random_bytes = original
        return 1, c, K

    def decaps_dk(self, p, dk, c):
        return 1, self.kem.decaps(dk, c)


class DilithiumPy(Adapter):
    """dilithium-py (ML-DSA, not round-3 Dilithium): verify(pk, m, sig, ctx=b"") -> bool.
    Raises ValueError if the context is longer than 255 bytes or the key has the wrong length."""

    def __init__(self, p):
        from dilithium_py.ml_dsa import ML_DSA_44, ML_DSA_65, ML_DSA_87
        self.name = "dilithium-py " + version("dilithium-py")
        self.dsa = {44: ML_DSA_44, 65: ML_DSA_65, 87: ML_DSA_87}[p]

    def verify(self, p, pk, msg, ctx, sig):
        return 1 if self.dsa.verify(pk, msg, sig, ctx) is True else 0


class MlKemRust(Adapter):
    """mlkem 0.2.x (Rust core): EncapsKey/DecapsKey.from_bytes validate the key; ML_KEM(p).encaps(ek) ->
    (K, c) with internal randomness; decaps(dk, c) -> K. They raise ValueError when they reject."""

    def __init__(self, p):
        import mlkem
        self.mod = mlkem
        self.name = "mlkem " + version("mlkem")
        self.kem = mlkem.ML_KEM({512: mlkem.ParameterSet.ML_KEM_512, 768: mlkem.ParameterSet.ML_KEM_768,
                                 1024: mlkem.ParameterSet.ML_KEM_1024}[p])

    def encaps(self, p, ek, m):
        K, c = self.kem.encaps(self.mod.EncapsKey.from_bytes(ek))
        return 1, None, None

    def decaps_dk(self, p, dk, c):
        return 1, self.kem.decaps(self.mod.DecapsKey.from_bytes(dk), c)


class PyKyber(Adapter):
    """pykyber 2.x (ML-KEM, not Kyber): ML_KEM_xxx(seed) -> pair with public_key and secret_key;
    ML_KEM_xxx.encapsulate(ek) with internal randomness; ML_KEM_xxx.decapsulate(c, dk) -> K. They raise their own
    exceptions."""

    def __init__(self, p):
        import pykyber
        self.name = "pykyber " + version("pykyber")
        self.cls = {512: pykyber.ML_KEM_512, 768: pykyber.ML_KEM_768, 1024: pykyber.ML_KEM_1024}[p]

    def seed(self, p, seed, c):
        pair = self.cls(seed)
        return 1, pair.public_key, self.cls.decapsulate(c, pair.secret_key)

    def encaps(self, p, ek, m):
        self.cls.encapsulate(ek)
        return 1, None, None

    def decaps_dk(self, p, dk, c):
        return 1, self.cls.decapsulate(c, dk)


PACKAGES = {"pqcrypto": PQCrypto, "keeper": Keeper, "kyber": KyberPy, "dilithium": DilithiumPy,
            "mlkem": MlKemRust, "pykyber": PyKyber}


def call(f, *a):
    """Runs the operation; an exception from the library is a rejection (0) and its class is recorded."""
    try:
        return f(*a), None
    except OWN:
        raise
    except Exception as e:  # noqa: BLE001 - any library error is a rejection
        return None, type(e).__name__


def test_kem(ad, path, p, derived):
    n, acc, fail, none = [0, 0, 0], [0, 0, 0], [0, 0, 0], [0, 0, 0]
    with_dk = False
    for line in open(path, encoding="utf-8"):
        x = line.rstrip("\r\n").split("|")
        if len(x) < 8:
            continue
        t = "DEX".index(x[0])
        valid = x[2] == "valid"
        good, r, err = False, 0, None
        if t == 0:
            seed, ek_exp, c, K_exp = h(x[3]), h(x[4]), h(x[5]), h(x[6])
            res, err = call(ad.seed, p, seed, c)
            if res is not None and res[0] == -1 and derived is not None:
                # No key generation from a seed: decapsulate with the dk derived by kyber-py (if there is one).
                if x[1] in derived:
                    with_dk = True
                    res2, err = call(ad.decaps_dk, p, derived[x[1]], c)
                    res = (res2[0], None, res2[1]) if res2 is not None else None
            if res is None:
                r = 0
            else:
                r, ek, K = res
                good = r == 1 and K == K_exp and (ek is None or ek == ek_exp)
        elif t == 1:
            m, ek, c_exp, K_exp = h(x[3]), h(x[4]), h(x[5]), h(x[6])
            res, err = call(ad.encaps, p, ek, m)
            if res is not None:
                r, c, K = res
                good = r == 1 and (c is None or (c == c_exp and K == K_exp))
        else:
            dk, c, K_exp = h(x[3]), h(x[4]), h(x[5])
            res, err = call(ad.decaps_dk, p, dk, c)
            if res is not None:
                r, K = res
                good = r == 1 and K == K_exp
        if r < 0:
            none[t] += 1
            continue
        n[t] += 1
        if valid and not good:
            fail[t] += 1
            reason = "different result" if r == 1 else "error " + str(err)
            print(f"  valid fails       [{KIND[t]}] tcId={x[1]} ({reason})  {x[7]}", flush=True)
        if not valid and r == 1:
            acc[t] += 1
            print(f"  INVALID ACCEPTED  [{KIND[t]}] tcId={x[1]}  {x[7]}", flush=True)
    s = f"{ad.name:<30} ML-KEM-{p:<4}"
    for t in range(3):
        label = KIND[t] + (" (derived dk)" if t == 0 and with_dk else "")
        if n[t] == 0 and none[t] > 0:
            s += f" | {label}: no interface"
        else:
            s += f" | {label}: {n[t]} vectors, INVALID ACCEPTED={acc[t]}, valid fails={fail[t]}"
            if none[t]:
                s += f" (no interface {none[t]})"
    print(s, flush=True)


def test_dsa(ad, path, p):
    total = acc = rej = na = 0
    for line in open(path, encoding="utf-8"):
        x = line.rstrip("\r\n").split("|")
        if len(x) < 7:
            continue
        valid = x[1] == "valid"
        ok, err = call(ad.verify, p, h(x[2]), h(x[3]), h(x[4]), h(x[5]))
        ok = ok or 0
        if ok < 0:
            na += 1
            continue
        total += 1
        if ok and not valid:
            acc += 1
            print(f"  INVALID ACCEPTED  tcId={x[0]}  {x[6]}", flush=True)
        if not ok and valid:
            rej += 1
            print(f"  valid rejected    tcId={x[0]} ({'false' if err is None else 'error ' + err})  {x[6]}", flush=True)
    s = f"{ad.name:<34} ML-DSA-{p}  vectors={total}   INVALID ACCEPTED={acc}   valid rejected={rej}"
    if na:
        s += f"   (not applicable: {na})"
    print(s, flush=True)


def derive(path, p):
    """Writes tcId|dk for every D vector with a 64-byte seed, using kyber-py, and checks the ek of the vector."""
    from kyber_py.ml_kem import ML_KEM_512, ML_KEM_768, ML_KEM_1024
    kem = {512: ML_KEM_512, 768: ML_KEM_768, 1024: ML_KEM_1024}[p]
    for line in open(path, encoding="utf-8"):
        x = line.rstrip("\r\n").split("|")
        if len(x) < 8 or x[0] != "D" or len(x[3]) != 128:
            continue
        ek, dk = kem.key_derive(h(x[3]))
        if x[4] and ek != h(x[4]):
            print(f"# tcId={x[1]}: the derived ek does not match the one in the vector", file=sys.stderr)
            continue
        print(f"{x[1]}|{dk.hex()}")


def main():
    if len(sys.argv) < 4:
        print(__doc__)
        return 2
    package, path, p = sys.argv[1], sys.argv[2], int(sys.argv[3])
    if package == "derive":
        derive(path, p)
        return 0
    ad = PACKAGES[package](p)
    if p in KEM:
        derived = None
        if len(sys.argv) > 4:
            derived = dict(l.strip().split("|") for l in open(sys.argv[4], encoding="utf-8") if "|" in l)
            derived = {k: h(v) for k, v in derived.items()}
        test_kem(ad, path, p, derived)
    else:
        test_dsa(ad, path, p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
