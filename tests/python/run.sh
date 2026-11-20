#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors against PyPI packages with their own implementation:
#
#   pqcrypto    pqcrypto 1.0.0 (ML-KEM, ML-DSA)
#   keeper      keeper-mlkem 1.0.2 (ML-KEM; imported as "mlkem")
#   dilithium   dilithium-py 1.5.1 (ML-DSA)
#   kyber       kyber-py 1.2.0 (ML-KEM)
#   mlkem       mlkem 0.2.0 (ML-KEM)
#   pykyber     pykyber 2.0.0 (ML-KEM)
#   diagnose    checks that explain the pqcrypto and keeper-mlkem results (not vector tests; needs the first two)
#
# Each package goes in its own virtual environment. Only the prebuilt wheel that pip picks is installed
# (--only-binary), and the wheel tag is printed. Packages without key generation from a seed are also given expanded
# decapsulation keys derived from the seeds with kyber-py (see wycheproof_py.py).
#
# Needs: git, curl, python3 with venv, and CPython 3.13 for keeper-mlkem (version 1.0.2 only ships wheels up to
# CPython 3.13; set PYTHON313 to its path, default "python3.13"). Everything is downloaded under $WORK.
# Nothing is installed system-wide.
#
# Usage:  ./run.sh [pqcrypto] [keeper] [dilithium] [kyber] [mlkem] [pykyber] [diagnose]
#         (no arguments: the six packages)
#         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
PY313="${PYTHON313:-python3.13}"
W="$WORK/python"; V="$WORK/vectors"; O="$W/out"; F="$W/sources"
export PIP_CACHE_DIR="$W/pipcache"; mkdir -p "$W/venv" "$O" "$F" "$V"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done
echo "Wycheproof $WYCHEPROOF_COMMIT"

summary() { grep -v '^  ' "$1"; grep '^  ' "$1" | sed 's/tcId=[0-9]*//' | sort | uniq -c | sort -rn | cut -c1-200 || true; }

declare -A PIP=( [pqcrypto]="pqcrypto==1.0.0" [keeper]="keeper-mlkem==1.0.2" [dilithium]="dilithium-py==1.5.1"
                 [kyber]="kyber-py==1.2.0" [mlkem]="mlkem==0.2.0" [pykyber]="pykyber==2.0.0" )
env_for() {   # creates the environment if missing and says which wheel was installed
    local n=$1 py=python3; [ "$n" = keeper ] && py=$PY313
    if [ ! -x "$W/venv/$n/bin/python" ]; then
        "$py" -m venv "$W/venv/$n" && "$W/venv/$n/bin/pip" install -q --only-binary=:all: "${PIP[$n]}" >"$O/pip-$n.log" 2>&1
    fi
    "$W/venv/$n/bin/python" -I -c "import sys,importlib.metadata as m
d=m.distribution(sys.argv[1]); w=d.read_text('WHEEL').split('Tag: ')[1].split()[0]
print(f'== {d.name} {d.version}  (wheel {w}, Python {sys.version.split()[0]}, from PyPI)')" "$(echo "${PIP[$n]}" | cut -d= -f1)"
}

# Downloads an sdist from PyPI, checks its sha256 against the index, unpacks it in $F and prints the sha256.
pypi_sdist() { # name version
    local URL SUM FN
    read -r URL SUM FN < <(python3 -I -c 'import json,sys,urllib.request
d=json.load(urllib.request.urlopen(f"https://pypi.org/pypi/{sys.argv[1]}/{sys.argv[2]}/json"))
u=[x for x in d["urls"] if x["packagetype"]=="sdist"][0]; print(u["url"], u["digests"]["sha256"], u["filename"])' "$1" "$2") || return 1
    [ -f "$F/$FN" ] || curl -sSfL -o "$F/$FN" "$URL" || return 1
    echo "$SUM  $F/$FN" | sha256sum -c --quiet || { echo "sha256 mismatch for $FN"; return 1; }
    tar xzf "$F/$FN" -C "$F" && echo "   $SUM  $FN"
}

# Checks that explain the discrepancies found by the vector tests. They use the environments created above.
diagnose() {
    echo "   sources read for the diagnosis (sha256 checked against the index):"
    pypi_sdist keeper-mlkem 1.0.2
    for v in 0.0.1 0.0.2 0.0.3; do mkdir -p "$F/mlkem-old"; ( F="$F/mlkem-old"; pypi_sdist mlkem "$v" ); done
    mkdir -p "$F/crates"
    [ -f "$F/crates/backbone-ml-dsa-0.2.0.crate" ] || curl -sSfL -o "$F/crates/backbone-ml-dsa-0.2.0.crate" https://static.crates.io/crates/backbone-ml-dsa/backbone-ml-dsa-0.2.0.crate
    tar xzf "$F/crates/backbone-ml-dsa-0.2.0.crate" -C "$F/crates" && echo "   $(sha256sum "$F/crates/backbone-ml-dsa-0.2.0.crate" | sed "s|$F/||")"

    echo "#### pqcrypto 1.0.0 (backbone-ml-dsa 0.2.0): context and message length, through the public interface"
    "$W/venv/pqcrypto/bin/python" -I - <<'EOF'
from pqcrypto.sign import ml_dsa_44 as d
pk, sk = d.keygen()
def test(msg, ctx):
    try:
        s = d.sign(sk, msg, context=ctx)
    except Exception as e:
        return f"sign raises {type(e).__name__}: {e}"
    try:
        d.verify(pk, msg, s, context=ctx)
        return "signs and verifies it"
    except Exception as e:
        return f"signs, but verify raises {type(e).__name__}"
for n in (0, 253, 254, 255, 256):
    print(f"  context of {n} bytes: {test(b'test', bytes(n))}")
for n in (1 << 20, (1 << 20) + 1):
    print(f"  message of {n} bytes: {test(bytes(n), b'')}")
EOF
    echo "#### signatures made with dilithium-py (which accepts them) and verified with pqcrypto"
    mkdir -p "$W/diag"
    "$W/venv/dilithium/bin/python" -I - "$W/diag" <<'EOF'
import sys
from dilithium_py.ml_dsa import ML_DSA_44 as D
pk, sk = D.key_derive(bytes(32))
for n, c in (((1 << 20) + 1, 0), (5, 253), (5, 254), (5, 255)):
    s = D.sign(sk, bytes(n), bytes(c), deterministic=True)
    assert D.verify(pk, bytes(n), s, bytes(c))
    open(f"{sys.argv[1]}/f_{n}_{c}.hex", "w").write(pk.hex() + "|" + s.hex())
EOF
    "$W/venv/pqcrypto/bin/python" -I - "$W/diag" <<'EOF'
import glob, os, sys
from pqcrypto.sign import ml_dsa_44 as d
for f in sorted(glob.glob(sys.argv[1] + "/f_*.hex")):
    n, c = map(int, os.path.basename(f)[2:-4].split("_"))
    pk, s = (bytes.fromhex(x) for x in open(f).read().split("|"))
    try:
        d.verify(pk, bytes(n), s, context=bytes(c)); r = "accepts"
    except Exception as e:
        r = f"rejects ({type(e).__name__})"
    print(f"  message of {n} bytes, context of {c} bytes: pqcrypto {r}")
EOF
    echo "   code: $(grep -n 'prefix.len() > 255' "$F"/crates/backbone-ml-dsa-0.2.0/src/sign.rs | tr '\n' ' ')"
    echo "         $(grep -n 'msg.len() > (1 << 20)' "$F"/crates/backbone-ml-dsa-0.2.0/src/sign.rs | tr '\n' ' ')"

    echo "#### keeper-mlkem 1.0.2: the encapsulation key check in encaps() does not detect coefficients >= q"
    "$W/venv/keeper/bin/python" -I - "$V/mlkem_768.txt" <<'EOF'
import sys
from mlkem.fastmath import byte_decode_matrix, byte_encode_matrix   # C module of the package (diagnosis only)
for line in open(sys.argv[1]):
    x = line.split("|")
    if x[0] == "E" and x[2] == "invalid" and "not reduced" in x[7]:
        ek = bytes.fromhex(x[4]); break
t = byte_decode_matrix(ek, 12, 3)
print(f"  tcId={x[1]} ({x[7].strip()}): largest decoded coefficient = {max(max(p) for p in t)} (q = 3329)")
print(f"  encode(decode(ek)) == ek[:1152]: {byte_encode_matrix(t, 12) == ek[:1152]}  -> the check never fails")
EOF
    echo "   code: mlkem/mlkem_core.py $(grep -n 'validation_test' "$F"/keeper_mlkem-1.0.2/mlkem/mlkem_core.py | cut -d: -f1 | tr '\n' ' ')"

    echo "#### keeper-mlkem's C module compared with the one in mlkem 0.0.1-0.0.3 on PyPI"
    for v in 0.0.1 0.0.2 0.0.3; do
        echo "   mlkem $v: $(diff "$F/mlkem-old/mlkem-$v/mlkem/math/fastmathmodule.c" "$F/keeper_mlkem-1.0.2/mlkem/fastmathmodule.c" | grep -c '^[<>]') lines differ"
    done
    diff "$F/mlkem-old/mlkem-0.0.3/mlkem/math/fastmathmodule.c" "$F/keeper_mlkem-1.0.2/mlkem/fastmathmodule.c" | sed 's/^/   /'

    echo "#### sampling_bytes.py (does any vector need more than the 840 SHAKE128 bytes keeper-mlkem asks for per entry of A?)"
    for P in 512 768 1024; do python3 -I "$HERE/sampling_bytes.py" "$V/mlkem_$P.txt" "$P"; done
}

# Expanded decapsulation keys derived from the seeds with kyber-py, for the packages without key generation from a seed.
env_for kyber >/dev/null
for P in 512 768 1024; do
    [ -s "$W/dk_$P.txt" ] || "$W/venv/kyber/bin/python" -I "$HERE/wycheproof_py.py" derive "$V/mlkem_$P.txt" $P >"$W/dk_$P.txt" &
done; wait

[ $# -eq 0 ] && set -- pqcrypto keeper dilithium kyber mlkem pykyber
for n in "$@"; do
    [ "$n" = diagnose ] && { echo; echo "######## diagnosis"; diagnose; continue; }
    [ -n "${PIP[$n]:-}" ] || { echo "unknown: $n"; continue; }
    env_for "$n"
    case $n in dilithium) SETS="44 65 87";; pqcrypto) SETS="512 768 1024 44 65 87";; *) SETS="512 768 1024";; esac
    for P in $SETS; do      # all parameter sets at once (the pure-Python ones are slow)
        FILE=mlkem_$P.txt; [ "$P" -lt 100 ] && FILE=mldsa_$P.txt
        DK=""; [ "$P" -gt 100 ] && DK="$W/dk_$P.txt"
        "$W/venv/$n/bin/python" -I "$HERE/wycheproof_py.py" "$n" "$V/$FILE" "$P" $DK >"$O/$n-$P.out" 2>&1 &
    done; wait
    for P in $SETS; do cat "$O/$n-$P.out"; done >"$O/$n.out"; summary "$O/$n.out"
done
