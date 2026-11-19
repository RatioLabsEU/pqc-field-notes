#!/usr/bin/env bash
# Reproduce the ML-DSA AVX2 verifier findings on Linux x86_64 with AVX2.
#
#   1. Wycheproof ML-DSA verification vectors against liboqs 0.15.0 / 0.16.0 and PQClean (clean / avx2).
#   2. Signatures with an out-of-bound z vector against the same verifiers.
#
# Needs: git, cmake, make, gcc, python3, perl.  Everything is downloaded and built under $WORK.
# Nothing is installed system-wide.
#
# Usage:  ./run.sh            (set WORK=/some/dir to choose the working directory)
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-lab-work}"
WYCHEPROOF_COMMIT=65ca494727a5
PQCLEAN_COMMIT=0586a824fc0d
LIBOQS_VERSIONS="0.15.0 0.16.0"
mkdir -p "$WORK/vectors"

grep -q avx2 /proc/cpuinfo || echo "WARNING: this CPU has no AVX2; the affected code path will not run."

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
fetch https://github.com/PQClean/PQClean.git "$WORK/PQClean" "$PQCLEAN_COMMIT" || exit 2
for V in $LIBOQS_VERSIONS; do
    fetch https://github.com/open-quantum-safe/liboqs.git "$WORK/liboqs-$V" "$V" || exit 2
    for VAR in avx2 portable; do
        B="$WORK/liboqs-$V/_build-$VAR"
        [ -f "$B/lib/liboqs.a" ] && continue
        [ "$VAR" = portable ] && OPT="-DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic" || OPT="-DOQS_DIST_BUILD=ON"
        cmake -S "$WORK/liboqs-$V" -B "$B" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
            -DOQS_USE_OPENSSL=OFF $OPT "-DOQS_MINIMAL_BUILD=SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87" >"$B.cmake.log" 2>&1 \
            && cmake --build "$B" -j"$(nproc)" >"$B.make.log" 2>&1 || { echo "liboqs $V ($VAR) failed to build, see $B.make.log"; exit 2; }
    done
done

PQ="$WORK/PQClean"
COMMON="$PQ/common/fips202.c $PQ/common/sha2.c $PQ/common/aes.c $PQ/common/randombytes.c $PQ/common/sp800-185.c"
KECCAK4X="$PQ/common/keccak4x/KeccakP-1600-times4-SIMD256.c"
AVXFLAGS="-mavx2 -mbmi2 -mpopcnt -maes"

echo "Wycheproof $WYCHEPROOF_COMMIT, PQClean $PQCLEAN_COMMIT, liboqs $LIBOQS_VERSIONS"
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2 | sed 's/^ //')"
echo
echo "### 1. Wycheproof ML-DSA verification vectors"
for P in 44 65 87; do
    python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$WORK/vectors/mldsa_$P.txt"
done
for V in $LIBOQS_VERSIONS; do
    for VAR in avx2 portable; do
        B="$WORK/liboqs-$V/_build-$VAR"
        echo "== liboqs $V, $VAR build"
        for P in 44 65 87; do
            gcc -O2 -w -DWITH_LIBOQS -DALG="\"ML-DSA-$P\"" -I"$B/include" "$HERE/wycheproof_mldsa.c" "$B/lib/liboqs.a" \
                -lm -lpthread -o "$B/_wycheproof$P" && "$B/_wycheproof$P" "$WORK/vectors/mldsa_$P.txt"
        done
    done
done
echo "== PQClean $PQCLEAN_COMMIT"
mkdir -p "$PQ/_out"
for P in 44 65 87; do
    for IMPL in clean avx2; do
        D="$PQ/crypto_sign/ml-dsa-$P/$IMPL/"; NS="PQCLEAN_MLDSA${P}_$(echo $IMPL | tr a-z A-Z)"
        FLAGS="-O2"; EXTRA=""
        [ "$IMPL" = avx2 ] && { FLAGS="-O2 $AVXFLAGS"; EXTRA="$KECCAK4X"; }
        gcc $FLAGS -w -DNS="$NS" -I"$PQ/common" -I"$PQ/common/keccak4x" -I"$D" "$HERE/wycheproof_mldsa.c" \
            $(ls "$D"*.c "$D"*.S 2>/dev/null) $COMMON $EXTRA -o "$PQ/_out/wycheproof_$NS" && "$PQ/_out/wycheproof_$NS" "$WORK/vectors/mldsa_$P.txt"
    done
done

echo
echo "### 2. Signatures with an out-of-bound z vector"
for P in 44 65 87; do
    CL="$PQ/crypto_sign/ml-dsa-$P/clean"; AV="$PQ/crypto_sign/ml-dsa-$P/avx2"
    C="PQCLEAN_MLDSA${P}_CLEAN"; A="PQCLEAN_MLDSA${P}_AVX2"
    # Patched signer: keep a candidate only if gamma1 - beta <= ||z||_inf < gamma1 (first match is in the signer).
    perl -0pe "s/if \(${C}_polyvecl_chknorm\(&z, GAMMA1 - BETA\)\) \{\s*goto rej;/if (!${C}_polyvecl_chknorm(&z, GAMMA1 - BETA) || ${C}_polyvecl_chknorm(&z, GAMMA1)) {\n        goto rej;/" \
        "$CL/sign.c" >"$PQ/_out/sign_patched_$P.c"
    cmp -s "$CL/sign.c" "$PQ/_out/sign_patched_$P.c" && { echo "ML-DSA-$P: could not patch the signer"; exit 2; }
    OBJ="$PQ/_out/obj$P"; rm -rf "$OBJ"; mkdir -p "$OBJ/c" "$OBJ/a"
    ( cd "$OBJ/c" && gcc -O2 -w -c -I"$PQ/common" -I"$CL" $(ls "$CL"/*.c | grep -v '/sign.c$') "$PQ/_out/sign_patched_$P.c" ) || exit 2
    ( cd "$OBJ/a" && gcc -O2 -w $AVXFLAGS -c -I"$PQ/common" -I"$PQ/common/keccak4x" -I"$AV" "$AV"/*.c "$AV"/*.S ) || exit 2
    gcc -O2 -w $AVXFLAGS -DC="$C" -DA="$A" "$HERE/oob_z.c" "$OBJ"/c/*.o "$OBJ"/a/*.o $COMMON $KECCAK4X -o "$PQ/_out/oob_$P" && "$PQ/_out/oob_$P"
    for V in $LIBOQS_VERSIONS; do
        for VAR in avx2 portable; do
            B="$WORK/liboqs-$V/_build-$VAR"
            printf '%-9s ' "$VAR"
            gcc -O2 -w -DC="$C" -DWITH_LIBOQS -DALG="\"ML-DSA-$P\"" -I"$B/include" "$HERE/oob_z.c" "$OBJ"/c/*.o $COMMON \
                "$B/lib/liboqs.a" -lm -lpthread -o "$B/_oob$P" && "$B/_oob$P"
        done
    done
done
