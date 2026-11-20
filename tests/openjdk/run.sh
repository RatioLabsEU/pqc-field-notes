#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors against OpenJDK's own implementation, in published builds of
# OpenJDK (Eclipse Temurin, latest GA build of each feature release, from api.adoptium.net).
#
# Each version is run in several JVM configurations, so that the interpreter, the JIT-compiled code and the
# CPU-specific intrinsics all get exercised:
#   def   default flags, 40 rounds so that the JIT compiler kicks in
#   int   -Xint, interpreter only (no accelerated paths)
#   comp  -Xcomp, everything compiled from the start
#   avx2  -XX:UseAVX=2, no AVX-512
#   sse   -XX:UseAVX=0, no AVX
#
# Needs: git, curl, python3, tar. Everything is downloaded under $WORK. Nothing is installed system-wide.
#
# Usage:  ./run.sh 24 25 26 27 ...            (feature releases; ML-KEM and ML-DSA are in OpenJDK 24 and later)
#         MODES="def int comp avx2 sse" chooses the configurations (default: def int comp)
#         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
W="$WORK/openjdk"; V="$WORK/vectors"
mkdir -p "$W" "$V"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done
echo "Wycheproof $WYCHEPROOF_COMMIT"

summary() { grep -v '^  ' "$1"; grep '^  ' "$1" | sed 's/tcId=[0-9]*//' | sort | uniq -c | cut -c1-170; }

[ $# -gt 0 ] || { echo "usage: ./run.sh <feature release>...   e.g. ./run.sh 24 25"; exit 2; }
for N in "$@"; do
    J="$W/jdk-$N"
    if [ ! -x "$J/bin/java" ]; then
        mkdir -p "$J" && curl -fsSL "https://api.adoptium.net/v3/binary/latest/$N/ga/linux/x64/jdk/hotspot/normal/eclipse" | tar xz -C "$J" --strip-components=1 \
            || { echo "== OpenJDK $N: could not download"; rm -rf "$J"; continue; }
    fi
    for M in ${MODES:-def int comp}; do
        case $M in
        def)  OPT="";             R=40; LABEL="default flags, 40 rounds so that the JIT compiler kicks in" ;;
        int)  OPT="-Xint";        R=1;  LABEL="interpreter only (no accelerated paths)" ;;
        comp) OPT="-Xcomp";       R=2;  LABEL="everything compiled from the start" ;;
        avx2) OPT="-XX:UseAVX=2"; R=40; LABEL="no AVX-512" ;;
        sse)  OPT="-XX:UseAVX=0"; R=40; LABEL="no AVX" ;;
        *)    echo "unknown mode: $M"; continue ;;
        esac
        echo "#### Java $N, $LABEL  ($OPT)"
        "$J/bin/java" $OPT "$HERE/WycheproofJDK.java" "$V" $R >"$W/jdk-$N-$M.out" 2>&1; summary "$W/jdk-$N-$M.out" | cut -c1-220
    done
done
