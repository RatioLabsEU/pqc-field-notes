#!/usr/bin/env bash
# Reproduce the ML-KEM input validation findings on Linux.
#
#   1. Wycheproof ML-KEM vectors that carry an explicit key, against liboqs 0.12.0 and 0.13.0.
#   2. The same vectors against the Rust crate pqcrypto-mlkem 0.1.1 (needs cargo; skipped if absent).
#
# Needs: git, python3, cmake, make, gcc. Everything is downloaded and built under $WORK.
# Nothing is installed system-wide.
#
# Usage:  ./run.sh            (set WORK=/some/dir to choose the working directory)
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
LIBOQS_VERSIONS="0.12.0 0.13.0"
mkdir -p "$WORK/vectors"
export PATH="$HOME/.cargo/bin:$PATH"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do
    python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$WORK/vectors/mlkem_$P.txt"
done
echo "Wycheproof $WYCHEPROOF_COMMIT"

echo
echo "### 1. liboqs"
for V in $LIBOQS_VERSIONS; do
    fetch https://github.com/open-quantum-safe/liboqs.git "$WORK/liboqs-$V" "$V" || exit 2
    B="$WORK/liboqs-$V/_build-mlkem"
    if [ ! -f "$B/lib/liboqs.a" ]; then
        cmake -S "$WORK/liboqs-$V" -B "$B" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
            -DOQS_USE_OPENSSL=OFF "-DOQS_MINIMAL_BUILD=KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024" >"$B.cmake.log" 2>&1 \
            && cmake --build "$B" -j"$(nproc)" >"$B.make.log" 2>&1 || { echo "liboqs $V failed to build, see $B.make.log"; continue; }
    fi
    gcc -O2 -w -I"$B/include" "$HERE/wycheproof_mlkem_liboqs.c" "$B/lib/liboqs.a" -lm -lpthread -o "$B/_wycheproof" || continue
    for P in 512 768 1024; do "$B/_wycheproof" "$WORK/vectors/mlkem_$P.txt" "$P"; done
done

echo
echo "### 2. pqcrypto-mlkem 0.1.1"
if command -v cargo >/dev/null; then
    export CARGO_TARGET_DIR="$WORK/pqcrypto-mlkem-check-target"
    ( cd "$HERE/pqcrypto-mlkem-check" && cargo run --quiet --release -- "$WORK/vectors" 2>"$WORK/pqcrypto-mlkem.log" ) || tail -n 5 "$WORK/pqcrypto-mlkem.log"
else
    echo "cargo not found: skipped"
fi
