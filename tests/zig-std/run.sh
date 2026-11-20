#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors against the Zig standard library (std.crypto.kem.ml_kem and
# std.crypto.sign.mldsa).
#
# Each Zig version is downloaded from ziglang.org (the download index gives the URL and the sha256 of the tarball,
# which is checked before unpacking), the test program is built with the vectors embedded, and it is run.
#
# Needs: git, curl, python3, tar with xz. Everything is downloaded and built under $WORK. Nothing is installed
# system-wide.
#
# Usage:  ./run.sh [zig versions...]      (default: 0.17.1 0.16.0; "master" also works)
#         MODES="ReleaseSafe ReleaseFast Debug" and CPUS="native baseline" choose the builds (default: ReleaseSafe, native)
#         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
W="$WORK/zig-std"; V="$WORK/vectors"
mkdir -p "$W/downloads" "$V"
export ZIG_GLOBAL_CACHE_DIR="$W/cache-global" ZIG_LOCAL_CACHE_DIR="$W/cache-local"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done
echo "Wycheproof $WYCHEPROOF_COMMIT"

# get_zig <version>: prints the path of the zig binary, downloading and checking it if needed.
get_zig() {
    local VER="$1" T="$W/downloads/zig-$1.tar.xz" D="$W/zig-$1" URL SUM
    if [ ! -x "$D/zig" ]; then
        [ -s "$W/downloads/zig-index.json" ] || curl -sSfL -o "$W/downloads/zig-index.json" https://ziglang.org/download/index.json || return 1
        read -r URL SUM < <(python3 -I -c "import json,sys; e=json.load(open(sys.argv[1]))[sys.argv[2]]['x86_64-linux']; print(e['tarball'], e['shasum'])" "$W/downloads/zig-index.json" "$VER") || return 1
        curl -sSfL -o "$T" "$URL" || return 1
        echo "$SUM  $T" | sha256sum -c --quiet >&2 || { echo "== Zig $VER: the sha256 does not match the index" >&2; return 1; }
        rm -rf "$D"; mkdir -p "$D"; tar xJf "$T" -C "$D" --strip-components=1 || return 1
    fi
    echo "$D/zig"
}

[ $# -eq 0 ] && set -- 0.17.1 0.16.0
for VER in "$@"; do
    Z="$(get_zig "$VER")" || { echo "== Zig $VER: could not download"; continue; }
    echo "== Zig $("$Z" version) (ziglang.org tarball, sha256 $(sha256sum "$W/downloads/zig-$VER.tar.xz" | cut -c1-64), checked against index.json)"
    B="$W/test-$VER"; rm -rf "$B"; mkdir -p "$B"; cp "$HERE/wycheproof.zig" "$V"/mlkem_*.txt "$V"/mldsa_*.txt "$B/"
    DSA=true; [ -f "$(dirname "$Z")/lib/std/crypto/ml_dsa.zig" ] || DSA=false
    printf 'pub const with_dsa = %s;\n' "$DSA" >"$B/options.zig"
    for M in ${MODES:-ReleaseSafe}; do
        for CPU in ${CPUS:-native}; do
            echo "#### Zig $VER, $M, cpu=$CPU"
            ( cd "$B" && "$Z" build-exe -O "$M" -mcpu="$CPU" --dep options -Mroot=wycheproof.zig -Moptions=options.zig -femit-bin="p-$M-$CPU" >"_b.log" 2>&1 \
              && "./p-$M-$CPU" >"_o.log" 2>&1; grep -v '^  ' _o.log 2>/dev/null; grep '^  ' _o.log 2>/dev/null | sed 's/tcId=[0-9]*//' | sort | uniq -c | cut -c1-170; grep -m6 'error' _b.log | cut -c1-200 )
        done
    done
done
