#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors against Rust and Go libraries with their own implementation:
#
#   cryptoxide   Rust crate cryptoxide 0.6.7 (ML-KEM, ML-DSA)
#   purecrypto   Rust crate purecrypto 0.10.6 (ML-KEM, ML-DSA)
#   macula       Rust crates macula-mlkem 0.3.0 and macula-mldsa 0.3.0
#   gmsm         Go module github.com/emmansun/gmsm v0.45.4 (ML-KEM, ML-DSA), with its assembly and with -tags purego
#   k2so         Go module github.com/symbolicsoft/kyber-k2so v1.1.1 (ML-KEM)
#   tink         Go module github.com/tink-crypto/tink-go/v2 v2.9.0, signature/mldsa (ML-DSA)
#   diag-gmsm    diagnosis of the gmsm ML-DSA result (see below); not a test of the unmodified module
#
# Rust crates are built in release and in debug (with overflow checks, to see whether a vector triggers an
# arithmetic panic). Versions are pinned in rust/*/Cargo.toml and go/go.mod.
#
# Needs: git, python3, perl, and the toolchains for what is run: Rust (cargo, edition 2024) and Go 1.26 or later.
# The sources are copied to $WORK and everything is downloaded and built there (CARGO_HOME, CARGO_TARGET_DIR, GOPATH,
# GOCACHE, GOMODCACHE). Nothing is installed system-wide.
#
# Usage:  ./run.sh [cryptoxide] [purecrypto] [macula] [gmsm] [k2so] [tink] [diag-gmsm]
#         (no arguments: cryptoxide purecrypto macula gmsm k2so tink)
#         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
W="$WORK/rust-go"; V="$WORK/vectors"; O="$W/out"; SRC="$W/src"
mkdir -p "$V" "$O" "$W/bin"
rm -rf "$SRC"; mkdir -p "$SRC"; cp -r "$HERE/rust" "$HERE/go" "$SRC/"
export CARGO_HOME="$W/cargo-home" CARGO_TARGET_DIR="$W/target" PATH="$HOME/.cargo/bin:/usr/local/go/bin:$PATH"
export GOPATH="$W/gopath" GOCACHE="$W/gocache" GOMODCACHE="$W/gomodcache" GOFLAGS=-modcacherw GOTOOLCHAIN=local

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done

# Summary: the total lines as they are, and the detail lines grouped by vector comment.
summary() { grep -v '^  ' "$1"; grep '^  ' "$1" | sed 's/tcId=[0-9]*//' | sort | uniq -c | sort -rn | cut -c1-200; }

echo "#### Wycheproof $WYCHEPROOF_COMMIT, $(uname -m), $(nproc) cores, CPU: $(grep -o -w 'avx2\|avx512f' /proc/cpuinfo | sort -u | tr '\n' ' ')"

# Rust: one crate per library.
rust() {
    local name="$1" dir="$SRC/rust/$1" profile opt
    echo "#### Rust $(rustc --version | cut -d' ' -f2), test crate rust/$name"
    for profile in release debug; do
        opt=""; [ "$profile" = release ] && opt="--release"
        if ( cd "$dir" && cargo build $opt -q ) >"$O/$name-$profile.build" 2>&1; then
            echo "## profile $profile"
            "$CARGO_TARGET_DIR/$profile/wycheproof-$name" "$V" >"$O/$name-$profile.out" 2>&1
            summary "$O/$name-$profile.out"
        else
            echo "## profile $profile: DOES NOT BUILD"; grep -m8 -E '^(error|warning: unused)' -A4 "$O/$name-$profile.build" | cut -c1-200
        fi
    done
    # provenance: crates.io, with the checksum pinned in Cargo.lock
    ( cd "$dir" && cargo tree -e normal --depth 1 2>/dev/null | head -5 | sed "s|$SRC/||" )
    awk '/^name = "(cryptoxide|purecrypto|macula-mlkem|macula-mldsa)"/{n=$3; getline v; getline s; getline c; print "   " n, v, c}' "$dir/Cargo.lock" 2>/dev/null
}

# Go: one module (go/go.mod) with one program per library.
gobuild() { ( cd "$SRC/go" && go build "$@" ) >"$O/go.build" 2>&1 || { echo "## DOES NOT BUILD: go build $*"; head -20 "$O/go.build"; return 1; }; }

prepare_go() {
    echo "#### $(go version)"
    ( cd "$SRC/go" && go mod tidy ) >"$O/go-tidy.log" 2>&1 || { echo "go mod tidy failed"; cat "$O/go-tidy.log"; }
    # provenance: proxy.golang.org (default GOPROXY), with the checksums pinned in go.sum
    ( cd "$SRC/go" && go env GOPROXY && grep -E '^github.com/(emmansun/gmsm|symbolicsoft/kyber-k2so|tink-crypto/tink-go/v2) v[^ ]* h1' go.sum )
}

gmsm() {
    # no tags: hand-written assembly (AVX2 on a CPU that has it); with -tags purego: generic code only
    gobuild -o "$W/bin/gmsm-asm" ./gmsm && { "$W/bin/gmsm-asm" "$V" >"$O/gmsm-asm.out" 2>&1; summary "$O/gmsm-asm.out"; }
    gobuild -tags purego -o "$W/bin/gmsm-purego" ./gmsm && { "$W/bin/gmsm-purego" "$V" >"$O/gmsm-purego.out" 2>&1; summary "$O/gmsm-purego.out"; }
}

k2so() {
    gobuild -o "$W/bin/k2so" ./k2so && { "$W/bin/k2so" "$V" >"$O/k2so.out" 2>&1; summary "$O/k2so.out"; }
}

tink() {
    gobuild -o "$W/bin/tink" ./tink && { "$W/bin/tink" "$V" >"$O/tink.out" 2>&1; summary "$O/tink.out"; }
}

# Diagnosis of gmsm ML-DSA. The only valid vectors gmsm rejects are the three per parameter set with an empty
# message. To confirm that the cause is the check "if len(message) == 0 { return false }" in VerifyWithOptions (and
# not the sampling of matrix A that the vector comments talk about), the module is copied, ONLY that check is removed
# from verification, and the same program is run again. The copy lives in $W/diag; the original module is not touched.
# This is a diagnosis, not the test: the result that counts is the one of the unmodified module.
diag_gmsm() {
    local D="$W/diag" T
    rm -rf "$D"; mkdir -p "$D"
    cp -r "$GOMODCACHE/github.com/emmansun/gmsm@v0.45.4" "$D/gmsm"; chmod -R u+w "$D/gmsm"
    cp -r "$SRC/go" "$D/go"
    # remove the 3-line block that returns false on an empty message (the signing one returns an error and is kept)
    perl -0pi -e 's/\tif len\(message\) == 0 \{\n\t\treturn false\n\t\}\n//g' "$D"/gmsm/mldsa/mldsa{44,65,87}.go
    echo "== diagnosis: empty-message checks left in the copy (only the signing ones should remain):"
    grep -n -A1 'len(message) == 0' "$D"/gmsm/mldsa/mldsa{44,65,87}.go | sed "s|$D/||"
    ( cd "$D/go" && go mod edit -replace github.com/emmansun/gmsm="$D/gmsm" && go mod tidy >/dev/null 2>&1 )
    for T in "" purego; do
        ( cd "$D/go" && go build ${T:+-tags $T} -o "$D/gmsm-diag" ./gmsm ) || { echo "does not build"; continue; }
        "$D/gmsm-diag" "$V" >"$D/diag-$T.out" 2>&1
        echo "== gmsm v0.45.4 WITHOUT the empty-message check in verification ${T:+(-tags $T)}"
        summary "$D/diag-$T.out" | grep -v 'ML-KEM'
    done
}

[ $# -eq 0 ] && set -- cryptoxide purecrypto macula gmsm k2so tink
GO_READY=false
for X in "$@"; do
    case "$X" in
        cryptoxide|purecrypto|macula) rust "$X" ;;
        gmsm|k2so|tink) $GO_READY || { prepare_go; GO_READY=true; }; "$X" ;;
        diag-gmsm) $GO_READY || { prepare_go; GO_READY=true; }; [ -d "$GOMODCACHE/github.com/emmansun/gmsm@v0.45.4" ] || ( cd "$SRC/go" && go mod download github.com/emmansun/gmsm ); diag_gmsm ;;
        *) echo "unknown: $X" ;;
    esac
done
