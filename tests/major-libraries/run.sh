#!/usr/bin/env bash
# Run the Wycheproof ML-DSA verification and ML-KEM vectors against the current code of the major libraries on
# x86_64. Each library is built from source at a pinned commit of its development branch, or at the named release:
#
#   wolfssl    wolfSSL: ML-DSA at 511ea63482eb (auto, AVX-512 off, AVX2 off), ML-KEM at f10bbcc7a15e
#   openssl    OpenSSL 354f1cf64842 (ML-DSA, ML-KEM)
#   boringssl  BoringSSL 12cb59022ae9 (ML-DSA, ML-KEM-768 and ML-KEM-1024)
#   aws-lc     AWS-LC 784feabf5fe3 (ML-DSA, ML-KEM)
#   symcrypt   SymCrypt 286762b7730e (ML-DSA, ML-KEM)
#   liboqs     liboqs: ML-DSA from the 0.16.0 release, ML-KEM from the development branch at f822b059350a; each in a
#              distribution build (optimized code chosen at run time) and a portable C build
#   pqclean    PQClean 0586a824fc0d, ML-DSA "clean"
#   botan      Botan 3a5a820fa54e, ML-DSA (only the vectors with an empty context)
#   go         Go 1.27.3 crypto/mldsa and crypto/mlkem, and CIRCL 31be93db4772 (ML-DSA, ML-KEM)
#   java       Bouncy Castle bcprov-jdk18on 1.87 from Maven Central (ML-DSA, ML-KEM)
#   rust       RustCrypto ml-dsa / ml-kem and libcrux (automatic, portable and AVX2 paths), commits pinned in
#              rust-mldsa/Cargo.toml and rust-mlkem/Cargo.toml
#   masked     OpenSSL, AWS-LC and BoringSSL again, with OPENSSL_ia32cap masking AVX-512, AVX2 and AVX in turn
#
# Needs: Linux x86_64, git, curl, python3, gcc, g++, cmake, make, perl, autoconf, automake, libtool; a JDK (javac and
# java) for "java"; rustup and cargo for "rust". Go 1.27.3 is downloaded into $WORK if the go on the PATH is another
# version. Everything is downloaded and built under $WORK. Nothing is installed system-wide.
#
# Usage:  ./run.sh [wolfssl] [openssl] [boringssl] [aws-lc] [symcrypt] [liboqs] [pqclean] [botan] [go] [java] [rust] [masked]
#         (no arguments: all of them, in this order)        set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
WOLFSSL_MLDSA_COMMIT=511ea63482eb3e3a226f0ce05ae595e6e35e5f4d
WOLFSSL_MLKEM_COMMIT=f10bbcc7a15e4e4b3eeaabb8a8c1b30a128bed58
OPENSSL_COMMIT=354f1cf64842dc03f30a97a3a4fd8a7b48e40807
BORINGSSL_COMMIT=12cb59022ae9cc34561113903cdee28ff3bdce17
AWSLC_COMMIT=784feabf5fe33678bfbd4badcd6e795092a37b7e
SYMCRYPT_COMMIT=286762b7730e2b780678f5ab11fef2b1bad639e0
LIBOQS_MLDSA_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183   # tag 0.16.0
LIBOQS_MLKEM_COMMIT=f822b059350af22adad99ef6b09a18819bcd49ed   # development branch, reports version 0.16.0
PQCLEAN_COMMIT=0586a824fc0d49df0b6b6e9179d8d15d06d0974f
BOTAN_COMMIT=3a5a820fa54e259bb5f7656cbe9604fad8fa4bbd
CIRCL_COMMIT=31be93db4772d9482a06c44eb2ed134fdacd2a2b
GO_VERSION=1.27.3
BC_VERSION=1.87
W="$WORK/major-libraries"; V="$WORK/vectors"; X="$W/bin"
mkdir -p "$W" "$V" "$X"
export PATH="$HOME/.cargo/bin:$PATH"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch_commit() { # url dir full-commit: shallow fetch of a single commit (for large repositories)
    [ -d "$2/.git" ] && return 0
    mkdir -p "$2" && git -C "$2" init -q && git -C "$2" remote add origin "$1" && git -C "$2" fetch -q --depth 1 origin "$3" \
        && git -C "$2" -c advice.detachedHead=false checkout -q FETCH_HEAD
}
rev() { echo "$(git -C "$1" rev-parse --short=12 HEAD) ($(git -C "$1" log -1 --format=%cs))"; }
need() { local m=""; for c in "$@"; do command -v "$c" >/dev/null || m="$m $c"; done; [ -z "$m" ] || { echo "missing:$m"; return 1; }; }
link_fail() { echo "   test program does not build:"; grep -m5 -E 'error|undefined' "$1" | cut -c1-200 | sed 's/^/     /'; }
# One run per parameter set; every output line is kept (the per-vector lines only appear on a discrepancy).
dsa() { local B="$1" P; shift; for P in 44 65 87; do "$B" "$V/mldsa_$P.txt" "$P" "$@"; done; }
kem() { local B="$1" P; shift; for P in 512 768 1024; do "$B" "$V/mlkem_$P.txt" "$P" "$@"; done; }

fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done
echo "Wycheproof $WYCHEPROOF_COMMIT: ML-DSA $(wc -l <"$V/mldsa_44.txt") / $(wc -l <"$V/mldsa_65.txt") / $(wc -l <"$V/mldsa_87.txt") vectors (44 / 65 / 87), ML-KEM $(wc -l <"$V/mlkem_512.txt") / $(wc -l <"$V/mlkem_768.txt") / $(wc -l <"$V/mlkem_1024.txt") (512 / 768 / 1024)"
echo "Machine: $(uname -srm); $(gcc --version | head -1); $(nproc) cores"
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'); $(grep -m1 '^flags' /proc/cpuinfo | grep -ow 'avx\|avx2\|avx512[a-z0-9_]*' | sort -u | tr '\n' ' ')"
echo "Note: in ML-KEM, the \"seed\" lines whose seed is not 64 bytes long (20 per parameter set) are rejected by the"
echo "harness itself without calling the library."

# ---------------------------------------------------------------------------------------------------------------------
# wolfSSL, two commits of the development branch (the ones we tested): one build with ML-DSA, one with ML-KEM, both
# with --enable-intelasm. wolfSSL chooses its x86_64 code at run time from the CPU flags it detects; the ML-DSA adapter
# clears the AVX-512 flags (no-avx512) or the AVX-512 and AVX2 flags (no-avx2) to run the other paths.
wolfssl_build() { # wolfssl_build <dir> <commit> <configure option>
    local S="$1" I="$1/_inst"
    fetch_commit https://github.com/wolfSSL/wolfssl.git "$S" "$2" || { echo "   could not clone"; return 1; }
    [ -f "$I/lib/libwolfssl.a" ] && return 0
    ( cd "$S" && ./autogen.sh >_autogen.log 2>&1 && ./configure --enable-intelasm "$3" --enable-static --disable-shared \
          --disable-examples --disable-crypttests --prefix="$I" >_configure.log 2>&1 && make -j"$(nproc)" install >_make.log 2>&1 ) \
      || { echo "   does not build (see $S/_*.log): $(grep -m2 -i error "$S/_configure.log" "$S/_make.log" | cut -c1-200)"; return 1; }
}
run_wolfssl() {
    local S="$W/wolfssl-mldsa" M
    if wolfssl_build "$S" "$WOLFSSL_MLDSA_COMMIT" --enable-mldsa; then
        echo "== wolfSSL $(rev "$S"), --enable-intelasm --enable-mldsa"
        echo "   options.h: $(grep -ow 'USE_INTEL_SPEEDUP\|WOLFSSL_X86_64_BUILD\|WOLFSSL_HAVE_MLDSA' "$S/_inst/include/wolfssl/options.h" | sort -u | tr '\n' ' ')"
        if gcc -O2 -w -I"$S/_inst/include" -I"$HERE" "$HERE/mldsa_wolfssl.c" "$S/_inst/lib/libwolfssl.a" -lm -lpthread -o "$X/wolfssl_md" 2>"$X/wolfssl_md.log"; then
            for M in auto no-avx512 no-avx2; do dsa "$X/wolfssl_md" "$M"; done
        else link_fail "$X/wolfssl_md.log"; fi
    fi
    S="$W/wolfssl-mlkem"
    if wolfssl_build "$S" "$WOLFSSL_MLKEM_COMMIT" --enable-mlkem; then
        echo "== wolfSSL $(rev "$S"), --enable-intelasm --enable-mlkem"
        if gcc -O2 -w -I"$S/_inst/include" -I"$HERE" "$HERE/mlkem_wolfssl.c" "$S/_inst/lib/libwolfssl.a" -lm -lpthread -o "$X/wolfssl_mk" 2>"$X/wolfssl_mk.log"; then
            kem "$X/wolfssl_mk"
        else link_fail "$X/wolfssl_mk.log"; fi
    fi
}

# ---------------------------------------------------------------------------------------------------------------------
# OpenSSL, AWS-LC and BoringSSL: static libcrypto with the default options (assembly included). The *_build functions
# also link the two test programs, which "masked" runs again.
openssl_build() {
    local S="$W/openssl"
    fetch_commit https://github.com/openssl/openssl.git "$S" "$OPENSSL_COMMIT" || { echo "== OpenSSL: could not clone"; return 1; }
    [ -f "$S/libcrypto.a" ] || ( cd "$S" && ./Configure no-shared no-tests no-docs >_configure.log 2>&1 \
        && make -j"$(nproc)" build_generated libcrypto.a >_make.log 2>&1 ) || { echo "== OpenSSL: does not build: $(tail -3 "$S/_make.log" | cut -c1-200)"; return 1; }
    gcc -O2 -w -I"$S/include" -I"$HERE" "$HERE/mlkem_openssl.c" "$S/libcrypto.a" -ldl -lpthread -o "$X/openssl_mk" 2>"$X/openssl_mk.log" || { link_fail "$X/openssl_mk.log"; return 1; }
    gcc -O2 -w -I"$S/include" -I"$HERE" "$HERE/mldsa_openssl.c" "$S/libcrypto.a" -ldl -lpthread -o "$X/openssl_md" 2>"$X/openssl_md.log" || { link_fail "$X/openssl_md.log"; return 1; }
}
awslc_build() {
    local S="$W/aws-lc" B="$W/aws-lc/_build" L
    fetch_commit https://github.com/aws/aws-lc.git "$S" "$AWSLC_COMMIT" || { echo "== AWS-LC: could not clone"; return 1; }
    [ -n "$(find "$B" -name libcrypto.a 2>/dev/null | head -n1)" ] || { cmake -S "$S" -B "$B" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTING=OFF -DBUILD_LIBSSL=OFF -DBUILD_TOOL=OFF -DDISABLE_GO=ON -DDISABLE_PERL=ON >"$S/_cmake.log" 2>&1 \
        && cmake --build "$B" -j"$(nproc)" --target crypto >"$S/_make.log" 2>&1; } || { echo "== AWS-LC: does not build: $(grep -m2 -i error "$S/_cmake.log" "$S/_make.log" | cut -c1-200)"; return 1; }
    L="$(find "$B" -name libcrypto.a | head -n1)"
    gcc -O2 -w -I"$HERE" "$HERE/mlkem_awslc.c" "$L" -lpthread -ldl -o "$X/awslc_mk" 2>"$X/awslc_mk.log" || { link_fail "$X/awslc_mk.log"; return 1; }
    gcc -O2 -w -I"$HERE" "$HERE/mldsa_awslc.c" "$L" -lpthread -ldl -o "$X/awslc_md" 2>"$X/awslc_md.log" || { link_fail "$X/awslc_md.log"; return 1; }
}
boringssl_build() {
    local S="$W/boringssl" B="$W/boringssl/_build" L
    fetch_commit https://github.com/google/boringssl.git "$S" "$BORINGSSL_COMMIT" || { echo "== BoringSSL: could not clone"; return 1; }
    [ -n "$(find "$B" -name libcrypto.a 2>/dev/null | head -n1)" ] || { cmake -S "$S" -B "$B" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF >"$S/_cmake.log" 2>&1 \
        && cmake --build "$B" -j"$(nproc)" --target crypto >"$S/_make.log" 2>&1; } || { echo "== BoringSSL: does not build: $(grep -m2 -i error "$S/_cmake.log" "$S/_make.log" | cut -c1-200)"; return 1; }
    L="$(find "$B" -name libcrypto.a | head -n1)"
    g++ -O2 -w -std=c++17 -I"$S/include" -I"$HERE" "$HERE/mlkem_boringssl.cc" "$L" -lpthread -o "$X/boringssl_mk" 2>"$X/boringssl_mk.log" || { link_fail "$X/boringssl_mk.log"; return 1; }
    g++ -O2 -w -std=c++17 -I"$S/include" -I"$HERE" "$HERE/mldsa_boringssl.cc" "$L" -lpthread -o "$X/boringssl_md" 2>"$X/boringssl_md.log" || { link_fail "$X/boringssl_md.log"; return 1; }
}
run_openssl()   { openssl_build   && echo "== OpenSSL $(rev "$W/openssl"), default build (linux-x86_64, with assembly)" && { kem "$X/openssl_mk"; dsa "$X/openssl_md"; }; }
run_awslc()     { awslc_build     && echo "== AWS-LC $(rev "$W/aws-lc"), default build (with assembly)" && { kem "$X/awslc_mk"; dsa "$X/awslc_md"; }; }
run_boringssl() { boringssl_build && echo "== BoringSSL $(rev "$W/boringssl"), default build (with assembly)" && { kem "$X/boringssl_mk"; dsa "$X/boringssl_md"; }; }

# The three libraries again with their documented OPENSSL_ia32cap variable, which masks CPUID bits before the library
# chooses its code. The masks clear bits 16-31 of CPUID leaf 7 EBX (AVX-512 F, DQ, IFMA, CD, BW, VL, and with them
# RDSEED, ADX and SHA), then also bit 5 (AVX2), then also bit 28 of leaf 1 ECX (AVX). The first configuration leaves
# the variable unset (the same as the plain runs above).
run_masked() {
    local L OK="" LABEL MASK
    for L in openssl awslc boringssl; do "${L}_build" && OK="$OK $L"; done
    while IFS='|' read -r LABEL MASK; do
        if [ -n "$MASK" ]; then echo "#### x86_64, $LABEL  (OPENSSL_ia32cap=$MASK)"; else echo "#### x86_64, $LABEL  (OPENSSL_ia32cap unset)"; fi
        for L in $OK; do
            case "$L" in openssl) echo "== OpenSSL $(rev "$W/openssl")" ;; awslc) echo "== AWS-LC $(rev "$W/aws-lc")" ;; boringssl) echo "== BoringSSL $(rev "$W/boringssl")" ;; esac
            ( if [ -n "$MASK" ]; then export OPENSSL_ia32cap="$MASK"; else unset OPENSSL_ia32cap; fi
              kem "$X/${L}_mk"; dsa "$X/${L}_md" )
        done
    done <<'EOF'
no mask|
AVX-512 off|:~0xFFFF0000
AVX2 and AVX-512 off|:~0xFFFF0020
AVX, AVX2 and AVX-512 off|~0x1000000000000000:~0xFFFF0020
EOF
}

# ---------------------------------------------------------------------------------------------------------------------
# SymCrypt, static libraries without FIPS post-processing, POSIX user-mode environment.
run_symcrypt() {
    local S="$W/SymCrypt" B="$W/SymCrypt/_build" C LIBS
    fetch_commit https://github.com/microsoft/SymCrypt.git "$S" "$SYMCRYPT_COMMIT" || { echo "== SymCrypt: could not clone"; return 1; }
    if [ ! -f "$B/lib/libsymcrypt_common.a" ]; then
        { cmake -S "$S" -B "$B" -DCMAKE_BUILD_TYPE=RelWithDebInfo -DSYMCRYPT_FIPS_BUILD=OFF -DSYMCRYPT_FIPS_POSTPROCESS=OFF >"$S/_cmake.log" 2>&1 \
          && cmake --build "$B" -j"$(nproc)" --target symcrypt_common symcrypt_mlkem symcrypt_posixusermode >"$S/_make.log" 2>&1; } \
          || { echo "== SymCrypt: does not build: $(grep -m2 -E 'error|Error' "$S/_cmake.log" "$S/_make.log" | cut -c1-200)"; return 1; }
    fi
    echo "== SymCrypt $(rev "$S"), RelWithDebInfo, non-FIPS"
    LIBS="-Wl,--start-group $B/lib/libsymcrypt_common.a $B/lib/libsymcrypt_mlkem.a $B/lib/libsymcrypt_posixusermode.a -Wl,--end-group -lpthread"
    for C in mk:mlkem md:mldsa; do
        gcc -O2 -w -I"$S/inc" -I"$B/inc" -I"$HERE" "$HERE/${C#*:}_symcrypt.c" $LIBS -o "$X/symcrypt_${C%%:*}" 2>"$X/symcrypt_${C%%:*}.log" || { link_fail "$X/symcrypt_${C%%:*}.log"; return 1; }
    done
    kem "$X/symcrypt_mk"; dsa "$X/symcrypt_md"
}

# ---------------------------------------------------------------------------------------------------------------------
# liboqs, two builds of each source: "dist" (OQS_DIST_BUILD: every optimized implementation is compiled in and the
# one for the processor is chosen at run time, AVX2 here) and "generic" (OQS_OPT_TARGET=generic: portable C only).
# Only the ML-DSA or ML-KEM algorithms are built (OQS_MINIMAL_BUILD). ML-DSA goes through wycheproof_mldsa.c, ML-KEM
# through mlkem_liboqs.c.
liboqs_build() { # liboqs_build <source dir> <commit> <dist|generic> <algorithm list>
    local S="$1" B="$1/_build-$3" OPT="-DOQS_DIST_BUILD=ON"
    [ "$3" = generic ] && OPT="-DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic"
    fetch_commit https://github.com/open-quantum-safe/liboqs.git "$S" "$2" || { echo "   could not clone"; return 1; }
    [ -f "$B/lib/liboqs.a" ] || { cmake -S "$S" -B "$B" -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_USE_OPENSSL=OFF $OPT -DOQS_MINIMAL_BUILD="$4" >"$B.cmake.log" 2>&1 && cmake --build "$B" -j"$(nproc)" >"$B.make.log" 2>&1; } \
        || { echo "   does not build; see $B.make.log"; return 1; }
    local IMPL="$(grep -o 'OQS_ENABLE_[A-Z]*_ml_[a-z]*_[0-9]*_[a-z0-9_]* 1' "$B/include/oqs/oqsconfig.h" | sed 's/OQS_ENABLE_//; s/ 1//' | tr '\n' ' ')"
    echo "== liboqs $(grep -m1 'OQS_VERSION_TEXT' "$B/include/oqs/oqsconfig.h" | cut -d'"' -f2) at $(rev "$S"), build \"$3\"; optimized implementations compiled in: ${IMPL:-none (portable C only)}"
}
run_liboqs() {
    local VAR S B P
    for VAR in dist generic; do
        S="$W/liboqs-mldsa"; B="$S/_build-$VAR"
        liboqs_build "$S" "$LIBOQS_MLDSA_COMMIT" "$VAR" "SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87" || continue
        for P in 44 65 87; do
            if gcc -O2 -w -DWITH_LIBOQS -DALG="\"ML-DSA-$P\"" -I"$B/include" "$HERE/wycheproof_mldsa.c" "$B/lib/liboqs.a" -lm -lpthread -o "$X/liboqs_${VAR}_md$P" 2>"$X/liboqs_md.log"; then
                "$X/liboqs_${VAR}_md$P" "$V/mldsa_$P.txt"
            else link_fail "$X/liboqs_md.log"; fi
        done
    done
    for VAR in dist generic; do
        S="$W/liboqs-mlkem"; B="$S/_build-$VAR"
        liboqs_build "$S" "$LIBOQS_MLKEM_COMMIT" "$VAR" "KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024" || continue
        if gcc -O2 -w -I"$B/include" -I"$HERE" "$HERE/mlkem_liboqs.c" "$B/lib/liboqs.a" -lm -lpthread -o "$X/liboqs_${VAR}_mk" 2>"$X/liboqs_mk.log"; then
            kem "$X/liboqs_${VAR}_mk"
        else link_fail "$X/liboqs_mk.log"; fi
    done
}

# ---------------------------------------------------------------------------------------------------------------------
# PQClean, ML-DSA "clean" (the portable reference code), through wycheproof_mldsa.c.
run_pqclean() {
    local PQ="$W/PQClean" P D NS COMMON
    fetch_commit https://github.com/PQClean/PQClean.git "$PQ" "$PQCLEAN_COMMIT" || { echo "== PQClean: could not clone"; return 1; }
    echo "== PQClean $(rev "$PQ"), ML-DSA clean"
    COMMON="$PQ/common/fips202.c $PQ/common/sha2.c $PQ/common/aes.c $PQ/common/randombytes.c $PQ/common/sp800-185.c"
    for P in 44 65 87; do
        D="$PQ/crypto_sign/ml-dsa-$P/clean/"; NS="PQCLEAN_MLDSA${P}_CLEAN"
        if gcc -O2 -w -DNS="$NS" -I"$PQ/common" -I"$D" "$HERE/wycheproof_mldsa.c" $(ls "$D"*.c) $COMMON -o "$X/$NS" 2>"$X/$NS.log"; then
            "$X/$NS" "$V/mldsa_$P.txt"
        else link_fail "$X/$NS.log"; fi
    done
}

# ---------------------------------------------------------------------------------------------------------------------
# Botan, minimized static build with the ML-DSA module. Its verifier takes no context string (see mldsa_botan.cpp).
run_botan() {
    local S="$W/botan" L
    fetch_commit https://github.com/randombit/botan.git "$S" "$BOTAN_COMMIT" || { echo "== Botan: could not clone"; return 1; }
    L="$(ls "$S"/libbotan-*.a 2>/dev/null | head -n1)"
    if [ -z "$L" ]; then
        ( cd "$S" && python3 configure.py --minimized-build --enable-modules=ml_dsa,dilithium,system_rng --disable-shared-library \
              --without-documentation --build-targets=static >_configure.log 2>&1 && make -j"$(nproc)" >_make.log 2>&1 ) \
          || { echo "== Botan: does not build: $(tail -n 3 "$S/_configure.log" "$S/_make.log" | cut -c1-200)"; return 1; }
        L="$(ls "$S"/libbotan-*.a | head -n1)"
    fi
    echo "== Botan $(rev "$S"), minimized build (modules ml_dsa, dilithium, system_rng)"
    if g++ -O2 -w -std=c++20 -I"$S/build/include/public" -I"$HERE" "$HERE/mldsa_botan.cpp" "$L" -lpthread -o "$X/botan_md" 2>"$X/botan_md.log"; then
        dsa "$X/botan_md"
    else link_fail "$X/botan_md.log"; fi
}

# ---------------------------------------------------------------------------------------------------------------------
# Go: crypto/mldsa and crypto/mlkem of the Go release, and CIRCL at a pinned commit. The module cache and build cache
# are kept under $W.
run_go() {
    local GO D C
    GO="$(command -v go || true)"
    if [ -z "$GO" ] || [ "$("$GO" env GOVERSION 2>/dev/null)" != "go$GO_VERSION" ]; then
        GO="$W/go$GO_VERSION/go/bin/go"
        if [ ! -x "$GO" ]; then
            mkdir -p "$W/go$GO_VERSION" && curl -sSfL -o "$W/go$GO_VERSION.linux-amd64.tar.gz" "https://go.dev/dl/go$GO_VERSION.linux-amd64.tar.gz" \
                && tar xzf "$W/go$GO_VERSION.linux-amd64.tar.gz" -C "$W/go$GO_VERSION" || { echo "== Go: could not download go$GO_VERSION"; return 1; }
            echo "   downloaded go$GO_VERSION.linux-amd64.tar.gz (sha256 $(sha256sum "$W/go$GO_VERSION.linux-amd64.tar.gz" | cut -c1-64))"
        fi
    fi
    export GOTOOLCHAIN=local GOFLAGS=-mod=mod GOPATH="$W/gopath" GOMODCACHE="$W/gopath/pkg/mod" GOCACHE="$W/gocache"
    echo "== $("$GO" version), CIRCL $CIRCL_COMMIT"
    for C in mldsa mlkem; do
        D="$W/go-$C"; rm -rf "$D"; mkdir -p "$D"; cp "$HERE/go-$C/main.go" "$D/"
        ( cd "$D" && "$GO" mod init wycheproof/$C >_get.log 2>&1 && "$GO" get "github.com/cloudflare/circl@$CIRCL_COMMIT" >>_get.log 2>&1 \
          && "$GO" mod tidy >>_get.log 2>&1 ) || { echo "   go get fails:"; tail -n 5 "$D/_get.log"; continue; }
        echo "   go-$C: github.com/cloudflare/circl $(grep cloudflare/circl "$D/go.mod" | awk '{print $NF}')"
        ( cd "$D" && "$GO" run . "$V" )
    done
}

# ---------------------------------------------------------------------------------------------------------------------
# Bouncy Castle: the published jar from Maven Central (checked against the .sha1 published next to it), with the
# lightweight API.
run_java() {
    local D="$W/bouncycastle" JAR="bcprov-jdk18on-$BC_VERSION.jar" U="https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/$BC_VERSION" SHA1
    need javac java || return 1
    mkdir -p "$D"
    [ -f "$D/$JAR" ] || curl -sSfL -o "$D/$JAR" "$U/$JAR" || { echo "== Bouncy Castle: could not download $JAR"; return 1; }
    SHA1="$(curl -sSfL "$U/$JAR.sha1" | cut -c1-40)"
    echo "== Bouncy Castle $JAR from Maven Central (sha256 $(sha256sum "$D/$JAR" | cut -c1-64); sha1 $([ "$(sha1sum "$D/$JAR" | cut -c1-40)" = "$SHA1" ] && echo "matches" || echo "DOES NOT MATCH") the published .sha1)"
    echo "   $(java -version 2>&1 | head -1)"
    rm -rf "$D/classes"
    javac -cp "$D/$JAR" -d "$D/classes" "$HERE/java/WycheproofMLDSA.java" "$HERE/java/WycheproofMLKEM.java" 2>"$D/_javac.log" \
        || { echo "   javac fails:"; head -n 12 "$D/_javac.log"; return 1; }
    java -cp "$D/$JAR:$D/classes" WycheproofMLDSA "$V"
    java -cp "$D/$JAR:$D/classes" WycheproofMLKEM "$V"
}

# ---------------------------------------------------------------------------------------------------------------------
# RustCrypto and libcrux (automatic, portable and AVX2 paths), built for this processor (target-cpu=native).
run_rust() {
    local C D
    need cargo rustc || return 1
    for C in rust-mldsa:wycheproof-mldsa rust-mlkem:wycheproof-mlkem; do
        D="$W/${C%%:*}"; mkdir -p "$D"; rm -rf "$D/src"; cp -r "$HERE/${C%%:*}/." "$D/"
        echo "== ${C##*:}, $(rustc --version), RUSTFLAGS=\"-C target-cpu=native\""
        if ( cd "$D" && RUSTFLAGS="-C target-cpu=native" cargo build --release >_build.log 2>&1 ); then
            grep -E 'name = "(ml-dsa|ml-kem|libcrux-ml-dsa|libcrux-ml-kem)"' -A2 "$D/Cargo.lock" | grep -E 'name|version|source' | sed 's/^/   /'
            "$D/target/release/${C##*:}" "$V"
        else
            echo "   cargo build fails:"; grep -E '^error' -A9 "$D/_build.log" | head -n 40
        fi
    done
}

[ $# -eq 0 ] && set -- wolfssl openssl boringssl aws-lc symcrypt liboqs pqclean botan go java rust masked
for A in "$@"; do
    echo
    case "$A" in
        wolfssl)   echo "########## wolfSSL"; run_wolfssl ;;
        openssl)   echo "########## OpenSSL"; run_openssl ;;
        boringssl) echo "########## BoringSSL"; run_boringssl ;;
        aws-lc)    echo "########## AWS-LC"; run_awslc ;;
        symcrypt)  echo "########## SymCrypt"; run_symcrypt ;;
        liboqs)    echo "########## liboqs"; run_liboqs ;;
        pqclean)   echo "########## PQClean"; run_pqclean ;;
        botan)     echo "########## Botan"; run_botan ;;
        go)        echo "########## Go crypto/mldsa, crypto/mlkem and CIRCL"; ( run_go ) ;;
        java)      echo "########## Bouncy Castle (Java)"; run_java ;;
        rust)      echo "########## RustCrypto and libcrux"; run_rust ;;
        masked)    echo "########## OpenSSL, AWS-LC and BoringSSL with OPENSSL_ia32cap masks"; run_masked ;;
        *)         echo "unknown: $A" ;;
    esac
done
