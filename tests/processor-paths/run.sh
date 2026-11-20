#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors through the processor-specific code paths of libraries whose x86_64
# results are already known, on other architectures, with cross compilation and user-mode emulation (qemu-user):
#
#   arm       PQClean (aarch64 ML-DSA, NEON) and liboqs (distribution build for aarch64, ML-DSA and ML-KEM)
#   cross     PQClean ("clean" ML-DSA) and liboqs on riscv64 and s390x (s390x is big-endian)
#   rust-arm  RustCrypto ml-dsa / ml-kem and libcrux (automatic, portable and NEON paths) for aarch64
#   big-arm   OpenSSL, AWS-LC and BoringSSL built for aarch64 with their assembly
#
# Versions: PQClean 0586a824fc0d, liboqs releases (LIBOQS_VERSIONS), OpenSSL 354f1cf64842, AWS-LC 784feabf5fe3 and
# BoringSSL 12cb59022ae9 (development branches at the commits we tested); the Rust crates are pinned in
# rust-mldsa/Cargo.toml and rust-mlkem/Cargo.toml.
#
# Needs: git, curl, python3, cmake, make, perl, qemu-user (qemu-aarch64, qemu-riscv64, qemu-s390x), the cross compilers
# gcc-aarch64-linux-gnu, g++-aarch64-linux-gnu, gcc-riscv64-linux-gnu and gcc-s390x-linux-gnu with their
# libc6-dev-*-cross packages, and for rust-arm: rustup, cargo and the aarch64-unknown-linux-gnu target.
# Everything is downloaded and built under $WORK. Nothing is installed system-wide.
#
# Usage:  ./run.sh [arm] [cross] [rust-arm] [big-arm]      (no arguments: all four)
#         LIBOQS_VERSIONS="0.12.0 0.13.0 0.14.0 0.15.0 0.16.0"   CROSS_ARCHS="riscv64 s390x"
#         BIG="openssl aws-lc boringssl"                         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
PQCLEAN_COMMIT=0586a824fc0d49df0b6b6e9179d8d15d06d0974f
OPENSSL_COMMIT=354f1cf64842dc03f30a97a3a4fd8a7b48e40807
AWSLC_COMMIT=784feabf5fe33678bfbd4badcd6e795092a37b7e
BORINGSSL_COMMIT=12cb59022ae9cc34561113903cdee28ff3bdce17
LIBOQS_VERSIONS="${LIBOQS_VERSIONS:-0.12.0 0.13.0 0.14.0 0.15.0 0.16.0}"
W="$WORK/processor-paths"; V="$WORK/vectors"
mkdir -p "$W" "$V"
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
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done
echo "Wycheproof $WYCHEPROOF_COMMIT"

need() { local m=""; for c in "$@"; do command -v "$c" >/dev/null || m="$m $c"; done; [ -z "$m" ] || { echo "missing:$m"; return 1; }; }

# liboqs, one version, distribution build for <arch>; then ML-DSA (wycheproof_mldsa.c) and ML-KEM (mlkem_liboqs.c).
liboqs_arch() { # liboqs_arch <arch> <version> <qemu command...>
    local A="$1" REF="$2"; shift 2
    local CC=$A-linux-gnu-gcc S="$W/liboqs-$REF" B="$W/liboqs-$REF/_build-$A" P
    [ -d "$S/.git" ] || git -c advice.detachedHead=false clone --quiet --depth 1 --branch "$REF" https://github.com/open-quantum-safe/liboqs.git "$S" 2>/dev/null \
        || { echo "== liboqs $REF: could not clone"; return 1; }
    echo "== liboqs $REF ($(git -C "$S" rev-parse --short=12 HEAD)), $A, distribution build, emulated"
    if [ ! -f "$B/lib/liboqs.a" ]; then
        cmake -S "$S" -B "$B" -DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=$A -DCMAKE_C_COMPILER=$CC \
            -DCMAKE_ASM_COMPILER=$CC -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
            -DOQS_BUILD_ONLY_LIB=ON -DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87;KEM_ml_kem_512;KEM_ml_kem_768;KEM_ml_kem_1024" \
            >"$S/_cmake-$A.log" 2>&1 && cmake --build "$B" -j"$(nproc)" >"$S/_make-$A.log" 2>&1 \
            || { echo "does not build; see $S/_make-$A.log: $(grep -m2 -i 'error' "$S/_make-$A.log" "$S/_cmake-$A.log" | cut -c1-200)"; return 1; }
    fi
    echo "   variants built: $(grep -o 'OQS_ENABLE_[A-Z]*_ml_[a-z]*_[0-9]*_[a-z0-9_]* 1' "$B/include/oqs/oqsconfig.h" | sed 's/OQS_ENABLE_//; s/ 1//' | tr '\n' ' ')"
    for P in 44 65 87; do
        $CC -O2 -static -w -DWITH_LIBOQS -DALG="\"ML-DSA-$P\"" -I"$B/include" "$HERE/wycheproof_mldsa.c" "$B/lib/liboqs.a" -lm -lpthread -o "$B/_wd$P" 2>"$B/_wd.log" \
            && "$@" "$B/_wd$P" "$V/mldsa_$P.txt" | tail -1 || echo "ML-DSA-$P: $(grep -m1 -i error "$B/_wd.log" | cut -c1-160)"
    done
    { $CC -O2 -static -w -I"$B/include" -I"$HERE" "$HERE/mlkem_liboqs.c" "$B/lib/liboqs.a" -lm -lpthread -o "$B/_wk" 2>"$B/_wk.log" \
        || { echo "   (no fixed-randomness functions: only acceptance of keys and the expanded decapsulation key)"; $CC -O2 -static -w -DNO_DERAND -I"$B/include" -I"$HERE" "$HERE/mlkem_liboqs.c" "$B/lib/liboqs.a" -lm -lpthread -o "$B/_wk" 2>"$B/_wk.log"; }; } \
        && for P in 512 768 1024; do "$@" "$B/_wk" "$V/mlkem_$P.txt" "$P" | tail -1; done || echo "ML-KEM: $(grep -m1 -i error "$B/_wk.log" | cut -c1-160)"
}

# PQClean ML-DSA, one implementation (<impl> = aarch64 or clean), built for <arch>.
pqclean_arch() { # pqclean_arch <arch> <impl> <extra gcc flags> <qemu command...>
    local A="$1" IMPL="$2" XF="$3"; shift 3
    local CC=$A-linux-gnu-gcc PQ="$W/PQClean" P D NS COMMON
    fetch_commit https://github.com/PQClean/PQClean.git "$PQ" "$PQCLEAN_COMMIT" || { echo "== PQClean: could not clone"; return 1; }
    echo "== PQClean $(git -C "$PQ" rev-parse --short=12 HEAD), ML-DSA $IMPL on $A, emulated"
    COMMON="$PQ/common/fips202.c $PQ/common/sha2.c $PQ/common/aes.c $PQ/common/randombytes.c $PQ/common/sp800-185.c"
    # the two-way Keccak (keccak2x, NEON) is only for the aarch64 implementation
    [ "$IMPL" = aarch64 ] && COMMON="$COMMON $(ls "$PQ"/common/keccak2x/*.c "$PQ"/common/keccak2x/*.S 2>/dev/null | tr '\n' ' ')"
    mkdir -p "$PQ/_out-$A"
    for P in 44 65 87; do
        D="$PQ/crypto_sign/ml-dsa-$P/$IMPL/"; NS="PQCLEAN_MLDSA${P}_$(echo "$IMPL" | tr a-z A-Z)"
        $CC -O2 -static $XF -w -DNS="$NS" -I"$PQ/common" -I"$PQ/common/keccak2x" -I"$D" "$HERE/wycheproof_mldsa.c" \
            $(ls "$D"*.c "$D"*.S 2>/dev/null) $COMMON -o "$PQ/_out-$A/$NS" 2>"$PQ/_out-$A/$NS.log" \
            && "$@" "$PQ/_out-$A/$NS" "$V/mldsa_$P.txt" || echo "ML-DSA-$P $A: does not build: $(grep -m2 -i 'error\|undefined' "$PQ/_out-$A/$NS.log" | cut -c1-200)"
    done
}

arm() {
    need aarch64-linux-gnu-gcc qemu-aarch64 || return 1
    pqclean_arch aarch64 aarch64 "-march=armv8.2-a+sha3" qemu-aarch64 -cpu max
    for REF in $LIBOQS_VERSIONS; do liboqs_arch aarch64 "$REF" qemu-aarch64 -cpu max; done
}

cross() {
    local A
    for A in ${CROSS_ARCHS:-riscv64 s390x}; do
        echo "######## $A"
        need $A-linux-gnu-gcc qemu-$A || continue
        pqclean_arch "$A" clean "" qemu-$A -cpu max
        for REF in $LIBOQS_VERSIONS; do liboqs_arch "$A" "$REF" qemu-$A -cpu max; done
    done
}

# RustCrypto and libcrux (automatic, portable and NEON) built for ARM64 and run with qemu-user.
rust_arm() {
    local T=aarch64-unknown-linux-gnu C D
    need cargo aarch64-linux-gnu-gcc qemu-aarch64 || return 1
    rustup target add $T >/dev/null 2>&1
    export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
    for C in rust-mldsa:wycheproof-mldsa rust-mlkem:wycheproof-mlkem; do
        D="$W/arm-${C%%:*}"; mkdir -p "$D"; rm -rf "$D/src"; cp -r "$HERE/${C%%:*}/." "$D/"
        ( cd "$D" && echo "== ${C##*:} for $T, $(rustc --version)" && cargo build --release --target $T >_build.log 2>&1 \
          && grep -E 'name = "(ml-dsa|ml-kem|libcrux-ml-dsa|libcrux-ml-kem)"' -A2 Cargo.lock | grep -E 'name|version|source' | sed 's/^/   /' \
          && qemu-aarch64 -cpu max -L /usr/aarch64-linux-gnu "target/$T/release/${C##*:}" "$V" ) \
          || { echo "fails:"; grep -E '^error' -A9 "$D/_build.log" | head -n 40; }
    done
}

# OpenSSL, AWS-LC and BoringSSL built for ARM64 (with their assembly) and run with qemu-user.
big_arm() {
    local CC=aarch64-linux-gnu-gcc CXX=aarch64-linux-gnu-g++ Q="qemu-aarch64 -cpu max" S B L WHICH
    local TC="-DCMAKE_SYSTEM_NAME=Linux -DCMAKE_SYSTEM_PROCESSOR=aarch64 -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX -DCMAKE_ASM_COMPILER=$CC -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF"
    need $CC $CXX qemu-aarch64 || return 1
    kem() { for P in 512 768 1024; do $Q "$1" "$V/mlkem_$P.txt" "$P" | tail -1; done; }
    dsa() { for P in 44 65 87; do $Q "$1" "$V/mldsa_$P.txt" "$P" | tail -1; done; }
    for WHICH in ${BIG:-openssl aws-lc boringssl}; do
    case "$WHICH" in
    openssl)
        S="$W/openssl-arm64"
        fetch_commit https://github.com/openssl/openssl.git "$S" "$OPENSSL_COMMIT" || { echo "== OpenSSL: could not clone"; continue; }
        echo "== OpenSSL $(git -C "$S" rev-parse --short=12 HEAD), linux-aarch64 with assembly, emulated"
        [ -f "$S/libcrypto.a" ] || ( cd "$S" && ./Configure linux-aarch64 --cross-compile-prefix=aarch64-linux-gnu- no-shared no-tests no-docs >_configure.log 2>&1 \
            && make -j"$(nproc)" build_generated libcrypto.a >_make.log 2>&1 ) || { echo "does not build: $(tail -3 "$S/_make.log" | cut -c1-200)"; continue; }
        $CC -O2 -static -w -I"$S/include" -I"$HERE" "$HERE/mlkem_openssl.c" "$S/libcrypto.a" -ldl -lpthread -o "$S/_mk" 2>"$S/_mk.log" && kem "$S/_mk" || grep -m3 -E 'error|undefined' "$S/_mk.log"
        $CC -O2 -static -w -I"$S/include" -I"$HERE" "$HERE/mldsa_openssl.c" "$S/libcrypto.a" -ldl -lpthread -o "$S/_md" 2>"$S/_md.log" && dsa "$S/_md" || grep -m3 -E 'error|undefined' "$S/_md.log" ;;
    aws-lc)
        S="$W/aws-lc"; B="$S/_build-arm64"
        fetch_commit https://github.com/aws/aws-lc.git "$S" "$AWSLC_COMMIT" || { echo "== AWS-LC: could not clone"; continue; }
        echo "== AWS-LC $(git -C "$S" rev-parse --short=12 HEAD), aarch64 with assembly, emulated"
        [ -n "$(find "$B" -name libcrypto.a 2>/dev/null | head -n1)" ] || { cmake -S "$S" -B "$B" $TC -DBUILD_TESTING=OFF -DBUILD_TOOL=OFF -DBUILD_LIBSSL=OFF -DDISABLE_GO=ON -DDISABLE_PERL=ON >"$S/_cmake-arm64.log" 2>&1 \
            && cmake --build "$B" -j"$(nproc)" --target crypto >"$S/_make-arm64.log" 2>&1; } || { echo "does not build: $(grep -m2 -i error "$S/_cmake-arm64.log" "$S/_make-arm64.log" | cut -c1-200)"; continue; }
        L="$(find "$B" -name libcrypto.a | head -n1)"
        $CC -O2 -static -w -I"$HERE" "$HERE/mlkem_awslc.c" "$L" -lpthread -ldl -o "$B/_mk" 2>"$B/_mk.log" && kem "$B/_mk" || grep -m3 -E 'error|undefined' "$B/_mk.log"
        $CC -O2 -static -w -I"$HERE" "$HERE/mldsa_awslc.c" "$L" -lpthread -ldl -o "$B/_md" 2>"$B/_md.log" && dsa "$B/_md" || grep -m3 -E 'error|undefined' "$B/_md.log" ;;
    boringssl)
        S="$W/boringssl"; B="$S/_build-arm64"
        fetch_commit https://github.com/google/boringssl.git "$S" "$BORINGSSL_COMMIT" || { echo "== BoringSSL: could not clone"; continue; }
        echo "== BoringSSL $(git -C "$S" rev-parse --short=12 HEAD), aarch64 with assembly, emulated"
        [ -n "$(find "$B" -name libcrypto.a 2>/dev/null | head -n1)" ] || { cmake -S "$S" -B "$B" $TC >"$S/_cmake-arm64.log" 2>&1 \
            && cmake --build "$B" -j"$(nproc)" --target crypto >"$S/_make-arm64.log" 2>&1; } || { echo "does not build: $(grep -m2 -i error "$S/_cmake-arm64.log" "$S/_make-arm64.log" | cut -c1-200)"; continue; }
        L="$(find "$B" -name libcrypto.a | head -n1)"
        $CXX -O2 -static -w -std=c++17 -I"$S/include" -I"$HERE" "$HERE/mlkem_boringssl.cc" "$L" -lpthread -o "$B/_mk" 2>"$B/_mk.log" && kem "$B/_mk" || grep -m3 -E 'error|undefined' "$B/_mk.log"
        $CXX -O2 -static -w -std=c++17 -I"$S/include" -I"$HERE" "$HERE/mldsa_boringssl.cc" "$L" -lpthread -o "$B/_md" 2>"$B/_md.log" && dsa "$B/_md" || grep -m3 -E 'error|undefined' "$B/_md.log" ;;
    *) echo "unknown: $WHICH" ;;
    esac
    done
}

[ $# -eq 0 ] && set -- arm cross rust-arm big-arm
for X in "$@"; do
    echo
    case "$X" in
        arm)      echo "########## arm"; arm ;;
        cross)    echo "########## cross"; cross ;;
        rust-arm) echo "########## rust-arm"; ( rust_arm ) ;;
        big-arm)  echo "########## big-arm"; big_arm ;;
        *)        echo "unknown: $X" ;;
    esac
done
