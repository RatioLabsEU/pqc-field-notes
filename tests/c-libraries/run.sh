#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors against five C libraries with their own implementation, built from
# their published sources:
#
#   libsodium   1.0.22 release tarball (ML-KEM-768)
#   leancrypto  1.9.1 tag (ML-KEM and ML-DSA; default build with AVX2 and a C-only build)
#   linux       lib/crypto/mldsa.c of the Linux kernel (tags v7.3.5, v7.0, v7.4-rc3), built in user space with the
#               linux_compat/ layer (ML-DSA)
#   strongswan  6.1.0 release tarball, "ml" plugin (ML-KEM)
#   nettle      development branch at commit 10d33c60c1c7 (ML-KEM-768 and ML-KEM-1024)
#
# Needs: git, curl, gcc (with AddressSanitizer), make, autoconf, m4, libgmp-dev, pkg-config, python3 with venv.
# Everything is downloaded and built under $WORK. Nothing is installed system-wide.
#
# Usage:  ./run.sh [libsodium] [leancrypto] [linux] [strongswan] [nettle]      (no arguments: all five)
#         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
SODIUM_VERSION="${SODIUM_VERSION:-1.0.22}"
LEANCRYPTO_VERSION="${LEANCRYPTO_VERSION:-1.9.1}"
LINUX_TAGS="${LINUX_TAGS:-v7.3.5 v7.0 v7.4-rc3}"
STRONGSWAN_VERSION="${STRONGSWAN_VERSION:-6.1.0}"
NETTLE_COMMIT="${NETTLE_COMMIT:-10d33c60c1c797c5ac4adb36e22294a91174fcd9}"
W="$WORK/c-libraries"; V="$WORK/vectors"; F="$W/sources"
mkdir -p "$W" "$V" "$F"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done

# Summary: the total lines as they are, and the detail lines grouped by vector comment.
summary() { grep -v '^  \|^Error -[0-9]* at ' "$1"; grep '^  ' "$1" | sed 's/tcId=[0-9]*//' | sort | uniq -c | sort -rn | cut -c1-170; }

echo "Wycheproof $WYCHEPROOF_COMMIT"
echo "Machine: $(uname -srm); $(gcc --version | head -1)"
echo "Note: in ML-KEM, the \"seed\" lines whose seed is not 64 bytes long (20 per parameter set) are rejected by the"
echo "harness itself without calling the library."

# ---------------------------------------------------------------------------------------------------------------------
libsodium() {
    local S="$W/libsodium-$SODIUM_VERSION" I="$W/inst-sodium-$SODIUM_VERSION"
    # 1. Source: official tarball from download.libsodium.org (its minisign signature is saved next to it).
    if [ ! -f "$F/libsodium-$SODIUM_VERSION.tar.gz" ]; then
        curl -sSfL -o "$F/libsodium-$SODIUM_VERSION.tar.gz" "https://download.libsodium.org/libsodium/releases/libsodium-$SODIUM_VERSION.tar.gz"
        curl -sSfL -o "$F/libsodium-$SODIUM_VERSION.tar.gz.minisig" "https://download.libsodium.org/libsodium/releases/libsodium-$SODIUM_VERSION.tar.gz.minisig"
    fi
    echo "== libsodium $SODIUM_VERSION  (sha256 $(sha256sum "$F/libsodium-$SODIUM_VERSION.tar.gz" | cut -c1-64))"
    # 2. Static build, touching nothing outside $W.
    if [ ! -f "$I/lib/libsodium.a" ]; then
        rm -rf "$S"; tar xzf "$F/libsodium-$SODIUM_VERSION.tar.gz" -C "$W"
        ( cd "$S" && ./configure --prefix="$I" --disable-shared --enable-static >"$W/_sodium_conf.log" 2>&1 \
          && make -j"$(nproc)" >"$W/_sodium_make.log" 2>&1 && make install >>"$W/_sodium_make.log" 2>&1 ) \
          || { echo "   does not build (see $W/_sodium_*.log)"; return 1; }
    fi
    # 3. Test program and run (libsodium only has ML-KEM-768).
    gcc -O2 -Wall -I"$I/include" -I"$HERE" "$HERE/mlkem_libsodium.c" "$I/lib/libsodium.a" -o "$W/_mk_sodium" || return 1
    "$W/_mk_sodium" "$V/mlkem_768.txt" 768 >"$W/_mk_sodium.out" 2>&1
    summary "$W/_mk_sodium.out"
}

# ---------------------------------------------------------------------------------------------------------------------
# Two static builds with meson: "def" (default accelerations: AVX2 on x86_64, chosen at run time) and "c"
# (-Ddisable-asm=true: C only). Meson and ninja go in a virtual environment inside $W.
# The project's default configuration (optimization=3, debug=true) makes the library write
# "Error -22 at file:function:line" to stdout on every rejection: the summary removes those lines and at the end
# counts them by source file, which also shows which code ran (C or AVX2).
leancrypto() {
    local VER="$LEANCRYPTO_VERSION" S="$W/leancrypto-$LEANCRYPTO_VERSION" B D I L OPT M P
    [ -x "$W/venv/bin/meson" ] || { python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q --disable-pip-version-check install meson ninja; }
    export PATH="$W/venv/bin:$PATH"
    [ -f "$F/leancrypto-$VER.tar.gz" ] || curl -sSfL -o "$F/leancrypto-$VER.tar.gz" "https://github.com/smuellerDD/leancrypto/archive/refs/tags/v$VER.tar.gz"
    echo "== leancrypto $VER  (tag v$VER; sha256 of the tarball $(sha256sum "$F/leancrypto-$VER.tar.gz" | cut -c1-64))"
    [ -d "$S" ] || tar xzf "$F/leancrypto-$VER.tar.gz" -C "$W"
    for B in def c; do
        OPT="-Ddefault_library=static -Dapps=disabled"; [ "$B" = c ] && OPT="$OPT -Ddisable-asm=true"
        D="$W/lc-$B"; I="$W/inst-lc-$B"
        if [ -z "$(find "$I" -name libleancrypto.a 2>/dev/null | head -1)" ]; then
            ( cd "$S" && meson setup "$D" --prefix="$I" $OPT >"$W/_lc_${B}_setup.log" 2>&1 \
              && ninja -C "$D" libleancrypto.a libleancrypto-raw.a libleancrypto-fips.a >"$W/_lc_${B}_build.log" 2>&1 \
              && meson install -C "$D" --no-rebuild --tags devel >"$W/_lc_${B}_inst.log" 2>&1 ) \
              || { echo "   build $B: fails (see $W/_lc_${B}_*.log)"; continue; }
        fi
        L="$(find "$I" -name libleancrypto.a | head -1)"
        echo "#### build \"$B\" (options: $OPT)"
        gcc -O2 -Wall -I"$I/include" -I"$HERE" "$HERE/mlkem_leancrypto.c" "$L" -lpthread -o "$W/_mk_lc_$B" || continue
        gcc -O2 -Wall -I"$I/include" -I"$HERE" "$HERE/mldsa_leancrypto.c" "$L" -lpthread -o "$W/_md_lc_$B" || continue
        export LC_NAME="leancrypto $VER $B"
        for P in 512 768 1024; do "$W/_mk_lc_$B" "$V/mlkem_$P.txt" "$P"; done >"$W/_mk_lc_$B.out" 2>"$W/_mk_lc_$B.err"
        summary "$W/_mk_lc_$B.out"
        for P in 512 768 1024; do RANDOM_RNG=1 "$W/_mk_lc_$B" "$V/mlkem_$P.txt" "$P"; done >"$W/_mk_lc_${B}_rnd.out" 2>"$W/_mk_lc_${B}_rnd.err"
        echo "   (repeated with lc_kyber_enc and the internal generator, accept/reject only:)"; summary "$W/_mk_lc_${B}_rnd.out"
        for M in ctx simple stream; do
            for P in 44 65 87; do MODE=$M "$W/_md_lc_$B" "$V/mldsa_$P.txt" "$P"; done >"$W/_md_lc_${B}_$M.out" 2>"$W/_md_lc_${B}_$M.err"
            summary "$W/_md_lc_${B}_$M.out"
        done
        echo "   rejection traces from the library by source file (shows which implementation ran):"
        cat "$W"/_m?_lc_"$B"*.out "$W"/_m?_lc_"$B"*.err | grep -o '^Error -[0-9]* at [^:]*' | sed 's#\.\./leancrypto-[0-9.]*/##' | sort | uniq -c | sed 's/^/     /'
    done
}

# ---------------------------------------------------------------------------------------------------------------------
# lib/crypto/mldsa.c of the Linux kernel, built in user space. Only the files needed are downloaded from a published
# tag (git.kernel.org, stable repository, which also carries Linus's tags):
#   lib/crypto/mldsa.c, lib/crypto/fips-mldsa.h, include/crypto/mldsa.h       (ML-DSA, unmodified)
#   lib/crypto/sha3.c, lib/crypto/fips-sha.h, include/crypto/sha3.h            (the kernel's generic SHA-3/SHAKE, unmodified)
# and they are built with the linux_compat/ layer (stand-in headers, see their comments) instead of the rest of the
# kernel.
linux() {
    local C="$HERE/linux_compat" U="https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/plain"
    local FILES="lib/crypto/mldsa.c include/crypto/mldsa.h lib/crypto/sha3.c include/crypto/sha3.h"
    # FIPS self-test data included by mldsa.c and sha3.c (not used without CONFIG_CRYPTO_FIPS); the name changes with
    # the version (v7.0: lib/crypto/fips.h; v7.3: fips-sha.h), so whichever exists is downloaded.
    local OPTIONAL="lib/crypto/fips-mldsa.h lib/crypto/fips-sha.h lib/crypto/fips.h"
    # Options close to the kernel's (Makefile: -std=gnu11 -fno-strict-aliasing -fno-strict-overflow ...).
    local BASE="-std=gnu11 -fno-strict-aliasing -fno-strict-overflow -fno-delete-null-pointer-checks -Wall -Wno-sign-compare"
    local VER K f MODE CF INC O P
    for VER in $LINUX_TAGS; do
        K="$W/linux-$VER"; mkdir -p "$K/lib/crypto" "$K/include/crypto"
        for f in $FILES; do [ -s "$K/$f" ] || curl -sSf -o "$K/$f" "$U/$f?h=$VER" || { echo "== $VER: could not download $f"; continue 2; }; done
        for f in $OPTIONAL; do [ -s "$K/$f" ] || curl -sSf -o "$K/$f" "$U/$f?h=$VER" 2>/dev/null || rm -f "$K/$f"; done
        echo "== Linux kernel $VER (git.kernel.org stable, tag $VER)"
        ( cd "$K" && for f in $FILES $OPTIONAL; do [ -f "$f" ] && sha256sum "$f"; done | sed 's/^/   /' )
        for MODE in O2 asan; do
            CF="$BASE -O2"; [ "$MODE" = asan ] && CF="$BASE -O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all"
            INC="-include $C/compat_common.h -I$C -I$K/include"
            O="$W/_lx_${VER}_$MODE"; mkdir -p "$O"
            gcc $CF $INC -DKBUILD_MODNAME='"mldsa"' -c "$K/lib/crypto/mldsa.c" -o "$O/mldsa.o" 2>"$O/cc.log" \
              && gcc $CF $INC -DKBUILD_MODNAME='"sha3"' -c "$K/lib/crypto/sha3.c" -o "$O/sha3.o" 2>>"$O/cc.log" \
              && gcc $CF $INC -I"$HERE" "$HERE/mldsa_linux.c" "$O/mldsa.o" "$O/sha3.o" -o "$O/md" 2>>"$O/cc.log" \
              && gcc $CF $INC "$HERE/shake_linux.c" "$O/sha3.o" -o "$O/shake" 2>>"$O/cc.log" \
              || { echo "   ($MODE) does not build:"; grep -m8 -E 'error|warning' "$O/cc.log"; continue; }
            [ -s "$O/cc.log" ] && { echo "   ($MODE) compiler warnings:"; grep -E 'warning' "$O/cc.log" | sed 's/^/     /' | head -5; }
            # Control 1: the extracted SHA-3 agrees with hashlib.
            "$O/shake" | python3 -I -c '
import sys, hashlib
msg = bytes((i * 7 + 3) & 0xff for i in range(700)); n = bad = 0
for l in sys.stdin:
    a, lm, ls, h = l.strip().split("|"); m = msg[:int(lm)]; ls = int(ls)
    e = hashlib.shake_128(m).hexdigest(ls) if a == "shake128" else hashlib.shake_256(m).hexdigest(ls) if a == "shake256" else hashlib.sha3_256(m).hexdigest()
    n += 1; bad += e != h
print(f"   ({sys.argv[1]}) check of the kernel SHA-3/SHAKE against hashlib: {n} comparisons, {bad} different")' "$MODE"
            # Vectors (only those with an empty context; the rest show up as "not applicable").
            export LX_NAME="linux $VER mldsa.c ($MODE)"
            for P in 44 65 87; do "$O/md" "$V/mldsa_$P.txt" "$P"; done >"$O/md.out" 2>"$O/md.err"
            summary "$O/md.out"
            [ -s "$O/md.err" ] && { echo "   stderr (sanitizers / WARN_ON_ONCE):"; head -5 "$O/md.err"; }
        done
    done
    # Differences in the ML-DSA code between the tested versions.
    set -- $LINUX_TAGS
    if [ $# -gt 1 ]; then
        for VER in "${@:2}"; do
            printf '   diff mldsa.c %s -> %s: ' "$1" "$VER"
            diff -q "$W/linux-$1/lib/crypto/mldsa.c" "$W/linux-$VER/lib/crypto/mldsa.c" >/dev/null && echo "identical" || diff -u "$W/linux-$1/lib/crypto/mldsa.c" "$W/linux-$VER/lib/crypto/mldsa.c" | grep -c '^[-+][^-+]' | sed 's/$/ lines changed/'
        done
    fi
}

# ---------------------------------------------------------------------------------------------------------------------
# strongSwan from the official tarball (download.strongswan.org, with its .sig saved next to it). Only libstrongswan is
# built, with the random, sha3 and ml plugins (--disable-defaults) and without TESTABLE_KE, i.e. the production
# interface.
strongswan() {
    local VER="$STRONGSWAN_VERSION" S="$W/strongswan-$STRONGSWAN_VERSION" I="$W/inst-swan-$STRONGSWAN_VERSION" P
    if [ ! -f "$F/strongswan-$VER.tar.bz2" ]; then
        curl -sSfL -o "$F/strongswan-$VER.tar.bz2" "https://download.strongswan.org/strongswan-$VER.tar.bz2"
        curl -sSfL -o "$F/strongswan-$VER.tar.bz2.sig" "https://download.strongswan.org/strongswan-$VER.tar.bz2.sig"
    fi
    echo "== strongSwan $VER  (sha256 $(sha256sum "$F/strongswan-$VER.tar.bz2" | cut -c1-64))"
    if [ ! -f "$I/lib/ipsec/plugins/libstrongswan-ml.so" ]; then
        rm -rf "$S"; tar xjf "$F/strongswan-$VER.tar.bz2" -C "$W"
        # With --disable-defaults the top-level make does not enter src/libstrongswan: that directory is built and
        # installed directly.
        ( cd "$S" && ./configure --prefix="$I" --disable-defaults --enable-ml --enable-sha3 --enable-random \
              --with-dev-headers="$I/include/strongswan" >"$W/_swan_conf.log" 2>&1 \
          && make -C src/libstrongswan -j"$(nproc)" >"$W/_swan_make.log" 2>&1 && make -C src/libstrongswan install >"$W/_swan_inst.log" 2>&1 ) \
          || { echo "   does not build (see $W/_swan_*.log)"; return 1; }
    fi
    # The development headers require the build's config.h to be included first (library.h: "pass -include
    # config.h"); installing only src/libstrongswan does not copy it, so the one generated by configure is used.
    gcc -O2 -Wall -include "$S/config.h" -I"$I/include/strongswan" -I"$HERE" "$HERE/mlkem_strongswan.c" -L"$I/lib/ipsec" -lstrongswan \
        -Wl,-rpath,"$I/lib/ipsec" -o "$W/_mk_swan" || return 1
    export SW_NAME="strongswan $VER ml"
    printf 'wycheproof {\n}\n' >"$W/wycheproof-strongswan.conf"; export SW_CONF="$W/wycheproof-strongswan.conf"
    for P in 512 768 1024; do "$W/_mk_swan" "$V/mlkem_$P.txt" "$P"; done >"$W/_mk_swan.out" 2>"$W/_mk_swan.err"
    summary "$W/_mk_swan.out"
    echo "   library messages (stderr), grouped:"
    sed 's/[0-9]\+ bytes/N bytes/g' "$W/_mk_swan.err" | sort | uniq -c | sed 's/^/     /' | head -10
}

# ---------------------------------------------------------------------------------------------------------------------
# Nettle, development branch (ML-KEM is not yet in a release: NEWS puts it under "NEWS for the Nettle 4.1 release").
# Default build: x86_64 "fat".
nettle() {
    local S="$W/nettle" I="$W/inst-nettle" L P
    fetch https://git.lysator.liu.se/nettle/nettle.git "$S" "$NETTLE_COMMIT" || { echo "== nettle: could not clone"; return 1; }
    echo "== nettle, master branch, commit $(git -C "$S" log -1 --format='%H (%cd)')"
    if [ ! -f "$I/lib/libnettle.a" ] && [ ! -f "$I/lib64/libnettle.a" ]; then
        ( cd "$S" && ./.bootstrap >"$W/_nettle_boot.log" 2>&1 \
          && ./configure --prefix="$I" --disable-documentation --disable-shared >"$W/_nettle_conf.log" 2>&1 \
          && make -j"$(nproc)" >"$W/_nettle_make.log" 2>&1 && make install >"$W/_nettle_inst.log" 2>&1 ) \
          || { echo "   does not build (see $W/_nettle_*.log)"; return 1; }
    fi
    grep -E 'Assembly files' "$W/_nettle_conf.log" | sed 's/^ */   /'
    L="$I/lib/libnettle.a"; [ -f "$L" ] || L="$I/lib64/libnettle.a"
    gcc -O2 -Wall -I"$I/include" -I"$HERE" "$HERE/mlkem_nettle.c" "$L" -o "$W/_mk_nettle" || return 1
    export NT_NAME="nettle master $(git -C "$S" log -1 --format=%h)"
    for P in 512 768 1024; do "$W/_mk_nettle" "$V/mlkem_$P.txt" "$P"; done >"$W/_mk_nettle.out" 2>&1
    summary "$W/_mk_nettle.out"
}

[ $# -eq 0 ] && set -- libsodium leancrypto linux strongswan nettle
for X in "$@"; do
    echo
    case "$X" in
        libsodium)  echo "########## libsodium"; libsodium ;;
        leancrypto) echo "########## leancrypto"; ( leancrypto ) ;;
        linux)      echo "########## Linux kernel, lib/crypto/mldsa.c"; ( linux ) ;;
        strongswan) echo "########## strongSwan, ml plugin"; ( strongswan ) ;;
        nettle)     echo "########## Nettle, development branch"; nettle ;;
        *)          echo "unknown: $X" ;;
    esac
done
