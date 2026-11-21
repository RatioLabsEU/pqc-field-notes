#!/usr/bin/env bash
# SLH-DSA (FIPS 205) interoperability of libbitcoinpqc, btx and PQMagic with OpenSSL, on Linux x86_64.
#
# Fetches the libraries at the commits we tested, OpenSSL at commit 354f1cf64842 of its development branch, the NIST
# ACVP SLH-DSA vectors, and the FIPS 205 branch of sphincsplus (only to print its version of the FORS line), builds
# everything under $WORK/slhdsa-interop and runs the tests named on the command line:
#   openssl     check of the vectors and the harness: OpenSSL with ACVP keyGen and sigVer, 12 parameter sets
#   bitcoinpqc  interop_bitcoinpqc + acvp_bitcoinpqc (direct and emulated), and the same with the CONTROL build
#   btx         interop_btx in the legacy and fips205 modes; acvp_btx in the legacy and fips205-core modes
#   pqmagic     acvp_pqmagic (direct and emulated) and interop_pqmagic, 12 parameter sets
# The full output of each test program goes to $WORK/slhdsa-interop/outputs; this script prints the summary lines and
# the discrepancies grouped by reason.
#
# Needs: git, cmake (with ctest), make, gcc, perl, python3 and network access. Nothing is installed system-wide.
# Usage:  ./run.sh [openssl] [bitcoinpqc] [btx] [pqmagic]     (default: all four; set WORK=/some/dir to choose the
#         working directory). The fetch and build steps always run; what is already built is reused.
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
W="$WORK/slhdsa-interop"; S=$W/src; B=$W/build; X=$W/bin; T=$W/txt; O=$W/outputs; OS=$W/libs/openssl; OSRC=$W/libs/openssl-src
OPENSSL_COMMIT=354f1cf64842dc03f30a97a3a4fd8a7b48e40807
ACVP_COMMIT=975de31eb83d87039ec88934fdc47d8c312b892d
SPX_COMMIT=ef36d20ff3588324ad69f844507b8217f008f35a
BITCOINPQC_COMMIT=fc08c05214d878cd899ce2cfcae43ee71f50981a
PQMAGIC_COMMIT=42f5b6e6fe7e4951ffc9437ecd77c9a5af93ff08
BTX_COMMIT=074dac167c26c1e091198f691ed5727817dba88a
J=$(nproc)
mkdir -p "$S" "$W/libs" "$B" "$X" "$T" "$O"

fetch_commit() { # url dir commit: one commit, shallow
    [ -d "$2/.git" ] && return 0
    mkdir -p "$2" && git -C "$2" init -q && git -C "$2" remote add origin "$1" && git -C "$2" fetch -q --depth 1 origin "$3" \
        && git -C "$2" -c advice.detachedHead=false checkout -q FETCH_HEAD
}
clone_at() { # url dir commit: full clone (so that the tags, if any, are listed), then that commit
    [ -d "$2/.git" ] || git clone -q "$1" "$2" || return 1
    git -C "$2" -c advice.detachedHead=false checkout -q "$3"
}

############################################################ fetch
echo "== sources ($(date -u '+%d-%m-%Y %H:%M') UTC)"
clone_at https://github.com/cryptoquick/libbitcoinpqc.git "$S/libbitcoinpqc" "$BITCOINPQC_COMMIT" || exit 2
echo "   libbitcoinpqc $(git -C "$S/libbitcoinpqc" log -1 --format='%H %cs') tags: $(git -C "$S/libbitcoinpqc" tag | tr '\n' ' ')"
clone_at https://github.com/pqcrypto-cn/PQMagic.git "$S/PQMagic" "$PQMAGIC_COMMIT" || exit 2
echo "   PQMagic $(git -C "$S/PQMagic" log -1 --format='%H %cs') tags: $(git -C "$S/PQMagic" tag | tail -5 | tr '\n' ' ')"
fetch_commit https://github.com/btxchain/btx.git "$S/btx" "$BTX_COMMIT" || exit 2
echo "   btx $(git -C "$S/btx" log -1 --format='%H %cs')"
[ -d "$S/sphincsplus-fips205/.git" ] || git clone -q -b bas/fips205 https://github.com/sphincs/sphincsplus.git "$S/sphincsplus-fips205" || exit 2
git -C "$S/sphincsplus-fips205" -c advice.detachedHead=false checkout -q "$SPX_COMMIT"
echo "   sphincsplus bas/fips205 $(git -C "$S/sphincsplus-fips205" log -1 --format='%H %cs')"

echo "== ACVP"
if [ ! -d "$W/acvp/.git" ]; then
    git clone -q --filter=blob:none --no-checkout https://github.com/usnistgov/ACVP-Server.git "$W/acvp" \
    && git -C "$W/acvp" sparse-checkout init --cone \
    && git -C "$W/acvp" sparse-checkout set gen-val/json-files/SLH-DSA-keyGen-FIPS205 \
       gen-val/json-files/SLH-DSA-sigGen-FIPS205 gen-val/json-files/SLH-DSA-sigVer-FIPS205 \
    && git -C "$W/acvp" -c advice.detachedHead=false checkout -q "$ACVP_COMMIT" || exit 2
fi
echo "   $(git -C "$W/acvp" log -1 --format='%H %cs') (pinned $ACVP_COMMIT); latest on origin/master: $(git -C "$W/acvp" log -1 --format='%H %cs' origin/master 2>/dev/null)"

echo "== OpenSSL $OPENSSL_COMMIT (our own build)"
if [ ! -f "$OS/libcrypto.a" ]; then
    fetch_commit https://github.com/openssl/openssl.git "$OSRC" "$OPENSSL_COMMIT" || exit 2
    ( cd "$OSRC" && ./Configure no-shared no-tests no-docs >_configure.log 2>&1 && make -j"$J" build_generated libcrypto.a >_make.log 2>&1 ) \
        && mkdir -p "$OS" && cp "$OSRC/libcrypto.a" "$OS/" && cp -r "$OSRC/include" "$OS/" \
        && echo "   built in $OSRC" || { echo "   DOES NOT BUILD: $(tail -3 "$OSRC/_make.log")"; exit 2; }
fi
echo "   $(git -C "$OSRC" log -1 --format='%H %cs')"
sha256sum "$OS/libcrypto.a" | cut -c1-16 | sed 's/^/   sha256 libcrypto.a: /'
echo "== end of fetch step: $(date -u '+%d-%m-%Y %H:%M') UTC"

############################################################ build
#   libbitcoinpqc  CMake Release, static library "bitcoinpqc" (it fetches libsecp256k1 v0.7.1 with FetchContent, as
#                  its CMakeLists.txt says). Its own tests are run too (ctest).
#   CONTROL        a copy of libbitcoinpqc with ONE line changed in sphincsplus/ref/fors.c (the bit order of the FORS
#                  indices of FIPS 205, as in sphincsplus bas/fips205). It is not the published library: it shows that
#                  the test program is not what fails, and attributes the difference to that line.
#   PQMagic        CMake Release, SLH-DSA only, "simple" thash, the 12 parameter sets of FIPS 205 (no SM3), no tests or
#                  benchmarks.
#   btx            src/libbitcoinpqc of btx, CMake Release ("ref" variant on x86_64).
# Programs: interop_<lib> (interop_slhdsa.c) and acvp_<lib> (acvp_lib.c + slhdsa_harness.h), and acvp_openssl
# (slhdsa_openssl.c) as the check of the vectors.
echo; echo "### build step"
fail() { echo "   DOES NOT BUILD ($1):"; grep -m6 -E 'error|undefined|Error' "$2" | cut -c1-220 | sed 's/^/     /'; }

echo "== libbitcoinpqc $(git -C "$S/libbitcoinpqc" log -1 --format='%H %cs')"
if [ ! -f "$B/libbitcoinpqc/lib/libbitcoinpqc.a" ]; then
    { cmake -S "$S/libbitcoinpqc" -B "$B/libbitcoinpqc" -DCMAKE_BUILD_TYPE=Release >"$B/libbitcoinpqc.cmake.log" 2>&1 \
      && cmake --build "$B/libbitcoinpqc" -j"$J" >"$B/libbitcoinpqc.make.log" 2>&1; } || fail cmake "$B/libbitcoinpqc.make.log"
fi
SECP=$(find "$B/libbitcoinpqc" -name 'libsecp256k1.a' | head -1)
echo "   $(ls "$B/libbitcoinpqc/lib/libbitcoinpqc.a" 2>/dev/null); secp256k1: $SECP"
echo "   its own tests (ctest):"
( cd "$B/libbitcoinpqc" && ctest --output-on-failure 2>&1 | tail -8 | sed 's/^/     /' )

echo "== CONTROL: libbitcoinpqc with fors.c patched to the FIPS 205 order"
C=$S/libbitcoinpqc-control
if [ ! -d "$C" ]; then
    cp -r "$S/libbitcoinpqc" "$C"
    # In the pattern, "." stands for "&"; in the replacement, "\&" is a literal "&".
    sed -i 's|indices\[i\] ^= ((m\[offset >> 3\] >> (offset . 0x7)) . 1u) << j;|indices[i] ^= ((m[offset >> 3] >> (~offset \& 0x7)) \& 1u) << (SPX_FORS_HEIGHT-1-j);|' "$C/sphincsplus/ref/fors.c"
fi
echo "   difference from the original:"
diff "$S/libbitcoinpqc/sphincsplus/ref/fors.c" "$C/sphincsplus/ref/fors.c" | sed 's/^/     /'
echo "   line in sphincsplus bas/fips205 (reference): $(grep -n 'indices\[i\] ^=' "$S/sphincsplus-fips205/ref/fors.c" | sed 's/^ *//')"
if [ ! -f "$B/control/lib/libbitcoinpqc.a" ]; then
    SECPSRC=$(find "$B/libbitcoinpqc/_deps" -maxdepth 1 -name 'secp256k1-src' | head -1)
    { cmake -S "$C" -B "$B/control" -DCMAKE_BUILD_TYPE=Release -DFETCHCONTENT_SOURCE_DIR_SECP256K1="$SECPSRC" >"$B/control.cmake.log" 2>&1 \
      && cmake --build "$B/control" -j"$J" --target bitcoinpqc >"$B/control.make.log" 2>&1; } || fail cmake "$B/control.make.log"
fi
SECPC=$(find "$B/control" -name 'libsecp256k1.a' | head -1)

echo "== PQMagic $(git -C "$S/PQMagic" log -1 --format='%H %cs')"
MODES="slh-dsa-sha2-128f;slh-dsa-sha2-128s;slh-dsa-sha2-192f;slh-dsa-sha2-192s;slh-dsa-sha2-256f;slh-dsa-sha2-256s;slh-dsa-shake-128f;slh-dsa-shake-128s;slh-dsa-shake-192f;slh-dsa-shake-192s;slh-dsa-shake-256f;slh-dsa-shake-256s"
if [ -z "$(find "$B/pqmagic" -name 'libpqmagic*.a' 2>/dev/null | head -1)" ]; then
    OFF=""; for o in KYBER ML_KEM AIGIS_ENC AIGIS_ENC_PLUS NEV QIMEN_PIKE NEV_AKE DILITHIUM ML_DSA AIGIS_SIG AIGIS_SIG_PLUS RESOLVED_ALPHA SPHINCS_A; do OFF="$OFF -DENABLE_$o=OFF"; done
    { cmake -S "$S/PQMagic" -B "$B/pqmagic" -DCMAKE_BUILD_TYPE=Release $OFF -DENABLE_SLH_DSA=ON -DSLH_DSA_MODES="$MODES" \
          -DSLH_DSA_THASH=simple -DENABLE_TEST=OFF -DENABLE_BENCH=OFF -DENABLE_KAT=OFF >"$B/pqmagic.cmake.log" 2>&1 \
      && cmake --build "$B/pqmagic" -j"$J" >"$B/pqmagic.make.log" 2>&1; } || fail cmake "$B/pqmagic.make.log"
fi
PQM=$(find "$B/pqmagic" -name 'libpqmagic*.a' | grep -v import | head -1)
echo "   $PQM"
grep -i 'SLH-DSA' "$B/pqmagic.cmake.log" | head -3 | sed 's/^/   /'

echo "== btx $(git -C "$S/btx" log -1 --format='%H %cs'), src/libbitcoinpqc"
if [ ! -f "$B/btx/lib/libbitcoinpqc.a" ]; then
    { cmake -S "$S/btx/src/libbitcoinpqc" -B "$B/btx" -DCMAKE_BUILD_TYPE=Release >"$B/btx.cmake.log" 2>&1 \
      && cmake --build "$B/btx" -j"$J" --target bitcoinpqc >"$B/btx.make.log" 2>&1; } || fail cmake "$B/btx.make.log"
fi
grep -m1 'SPHINCS+ variant' "$B/btx.cmake.log" | sed 's/^/   /'
echo "   $(ls "$B/btx/lib/libbitcoinpqc.a" 2>/dev/null)"

echo "== test programs"
OSL="$OS/libcrypto.a -ldl -lpthread"
cc_() { local name="$1"; shift; gcc -O2 -w "$@" -o "$X/$name" 2>"$X/$name.log" && echo "   $name" || fail "$name" "$X/$name.log"; }
cc_ interop_bitcoinpqc -include "$HERE/adapter_bitcoinpqc.h" -I"$S/libbitcoinpqc/include" -I"$OS/include" "$HERE/interop_slhdsa.c" "$B/libbitcoinpqc/lib/libbitcoinpqc.a" "$SECP" $OSL
cc_ acvp_bitcoinpqc -include "$HERE/adapter_bitcoinpqc.h" -I"$S/libbitcoinpqc/include" -I"$HERE" "$HERE/acvp_lib.c" "$B/libbitcoinpqc/lib/libbitcoinpqc.a" "$SECP" -lpthread
cc_ interop_control -DBPQC_LABEL='" [CONTROL: fors.c patched]"' -include "$HERE/adapter_bitcoinpqc.h" -I"$C/include" -I"$OS/include" "$HERE/interop_slhdsa.c" "$B/control/lib/libbitcoinpqc.a" "$SECPC" $OSL
cc_ acvp_control -DBPQC_LABEL='" [CONTROL: fors.c patched]"' -include "$HERE/adapter_bitcoinpqc.h" -I"$C/include" -I"$HERE" "$HERE/acvp_lib.c" "$B/control/lib/libbitcoinpqc.a" "$SECPC" -lpthread
cc_ interop_pqmagic -include "$HERE/adapter_pqmagic.h" -I"$S/PQMagic/include" -I"$OS/include" "$HERE/interop_slhdsa.c" "$PQM" $OSL
cc_ acvp_pqmagic -include "$HERE/adapter_pqmagic.h" -I"$S/PQMagic/include" -I"$HERE" "$HERE/acvp_lib.c" "$PQM" -lpthread
cc_ interop_btx -include "$HERE/adapter_btx.h" -I"$S/btx/src/libbitcoinpqc/include" -I"$OS/include" "$HERE/interop_slhdsa.c" "$B/btx/lib/libbitcoinpqc.a" $OSL
cc_ acvp_btx -include "$HERE/adapter_btx.h" -I"$S/btx/src/libbitcoinpqc/include" -I"$HERE" "$HERE/acvp_lib.c" "$B/btx/lib/libbitcoinpqc.a" -lpthread
cc_ acvp_openssl -I"$OS/include" -I"$HERE" "$HERE/slhdsa_openssl.c" $OSL

echo "== ACVP vectors ($(git -C "$W/acvp" log -1 --format='%H %cs'))"
python3 -I "$HERE/acvp_to_text.py" "$W/acvp/gen-val/json-files" "$T" | sed 's/^/   /'
echo "== end of build step: $(date -u '+%d-%m-%Y %H:%M') UTC"

############################################################ tests
SETS="SLH-DSA-SHA2-128s SLH-DSA-SHAKE-128s SLH-DSA-SHA2-128f SLH-DSA-SHAKE-128f SLH-DSA-SHA2-192s SLH-DSA-SHAKE-192s
SLH-DSA-SHA2-192f SLH-DSA-SHAKE-192f SLH-DSA-SHA2-256s SLH-DSA-SHAKE-256s SLH-DSA-SHA2-256f SLH-DSA-SHAKE-256f"

# summary <file>: the summary lines as they are; the discrepancies grouped by reason, with up to 12 tcIds.
summary() {
    grep -v '^  ' "$1"
    grep '^  [A-Za-z(]' "$1" | awk '{
        l=$0; id=""; if (match(l, /tcId=[^ ]*/)) { id=substr(l, RSTART+5, RLENGTH-5); sub(/tcId=[^ ]* */, "", l) }
        gsub(/ tg=[0-9]+/, "", l); n[l]++; if (n[l] <= 12) ids[l]=ids[l] " " id; else if (n[l] == 13) ids[l]=ids[l] " ..." }
        END { for (k in n) printf "%6d %s   [tcId:%s]\n", n[k], substr(k, 1, 200), ids[k] }' | sort -rn
}
# acvp <name> <program> <parameter sets> [mode]: keyGen and sigVer of each set; output in $O/<name>.out
acvp() {
    local N="$1" P="$2" PS="$3" M="${4:-}" PSET
    : >"$O/$N.out"
    for PSET in $PS; do "$P" "$T/$PSET.txt" kg,sv $M >>"$O/$N.out" 2>&1; done
    summary "$O/$N.out" | sed 's/^/   /'
}

echo
echo "# SLH-DSA interoperability. $(date -u '+%d-%m-%Y %H:%M') UTC, machine: $(uname -srm); $(gcc --version | head -1)"
echo "# CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'); $(nproc) cores"
echo "# OpenSSL $(git -C "$OSRC" rev-parse HEAD) (built here: no-shared no-tests no-docs)"
echo "# ACVP usnistgov/ACVP-Server $(git -C "$W/acvp" log -1 --format='%H %cs'), SLH-DSA-{keyGen,sigVer}-FIPS205/internalProjection.json"
echo "# libbitcoinpqc $(git -C "$S/libbitcoinpqc" log -1 --format='%H %cs'); PQMagic $(git -C "$S/PQMagic" log -1 --format='%H %cs'); btx $(git -C "$S/btx" log -1 --format='%H %cs')"
echo "# In ACVP: \"direct\" = internal sigVer with M' as given, and external pure only with an empty context; \"emulated\" = external pure"
echo "# with M' = 00 ‖ |ctx| ‖ ctx ‖ M built by the program. sigGen is not run (none lets the caller fix opt_rand)."
[ $# -eq 0 ] && set -- openssl bitcoinpqc btx pqmagic
for A in "$@"; do
    echo
    case "$A" in
    openssl)
        echo "########## Check of the vectors: OpenSSL with keyGen and sigVer in the 12 parameter sets"
        acvp openssl "$X/acvp_openssl" "$SETS" ;;
    bitcoinpqc)
        echo "########## libbitcoinpqc: interoperability with OpenSSL"
        "$X/interop_bitcoinpqc" 2>&1 | tee "$O/interop_bitcoinpqc.out" | sed 's/^/   /'
        echo "########## libbitcoinpqc: ACVP SLH-DSA-SHA2-128s"
        acvp acvp_bitcoinpqc_direct "$X/acvp_bitcoinpqc" SLH-DSA-SHA2-128s direct
        acvp acvp_bitcoinpqc_emulated "$X/acvp_bitcoinpqc" SLH-DSA-SHA2-128s emulated
        echo "########## CONTROL (not the published library): libbitcoinpqc with line 59 of fors.c in the FIPS 205 order"
        "$X/interop_control" 2>&1 | tee "$O/interop_control.out" | sed 's/^/   /'
        acvp acvp_control_direct "$X/acvp_control" SLH-DSA-SHA2-128s direct
        acvp acvp_control_emulated "$X/acvp_control" SLH-DSA-SHA2-128s emulated ;;
    btx)
        for MODE in legacy fips205; do
            echo "########## btx (src/libbitcoinpqc), mode $MODE: interoperability with OpenSSL"
            BTX_MODE=$MODE "$X/interop_btx" 2>&1 | tee "$O/interop_btx_$MODE.out" | sed 's/^/   /'
        done
        echo "########## btx: ACVP SLH-DSA-SHAKE-128s"
        BTX_MODE=legacy acvp acvp_btx_legacy_direct "$X/acvp_btx" SLH-DSA-SHAKE-128s direct
        BTX_MODE=legacy acvp acvp_btx_legacy_emulated "$X/acvp_btx" SLH-DSA-SHAKE-128s emulated
        BTX_MODE=fips205-core acvp acvp_btx_fips205_direct "$X/acvp_btx" SLH-DSA-SHAKE-128s direct
        BTX_MODE=fips205-core acvp acvp_btx_fips205_emulated "$X/acvp_btx" SLH-DSA-SHAKE-128s emulated ;;
    pqmagic)
        echo "########## PQMagic: ACVP (12 parameter sets)"
        acvp acvp_pqmagic_direct "$X/acvp_pqmagic" "$SETS" direct
        acvp acvp_pqmagic_emulated "$X/acvp_pqmagic" "$SETS" emulated
        echo "########## PQMagic: interoperability with OpenSSL (12 parameter sets)"
        "$X/interop_pqmagic" 2>&1 | tee "$O/interop_pqmagic.out" | sed 's/^/   /' ;;
    *) echo "unknown: $A" ;;
    esac
done
echo; echo "# end: $(date -u '+%d-%m-%Y %H:%M') UTC"
