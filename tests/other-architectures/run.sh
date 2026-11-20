#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors on other processor architectures, with cross compilation and user-mode
# emulation (qemu-user):
#
#   gmsm        Go module github.com/emmansun/gmsm v0.45.4 on arm64, riscv64, ppc64le and loong64 (and s390x as a
#               big-endian control), with its assembly and with -tags purego
#   leancrypto  leancrypto 1.9.1 (C, meson) on aarch64 and riscv64, default build and C-only build
#   zig         the Zig standard library (0.17.1) on aarch64, riscv64 and s390x (big-endian)
#
# The test programs are the same ones used on x86_64 (go/, mlkem_leancrypto.c, mldsa_leancrypto.c, wycheproof.zig),
# unmodified; only the build changes. Each run goes through "qemu -d in_asm", which logs the name of every block of code
# it translates; that log is used to show which architecture-specific code actually ran.
#
# Needs: git, curl, python3 with venv, perl, Go 1.27 or later (gmsm's riscv64 ML-KEM assembly needs go1.27), qemu-user
# (qemu-aarch64, qemu-riscv64, qemu-ppc64le, qemu-loongarch64, qemu-s390x), the cross compilers gcc-aarch64-linux-gnu and
# gcc-riscv64-linux-gnu with their libc6-dev-*-cross, and binutils-aarch64-linux-gnu, binutils-riscv64-linux-gnu and
# binutils-s390x-linux-gnu (objdump). Everything is downloaded and built under $WORK. Nothing is installed system-wide.
#
# Usage:  ./run.sh [gmsm] [leancrypto] [zig]      (no arguments: all three)
#         ARCHS="arm64 s390x" limits the gmsm architectures; ZIG_VERSION (default 0.17.1); LEANCRYPTO_VERSION (1.9.1)
#         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
W="$WORK/other-architectures"; V="$WORK/vectors"; SRC="$W/src"
mkdir -p "$V" "$W/downloads"
rm -rf "$SRC"; mkdir -p "$SRC"; cp -r "$HERE/go" "$SRC/"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done

echo "# Wycheproof $WYCHEPROOF_COMMIT"
echo "# Machine: $(uname -srm); $(nproc) cores; $(qemu-aarch64 --version | head -1)"
echo "# sha256 of the test programs:"
( cd "$HERE" && sha256sum go/common/common.go go/gmsm/*.go mlkem_harness.h mldsa_harness.h mlkem_leancrypto.c mldsa_leancrypto.c wycheproof.zig | sed 's/^/#   /' )

# =====================================================================================================================
# gmsm v0.45.4 (Go), mlkem and mldsa packages. GOOS=linux GOARCH=<arch> CGO_ENABLED=0, without tags (gmsm assembly)
# and with -tags purego (generic Go only).
#
# How gmsm v0.45.4 chooses its assembly (read in the module's code):
#   arm64   mlkem/field_arm64.go and mldsa/field_arm64.go ("//go:build arm64 && !purego"): always NEON, no detection.
#   riscv64 mlkem/field_riscv64.go ("//go:build go1.27 && !purego") and mldsa/field_riscv64.go ("!purego"): at run
#           time, hasRVV = cpu.RISCV64.HasV, which comes from the riscv_hwprobe call
#           (internal/deps/cpu/cpu_linux_riscv64.go); internal/keccakx4 also uses Zvbb (permute4RVV128/256) if hwprobe
#           reports it. It does not depend on GORISCV64.
#   ppc64le mlkem only (mlkem/field_ppc64le.go, "ppc64le && !purego"), no detection; mldsa has no ppc64le assembly.
#   loong64 mlkem, mldsa and internal/keccakx4: at run time, useLASX = cpu.Loong64.HasLASX (bit 5 of AT_HWCAP).
#
# Check that the assembly really runs: each run is launched with "qemu -d in_asm", which logs every block of code it
# translates with the symbol name ("IN: github.com/emmansun/gmsm/mlkem.internalNTTNEON.abi0"). Those names are matched
# against the TEXT functions of gmsm's .s files for that architecture (mlkem, mldsa, internal/keccakx4).
# =====================================================================================================================
gmsm() {
    local S="$W/out/gmsm" B="$W/bin" G A
    mkdir -p "$S" "$B"
    export PATH="/usr/local/go/bin:$PATH" GOPATH="$W/gopath" GOCACHE="$W/gocache" GOMODCACHE="$W/gomodcache"
    export GOFLAGS=-modcacherw GOTOOLCHAIN=local GOOS=linux CGO_ENABLED=0
    G="$GOMODCACHE/github.com/emmansun/gmsm@v0.45.4"

    # Summary (as in the x86_64 tests): totals as they are and details grouped by vector comment.
    summary() { grep -v '^  ' "$1" | head -${2:-40}; grep '^  ' "$1" | sed 's/tcId=[0-9]*//' | sort | uniq -c | sort -rn | cut -c1-200; }
    # Functions written in assembly by gmsm for architecture $1 (names of the TEXT symbols in its .s files).
    asm_functions() {
        ls "$G"/mlkem/*"$1"*.s "$G"/mldsa/*"$1"*.s "$G"/internal/keccakx4/*"$1"*.s 2>/dev/null \
            | xargs -r grep -ho '^TEXT ·[A-Za-z0-9_]*' | sed 's/^TEXT ·//' | sort -u
    }
    # gmsm symbols (mlkem, mldsa, keccakx4) that qemu translated, i.e. that ran at least once.
    executed() { grep -o '^IN: github.com/emmansun/gmsm/\(mlkem\|mldsa\|internal/keccakx4\)\.[A-Za-z0-9_]*' "$1" | sed 's/.*\.//' | sort -u; }

    build() {  # build <arch> <binary> [go build options]
        local A="$1" N="$2"; shift 2
        ( cd "$SRC/go" && GOARCH="$A" go build "$@" -o "$B/$N" ./gmsm ) >"$S/build-$N.log" 2>&1 \
            || { echo "## DOES NOT BUILD $N (GOARCH=$A $*)"; head -20 "$S/build-$N.log"; return 1; }
    }

    run_one() {  # run_one <arch> <label> <binary> <qemu command...>
        local A="$1" E="$2" N="$3"; shift 3
        local T="$S/trace-$A-$E.log" OUT="$S/$A-$E.out" rc PC total det
        echo "## $A · $E · binary $N · $*"
        "$@" -d in_asm -D "$T" "$B/$N" "$V" >"$OUT" 2>&1; rc=$?
        if [ $rc -eq 0 ]; then
            summary "$OUT" 12
        else
            echo "   EXITS WITH CODE $rc:"; grep -v '^\s' "$OUT" | head -6 | sed 's/^/   | /'
            PC=$(grep -o '^PC=0x[0-9a-f]*' "$OUT" | head -1 | cut -c4-)
            [ -n "$PC" ] && echo "   instruction at $PC: $(go tool objdump "$B/$N" 2>/dev/null | grep -m1 -i "0x${PC#0x}[^0-9a-f]" | sed "s|$G/||" | tr -s ' \t' ' ')"
            grep '^  ' "$OUT" | sed 's/tcId=[0-9]*//' | sort | uniq -c | sort -rn | cut -c1-200
        fi
        total=$(asm_functions "$A" | wc -l)
        comm -12 <(asm_functions "$A") <(executed "$T") >"$S/$A-$E.asm"
        echo "   gmsm assembly executed: $(wc -l <"$S/$A-$E.asm") of $total .s functions for $A"
        if [ -s "$S/$A-$E.asm" ]; then
            echo "     yes: $(tr '\n' ' ' <"$S/$A-$E.asm")"
            [ "$(wc -l <"$S/$A-$E.asm")" -lt "$total" ] && echo "     no: $(comm -23 <(asm_functions "$A") "$S/$A-$E.asm" | tr '\n' ' ')"
        fi
        det=$(grep -o '^IN: [^ ]*\(riscvHWProbe\|get_cpucfg\)[^ ]*' "$T" | sort -u | sed 's/^IN: //' | tr '\n' ' ')
        echo "   CPU detection executed: ${det:-(none)}"
        rm -f "$T"
    }

    echo "#### gmsm on other architectures · $(go version) · $(qemu-aarch64 --version | head -1)"
    ( cd "$SRC/go" && go mod tidy ) >"$S/go-tidy.log" 2>&1 || { echo "go mod tidy failed"; cat "$S/go-tidy.log"; }
    ( cd "$SRC/go" && go env GOPROXY && grep '^github.com/emmansun/gmsm v[^ ]* h1' go.sum )

    # Architectures to run (variable ARCHS; default all). s390x is only a byte-order control (big-endian): gmsm has no
    # mlkem/mldsa assembly for s390x, so both builds use the generic Go code.
    local ARCHS="${ARCHS:-arm64 riscv64 ppc64le loong64 s390x}"
    wanted() { [[ " $ARCHS " == *" $1 "* ]]; }
    for A in $ARCHS; do
        build "$A" "gmsm-$A-asm"
        build "$A" "gmsm-$A-purego" -tags purego
    done
    wanted riscv64 && GORISCV64=rva23u64 build riscv64 gmsm-riscv64-rva23-asm
    echo "   (default GORISCV64: $(GOARCH=riscv64 go env GORISCV64); default GOPPC64: $(GOARCH=ppc64le go env GOPPC64))"

    # arm64: always NEON.
    if wanted arm64; then
        run_one arm64 asm gmsm-arm64-asm qemu-aarch64 -cpu max
        run_one arm64 purego gmsm-arm64-purego qemu-aarch64 -cpu max
    fi
    # riscv64: V with VLEN=128 (max by default) and VLEN=256; built with GORISCV64=rva23u64; and a CPU without V (rv64),
    # where the same "assembly" binary must fall back to generic Go through run-time detection.
    if wanted riscv64; then
        run_one riscv64 asm-max gmsm-riscv64-asm qemu-riscv64 -cpu max
        run_one riscv64 asm-max-vlen256 gmsm-riscv64-asm qemu-riscv64 -cpu max,vlen=256
        run_one riscv64 asm-rva23-max gmsm-riscv64-rva23-asm qemu-riscv64 -cpu max
        run_one riscv64 asm-noV gmsm-riscv64-asm qemu-riscv64 -cpu rv64
        run_one riscv64 purego gmsm-riscv64-purego qemu-riscv64 -cpu max
    fi
    # ppc64le: POWER10 and POWER9; also POWER8, which is the minimum Go sets by default (GOPPC64=power8).
    if wanted ppc64le; then
        run_one ppc64le asm-power10 gmsm-ppc64le-asm qemu-ppc64le -cpu power10
        run_one ppc64le asm-power9 gmsm-ppc64le-asm qemu-ppc64le -cpu power9
        run_one ppc64le asm-power8 gmsm-ppc64le-asm qemu-ppc64le -cpu power8
        run_one ppc64le purego-power8 gmsm-ppc64le-purego qemu-ppc64le -cpu power8
    fi
    # loong64: la464 (the core of the Loongson 3A5000/3A6000, with LSX and LASX).
    if wanted loong64; then
        run_one loong64 asm-la464 gmsm-loong64-asm qemu-loongarch64 -cpu la464
        run_one loong64 purego gmsm-loong64-purego qemu-loongarch64 -cpu la464
    fi
    # s390x: big-endian control of the generic code (no gmsm assembly in either build).
    if wanted s390x; then
        run_one s390x no-tags gmsm-s390x-asm qemu-s390x -cpu max
        run_one s390x purego gmsm-s390x-purego qemu-s390x -cpu max
    fi
}

# =====================================================================================================================
# leancrypto 1.9.1 (C, meson) on aarch64 and riscv64, cross compilation and emulation (qemu-user).
#
# The adapters are mlkem_leancrypto.c and mldsa_leancrypto.c with mlkem_harness.h / mldsa_harness.h, the same as on
# x86_64. The runs are the same: ML-KEM with fixed randomness and with RANDOM_RNG=1; ML-DSA with MODE=ctx, simple and
# stream. The only thing that changes is the build: meson with a cross file (cross-<arch>.ini), static linking with
# <arch>-linux-gnu-gcc, and execution with qemu-<arch>.
#
# Two builds per architecture, as on x86_64: "def" (default accelerations) and "c" (-Ddisable-asm=true).
# How leancrypto 1.9.1 chooses its code (read in meson.build and the *_api_*.c files):
#   aarch64: with cpu_family aarch64, ml-kem/src/armv8 and ml-dsa/src/armv8 are built and the APIs ALWAYS call them (no
#            detection: kyber_kem_api_armv8.c, dilithium_signature_*_api_armv8.c). NOTE: ML-KEM-512 uses
#            kyber_kem_api_c.c (ml-kem/src/meson.build: "if (x86_64_asm or arm64_asm) kyber_512_files +=
#            kyber_kem_api_c.c"), as on x86_64. SHA-3: ARMv8 variants chosen through AT_HWCAP (cpufeatures_arm64_auxv.c).
#   riscv64: ml-kem/src/riscv64/kyber_kem_api_riscv.c and ml-dsa/src/riscv64/*_api_riscv64.c use RVV if
#            lc_cpu_feature_available() reports LC_CPU_FEATURE_RISCV_ASM_RVV, which comes from the 'v' bit of AT_HWCAP
#            (internal/src/cpufeatures_riscv_auxv.c); ML-KEM also picks VLEN 128 or 256 at start-up
#            (kyber_rvv_vlen_selector.c). Without V, it falls back to C (with the NTT in rv64im assembly).
#
# Check of which code runs: (1) the library (debug=true by default) writes "Error -22 at file:function:line" on every
# rejection, and these are counted by source file; (2) every run goes through "qemu -d in_asm", which logs the name of
# every function it translates; the architecture-specific functions that ran (armv8, neon, rvv, rv64im, riscv,
# accelerated keccak/sha3) are listed.
# =====================================================================================================================
leancrypto() {
    local VER="${LEANCRYPTO_VERSION:-1.9.1}" L="$W/lc" F="$W/downloads" A C
    local SRCLC="$W/leancrypto-${LEANCRYPTO_VERSION:-1.9.1}"
    mkdir -p "$L"
    summary() { grep -v '^  \|^Error -[0-9]* at ' "$1"; grep '^  ' "$1" | sed 's/tcId=[0-9]*//' | sort | uniq -c | sort -rn | cut -c1-170; }

    [ -x "$W/venv/bin/meson" ] || { python3 -m venv "$W/venv" && "$W/venv/bin/pip" -q install meson ninja; } >/dev/null 2>&1
    export PATH="$W/venv/bin:$PATH"
    [ -f "$F/leancrypto-$VER.tar.gz" ] || curl -sSfL -o "$F/leancrypto-$VER.tar.gz" "https://github.com/smuellerDD/leancrypto/archive/refs/tags/v$VER.tar.gz"
    echo "== leancrypto $VER  (tag v$VER; sha256 of the tarball $(sha256sum "$F/leancrypto-$VER.tar.gz" | cut -c1-64))"
    echo "   meson $(meson --version), $(aarch64-linux-gnu-gcc --version | head -1), $(riscv64-linux-gnu-gcc --version | head -1)"
    [ -d "$SRCLC" ] || tar xzf "$F/leancrypto-$VER.tar.gz" -C "$W"

    build_lc() {  # build_lc <arch> <def|c>: cross-builds the library and links the two adapters (static)
        local A="$1" C="$2" D="$L/build-$1-$2" I="$L/inst-$1-$2" LIB
        local OPT="-Ddefault_library=static -Dapps=disabled"; [ "$C" = c ] && OPT="$OPT -Ddisable-asm=true"
        if [ ! -f "$I/.done" ]; then
            ( cd "$SRCLC" && meson setup "$D" --cross-file "$HERE/cross-$A.ini" --prefix="$I" $OPT >"$L/_${A}_${C}_setup.log" 2>&1 \
              && ninja -C "$D" libleancrypto.a libleancrypto-raw.a libleancrypto-fips.a >"$L/_${A}_${C}_build.log" 2>&1 \
              && meson install -C "$D" --no-rebuild --tags devel >"$L/_${A}_${C}_inst.log" 2>&1 ) && touch "$I/.done" \
              || { echo "   build $A $C: fails (see $L/_${A}_${C}_*.log)"; tail -5 "$L/_${A}_${C}"_*.log; return 1; }
        fi
        LIB=$(find "$I" -name libleancrypto.a | head -1)
        echo "#### $A, build \"$C\" (options: $OPT; $(grep -o 'riscv64_asm\|arm64_asm\|LC_HOST_[A-Z0-9_]*' "$D/build.ninja" | sort -u | tr '\n' ' '))"
        "$A-linux-gnu-gcc" -O2 -Wall -static -I"$I/include" -I"$HERE" "$HERE/mlkem_leancrypto.c" "$LIB" -lpthread -o "$L/mk-$A-$C" || return 1
        "$A-linux-gnu-gcc" -O2 -Wall -static -I"$I/include" -I"$HERE" "$HERE/mldsa_leancrypto.c" "$LIB" -lpthread -o "$L/md-$A-$C" || return 1
    }

    # Architecture-specific functions (or accelerated Keccak) that qemu translated in a trace.
    own_functions() { grep -o '^IN: [A-Za-z0-9_.]*' "$1" | cut -c5- | grep -i 'armv8\|neon\|_ce\b\|_ce_\|arm_\|rvv\|rv64\|riscv\|zbb\|avx\|keccak\|sha3' ; }

    run_lc() {  # run_lc <arch> <def|c> <label> <qemu command...>
        local A="$1" C="$2" E="$3"; shift 3
        local P="$L/$A-$C-$E" T="$L/_trace.log" N M
        : >"$P.functions"
        echo "## $A · \"$C\" · $E · $*"
        export LC_NAME="leancrypto $VER $A $C $E"
        for N in 512 768 1024; do "$@" -d in_asm -D "$T" "$L/mk-$A-$C" "$V/mlkem_$N.txt" "$N"; own_functions "$T" >>"$P.functions"; done >"$P-mk.out" 2>"$P-mk.err"
        summary "$P-mk.out"
        for N in 512 768 1024; do RANDOM_RNG=1 "$@" -d in_asm -D "$T" "$L/mk-$A-$C" "$V/mlkem_$N.txt" "$N"; own_functions "$T" >>"$P.functions"; done >"$P-mk_rnd.out" 2>"$P-mk_rnd.err"
        echo "   (repeated with lc_kyber_enc and the internal generator, accept/reject only:)"; summary "$P-mk_rnd.out"
        for M in ctx simple stream; do
            for N in 44 65 87; do MODE=$M "$@" -d in_asm -D "$T" "$L/md-$A-$C" "$V/mldsa_$N.txt" "$N"; own_functions "$T" >>"$P.functions"; done >"$P-md_$M.out" 2>"$P-md_$M.err"
            summary "$P-md_$M.out"
        done
        rm -f "$T"
        # (explicit list: with a wildcard, "…-max-*" would also catch the files of the "max-vlen256" run)
        local OUTS=("$P"-{mk,mk_rnd,md_ctx,md_simple,md_stream}.out) ERRS=("$P"-{mk,mk_rnd,md_ctx,md_simple,md_stream}.err)
        echo "   errors or warnings on stderr: $(cat "${ERRS[@]}" | grep -v '^Error -[0-9]* at ' | sort | uniq -c | head -5 | tr -s ' ' | tr '\n' ';')"
        echo "   rejection traces from the library by source file:"
        cat "${OUTS[@]}" "${ERRS[@]}" | grep -o '^Error -[0-9]* at [^:]*' | sed 's#\.\./leancrypto-[0-9.]*/##' | sort | uniq -c | sed 's/^/     /'
        echo "   architecture-specific functions executed (qemu -d in_asm), $(sort -u "$P.functions" | wc -l) distinct:"
        sort -u "$P.functions" | tr '\n' ' ' | fold -s -w 160 | sed 's/^/     /'; echo
    }

    for A in aarch64 riscv64; do
        for C in def c; do build_lc "$A" "$C" || continue; done
    done
    # aarch64: "max" (NEON, SHA3 and the other extensions) and cortex-a53 (ARMv8.0 with NEON, without the SHA3 instructions).
    [ -x "$L/mk-aarch64-def" ] && run_lc aarch64 def max qemu-aarch64 -cpu max
    [ -x "$L/mk-aarch64-def" ] && run_lc aarch64 def a53 qemu-aarch64 -cpu cortex-a53
    [ -x "$L/mk-aarch64-c" ]   && run_lc aarch64 c max qemu-aarch64 -cpu max
    # riscv64: V with VLEN 128 (max) and 256; rv64 without V (must fall back to C); and the C-only build.
    [ -x "$L/mk-riscv64-def" ] && run_lc riscv64 def max qemu-riscv64 -cpu max
    [ -x "$L/mk-riscv64-def" ] && run_lc riscv64 def max-vlen256 qemu-riscv64 -cpu max,vlen=256
    [ -x "$L/mk-riscv64-def" ] && run_lc riscv64 def rv64-noV qemu-riscv64 -cpu rv64
    [ -x "$L/mk-riscv64-c" ]   && run_lc riscv64 c max qemu-riscv64 -cpu max
}

# =====================================================================================================================
# Zig standard library (std.crypto.kem.ml_kem and std.crypto.sign.mldsa) on aarch64, riscv64 and s390x (reverse byte
# order), Zig cross compilation and emulation with qemu-user.
#
# The program is wycheproof.zig as on x86_64 (the vectors are embedded at compile time with @embedFile), built with
# "build-exe -O ReleaseSafe --dep options -Mroot=wycheproof.zig -Moptions=options.zig"; the only change is
# "-target <arch>-linux" and -mcpu. The Zig std (0.17.1) has no assembly and no @Vector types in ml_kem.zig, ml_dsa.zig
# or keccak_p.zig; what depends on the architecture is the byte order (s390x is big-endian), the type used to sample
# the CBD (ml_kem.zig:1180: u32 on x86, u64 elsewhere) and whatever LLVM auto-vectorises if -mcpu has a vector
# extension. On riscv64 "baseline" (rv64gc) has none, so it is also built with baseline+v; on s390x Zig's "baseline"
# already has the vector facility (vl, vst, vgbm…), so it is also built for z10, without it.
# To see whether it is used, the vector instructions in the binary and in the functions qemu runs are counted.
# =====================================================================================================================
zig_() {
    local VER="${ZIG_VERSION:-0.17.1}" ZD="$W/zig" Z URL SUM T B
    mkdir -p "$ZD"
    export ZIG_GLOBAL_CACHE_DIR="$ZD/cache-global" ZIG_LOCAL_CACHE_DIR="$ZD/cache-local"
    Z="$ZD/zig-$VER/zig"; T="$W/downloads/zig-$VER.tar.xz"
    if [ ! -x "$Z" ]; then
        # ziglang.org: the index gives the URL and the sha256 of the tarball; it is checked before unpacking.
        curl -sSfL -o "$W/downloads/zig-index.json" https://ziglang.org/download/index.json
        read -r URL SUM < <(python3 -I -c "import json,sys; e=json.load(open(sys.argv[1]))[sys.argv[2]]['x86_64-linux']; print(e['tarball'], e['shasum'])" "$W/downloads/zig-index.json" "$VER")
        curl -sSfL -o "$T" "$URL"
        echo "$SUM  $T" | sha256sum -c --quiet || { echo "== Zig $VER: the sha256 does not match the index"; return 1; }
        mkdir -p "$ZD/zig-$VER"; tar xJf "$T" -C "$ZD/zig-$VER" --strip-components=1
    fi
    echo "== Zig $("$Z" version) (ziglang.org tarball, sha256 $(sha256sum "$T" 2>/dev/null | cut -c1-64), checked against index.json)"

    B="$ZD/test-$VER"; rm -rf "$B"; mkdir -p "$B"; cp "$HERE/wycheproof.zig" "$V"/mlkem_*.txt "$V"/mldsa_*.txt "$B/"
    local DSA=true; [ -f "$(dirname "$Z")/lib/std/crypto/ml_dsa.zig" ] || DSA=false
    printf 'pub const with_dsa = %s;\n' "$DSA" >"$B/options.zig"

    # Expression (grep -E) for a vector instruction in objdump / qemu output, for each architecture.
    vector_re() {
        case "$1" in
            aarch64) echo '[[:space:]]v[0-9]+\.(16b|8b|8h|4h|4s|2s|2d)' ;;
            riscv64) echo '[[:space:]]v[a-z0-9]+\.[a-z.]+[[:space:]]|vsetivli|vsetvli' ;;
            s390x)   echo '[[:space:]]v[a-z]+[[:space:]]+%v[0-9]' ;;
        esac
    }

    run_zig() {  # run_zig <arch> <mcpu> <qemu command...>
        local A="$1" M="$2"; shift 2
        local N="p-$A-${M//+/_}" TR="$B/_trace.log" X; X=$(vector_re "$A")
        echo "#### Zig $VER, ReleaseSafe, -target $A-linux -mcpu=$M, run with: $*"
        ( cd "$B" && "$Z" build-exe -O ReleaseSafe -target "$A-linux" -mcpu="$M" --dep options -Mroot=wycheproof.zig -Moptions=options.zig \
            -femit-bin="$N" >"_b-$N.log" 2>&1 ) || { echo "   DOES NOT BUILD:"; grep -m6 'error' "$B/_b-$N.log" | cut -c1-200; return; }
        ( cd "$B" && "$@" -d in_asm -D "$TR" "./$N" >"_o-$N.log" 2>&1; echo "   (exit code $?)" )
        grep -v '^  ' "$B/_o-$N.log"; grep '^  ' "$B/_o-$N.log" | sed 's/tcId=[0-9]*//' | sort | uniq -c | cut -c1-170
        # vector instructions: in the binary, and in the blocks qemu translated inside ml_kem / ml_dsa functions
        echo "   vector instructions in the binary: $("$A-linux-gnu-objdump" -d "$B/$N" 2>/dev/null | grep -cE "$X")"
        # qemu (without capstone) does not disassemble aarch64: the functions qemu translated are taken and the vector
        # instructions objdump sees inside them are counted (total, and only in ml_kem / ml_dsa / keccak functions).
        grep '^IN: ' "$TR" | cut -c5- | sort -u >"$B/_functions"
        "$A-linux-gnu-objdump" -d "$B/$N" 2>/dev/null | awk -v F="$B/_functions" -v X="$X" '
            BEGIN { while ((getline l < F) > 0) e[l] = 1 }
            /^[0-9a-f]+ <.*>:$/ { n = $0; sub(/^[0-9a-f]+ </, "", n); sub(/>:$/, "", n); f = (n in e); g = (n ~ /ml_kem|ml_dsa|keccak/); if (f) { nf++; if (g) ng++ }; next }
            f && $0 ~ X { t++; if (g) k++ }
            END { printf "   in the %d executed functions: %d vector instructions; in the %d of ml_kem/ml_dsa/keccak: %d (code inlined into wycheproof.zig counts separately)\n", nf, t, ng, k }'
        rm -f "$TR"
    }

    run_zig aarch64 baseline qemu-aarch64 -cpu max
    run_zig riscv64 baseline qemu-riscv64 -cpu max
    run_zig riscv64 baseline+v qemu-riscv64 -cpu max
    run_zig s390x baseline qemu-s390x -cpu max
    run_zig s390x z10 qemu-s390x -cpu max
}

[ $# -eq 0 ] && set -- gmsm leancrypto zig
for X in "$@"; do
    echo
    case "$X" in
        gmsm)       echo "########## gmsm"; ( gmsm ) ;;
        leancrypto) echo "########## leancrypto"; ( leancrypto ) ;;
        zig)        echo "########## zig"; ( zig_ ) ;;
        *)          echo "unknown: $X" ;;
    esac
done
