#!/usr/bin/env bash
# Check the archived Rust crate pqcrypto-dilithium 0.5.0 on x86_64 with AVX2: its AVX2 verifier against its portable
# ("clean") verifier on the same inputs. This adapts section 2 of run.sh (the patched signer of oob_z.c) and
# run_pqcrypto.sh to this crate. The crate implements a pre-standard version of Dilithium, so the Wycheproof ML-DSA
# vectors do not apply: dilithium_generator.c makes the inputs with the crate's own C code instead.
#
# Needs: gcc, perl and a Rust toolchain (cargo). Does not need ./run.sh first. Cargo's home and target directories are
# set under $WORK/pqcrypto-dilithium; nothing is installed system-wide.
#
# Usage:  ./run_pqcrypto_dilithium.sh       (set WORK=/some/dir to choose the working directory)
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
D="$WORK/pqcrypto-dilithium"
export CARGO_HOME="$D/cargo-home" CARGO_TARGET_DIR="$D/target" PATH="$HOME/.cargo/bin:$PATH"
mkdir -p "$D" "$CARGO_HOME"

grep -q avx2 /proc/cpuinfo || echo "WARNING: this CPU has no AVX2; the affected code path will not run."
cd "$HERE/pqcrypto-dilithium-check" || exit 2
echo "# pqcrypto-dilithium 0.5.0: AVX2 against clean. $(date -u '+%d-%m-%Y %H:%M') UTC"
echo "# $(uname -srm); $(rustc --version); $(cargo --version); $(gcc --version | head -1)"
echo "# CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//'); $(grep -m1 '^flags' /proc/cpuinfo | grep -ow 'avx2\|bmi2\|popcnt\|aes' | sort -u | tr '\n' ' ')"
cargo fetch -q || { echo "cargo fetch failed"; exit 2; }
CR=$(ls -d "$CARGO_HOME"/registry/src/*/pqcrypto-dilithium-0.5.0 | head -1)
echo "# crate: $CR"
echo "# sha256 of the .crate: $(sha256sum "$CARGO_HOME"/registry/cache/*/pqcrypto-dilithium-0.5.0.crate | cut -c1-64)"
echo "# resolved versions (Cargo.lock): $(grep -A1 '^name = "pqcrypto-\|^name = "cc"' Cargo.lock | grep -o '"[^"]*"' | paste -sd' ' | sed 's/" "/ /g')"
grep -h 'version: https' "$CR/pqclean/crypto_sign/dilithium3/META.yml" 2>/dev/null | head -1 | sed 's/ via .*//; s/^ */# origin of the C code (META.yml of dilithium3): /'
grep -n 'shortness follows from unpacking' "$CR"/pqclean/crypto_sign/dilithium*/avx2/sign.c | sed "s#$CR/##; s/^/# in the AVX2 verifier: /"

echo; echo "## 1. Inputs (dilithium_generator.c with the crate's C code and the patched clean signer)"
: >"$D/cases.txt"
for P in 2 3 5; do
    CL="$CR/pqclean/crypto_sign/dilithium$P/clean"; C="PQCLEAN_DILITHIUM${P}_CLEAN"
    # The same patch as in run.sh: keep only candidates with gamma1 - beta <= ||z||_inf < gamma1.
    perl -0pe "s/if \(${C}_polyvecl_chknorm\(&z, GAMMA1 - BETA\)\) \{\s*goto rej;/if (!${C}_polyvecl_chknorm(&z, GAMMA1 - BETA) || ${C}_polyvecl_chknorm(&z, GAMMA1)) {\n        goto rej;/" \
        "$CL/sign.c" >"$D/sign_patched_$P.c"
    if cmp -s "$CL/sign.c" "$D/sign_patched_$P.c"; then echo "dilithium$P: could not patch the signer"; exit 2; fi
    echo "dilithium$P: signer patch:"; diff "$CL/sign.c" "$D/sign_patched_$P.c" | sed 's/^/    /'
    gcc -O2 -w -DNS="$C" -DVARIANT="\"dilithium$P\"" -I"$CR/pqclean/common" -I"$CL" "$HERE/dilithium_generator.c" \
        $(ls "$CL"/*.c | grep -v '/sign\.c$') "$D/sign_patched_$P.c" "$CR/pqclean/common/fips202.c" -o "$D/gen$P" 2>"$D/gen$P.log" \
        || { echo "dilithium$P: the generator does not build"; head -5 "$D/gen$P.log"; exit 2; }
    "$D/gen$P" >>"$D/cases.txt" 2>"$D/gen$P.err" || { echo "dilithium$P: the generator failed"; cat "$D/gen$P.err"; exit 2; }
    sed 's/^/    /' "$D/gen$P.err"
done
echo "cases: $(wc -l <"$D/cases.txt") lines; sha256 $(sha256sum "$D/cases.txt" | cut -c1-16)"

echo; echo "## 2. pqcrypto-dilithium 0.5.0 with the avx2 feature (default): API (selects AVX2 at run time), ffi clean and ffi avx2"
cargo run -q --release -- "$D/cases.txt" 2>"$D/cargo_avx2.err" || { echo "(non-zero exit)"; tail -5 "$D/cargo_avx2.err"; }
echo; echo "## 3. Without the avx2 feature (--no-default-features): the API uses clean"
cargo run -q --release --no-default-features -- "$D/cases.txt" 2>"$D/cargo_ref.err" || { echo "(non-zero exit)"; tail -5 "$D/cargo_ref.err"; }
echo; echo "# end: $(date -u '+%d-%m-%Y %H:%M') UTC"
