#!/usr/bin/env bash
# Check two Rust crates with the Wycheproof vectors: pqcrypto-mldsa 0.1.2 (a PQClean wrapper) and
# oqs 0.11.0 (which builds its bundled liboqs 0.13.0; needs cmake).
# Run ./run.sh first: it downloads and converts the vectors. Needs a Rust toolchain (cargo).
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-lab-work}"
export PATH="$HOME/.cargo/bin:$PATH"
[ -f "$WORK/vectors/mldsa_65.txt" ] || { echo "run ./run.sh first"; exit 2; }
export CARGO_TARGET_DIR="$WORK/pqcrypto-check-target"

cd "$HERE/pqcrypto-check" || exit 2
echo "== pqcrypto-mldsa 0.1.2 with default features (avx2 enabled), and oqs 0.11.0"
cargo run --quiet --release -- "$WORK/vectors" 2>"$WORK/pqcrypto-avx2.log" || tail -n 5 "$WORK/pqcrypto-avx2.log"
echo "== pqcrypto-mldsa 0.1.2 with the avx2 feature disabled (oqs is unchanged: it selects AVX2 at run time)"
cargo run --quiet --release --no-default-features -- "$WORK/vectors" 2>"$WORK/pqcrypto-ref.log" || tail -n 5 "$WORK/pqcrypto-ref.log"
