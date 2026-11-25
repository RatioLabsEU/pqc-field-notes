#!/usr/bin/env bash
# Runs the Wycheproof ML-KEM vectors against several released versions of the npm package "mlkem".
#
# Needs: git, python3, node and npm. Everything is downloaded under $WORK. Nothing is installed system-wide.
#
# Usage:  ./run.sh            (set WORK=/some/dir to choose the working directory)
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
MLKEM_VERSIONS="${MLKEM_VERSIONS:-3.0.0 2.7.2 2.7.1 2.7.0 2.5.0}"
mkdir -p "$WORK/vectors" "$WORK/mlkem-js"

if [ ! -d "$WORK/wycheproof/.git" ]; then
    git clone --quiet https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" \
        && git -C "$WORK/wycheproof" -c advice.detachedHead=false checkout --quiet "$WYCHEPROOF_COMMIT" || exit 2
fi
for P in 512 768 1024; do
    python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$WORK/vectors/mlkem_$P.txt"
done
echo "Wycheproof $(git -C "$WORK/wycheproof" rev-parse --short=12 HEAD): $(wc -l <"$WORK/vectors/mlkem_512.txt") / $(wc -l <"$WORK/vectors/mlkem_768.txt") / $(wc -l <"$WORK/vectors/mlkem_1024.txt") ML-KEM vectors (512 / 768 / 1024)"
echo "node $(node --version)"
echo

cd "$WORK/mlkem-js" || exit 2
[ -f package.json ] || npm init -y >/dev/null 2>&1
cp "$HERE/mlkem_npm.mjs" .
for V in $MLKEM_VERSIONS; do
    A="mlkem$(echo "$V" | tr -d .)"
    [ -d "node_modules/$A" ] || npm install --silent "$A@npm:mlkem@$V" >/dev/null 2>&1 || { echo "could not install $V"; continue; }
    node mlkem_npm.mjs "$A" "$WORK/vectors"
done
