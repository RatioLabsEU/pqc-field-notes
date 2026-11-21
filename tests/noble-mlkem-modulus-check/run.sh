#!/usr/bin/env bash
# Runs the Wycheproof ML-KEM vectors against several released versions of @noble/post-quantum.
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
NOBLE_VERSIONS="0.7.1 0.6.1 0.6.0 0.5.4 0.5.0 0.4.1 0.3.1 0.2.1"
mkdir -p "$WORK/vectors" "$WORK/js"

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do
    python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$WORK/vectors/mlkem_$P.txt"
done
echo "Wycheproof $WYCHEPROOF_COMMIT: $(wc -l <"$WORK/vectors/mlkem_512.txt") / $(wc -l <"$WORK/vectors/mlkem_768.txt") / $(wc -l <"$WORK/vectors/mlkem_1024.txt") ML-KEM vectors (512 / 768 / 1024)"

echo
echo "### @noble/post-quantum"
if command -v npm >/dev/null; then
    cd "$WORK/js" || exit 2
    [ -f package.json ] || npm init -y >/dev/null 2>&1
    cp "$HERE/noble.mjs" .
    for V in $NOBLE_VERSIONS; do
        A="noble$(echo "$V" | tr -d .)"
        [ -d "node_modules/$A" ] || npm install --silent "$A@npm:@noble/post-quantum@$V" >/dev/null 2>&1 || { echo "could not install $V"; continue; }
        node noble.mjs "$A" "$WORK/vectors"
    done
else
    echo "npm not found: skipped"
fi
