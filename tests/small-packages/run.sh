#!/usr/bin/env bash
# Run the Wycheproof ML-KEM and ML-DSA vectors against small packages with their own implementation:
#
#   dart    pub.dev: pqcrypto 0.4.4 (ML-KEM, ML-DSA) and cipherlib 0.7.2 (ML-KEM), pure Dart
#   nuget   nuget.org: KyberNET 1.0.3 (ML-KEM), C#
#   npm     registry.npmjs.org: @theqrl/mldsa87 2.2.0, noqtis 0.2.2 and @umbra-privacy/quick-mlkem768 0.1.1
#   swift   SwiftKyber 3.5.0 and SwiftDilithium 3.6.0 (github.com/leif-ibsen), with a Linux platform patch
#   php     Packagist: paragonie/pqcrypto_compat 0.3.4, pure PHP
#   analyze diagnosis of the vectors that explains the KyberNET result (not a library test)
#
# Versions are pinned in dart/pubspec.yaml, nuget/WycheproofNuget.csproj, npm/package.json, swift/Package.swift and
# php/composer.json; the lock files written by each tool record the checksum of every downloaded archive.
#
# Needs: git, curl, unzip, gpg, python3, and for each part: nothing else for dart and swift (the official Dart SDK and
# Swift toolchain for Ubuntu 24.04 are downloaded and checked); .NET SDK 10 for nuget; Node.js and npm for npm; PHP 8.1+
# and Composer for php. The sources are copied to $WORK and everything is downloaded and built there. Nothing is
# installed system-wide.
#
# Usage:  ./run.sh [dart] [nuget] [npm] [swift] [php] [analyze]      (no arguments: dart nuget npm swift php)
#         set WORK=/some/dir to choose the working directory
#
# Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
WORK="${WORK:-$HOME/pqc-field-notes-work}"
WYCHEPROOF_COMMIT=65ca494727a5
W="$WORK/small-packages"; V="$WORK/vectors"; O="$W/out"; SRC="$W/src"
mkdir -p "$V" "$O" "$W/downloads"
rm -rf "$SRC"; mkdir -p "$SRC"; cp -r "$HERE/dart" "$HERE/nuget" "$HERE/npm" "$HERE/swift" "$HERE/php" "$SRC/"
export PUB_CACHE="$W/pub-cache" DART_DISABLE_ANALYTICS=1
export NUGET_PACKAGES="$W/nuget" DOTNET_CLI_HOME="$W/dotnet-home" DOTNET_CLI_TELEMETRY_OPTOUT=1 DOTNET_NOLOGO=1
export npm_config_cache="$W/npm-cache" npm_config_update_notifier=false npm_config_fund=false npm_config_audit=false

fetch() { # url dir ref
    [ -d "$2/.git" ] && return 0
    git clone --quiet "$1" "$2" && git -C "$2" -c advice.detachedHead=false checkout --quiet "$3"
}
fetch https://github.com/C2SP/wycheproof.git "$WORK/wycheproof" "$WYCHEPROOF_COMMIT" || exit 2
for P in 512 768 1024; do python3 "$HERE/mlkem_to_text.py" "$WORK/wycheproof/testvectors_v1" "$P" >"$V/mlkem_$P.txt"; done
for P in 44 65 87; do python3 "$HERE/wycheproof_to_text.py" "$WORK/wycheproof/testvectors_v1/mldsa_${P}_verify_test.json" >"$V/mldsa_$P.txt"; done

# Summary: the total lines as they are, and the detail lines grouped by vector comment.
summary() { grep -v '^  ' "$1"; grep '^  ' "$1" | sed 's/tcId=[0-9]*//' | sort | uniq -c | sort -rn | cut -c1-220 || true; }

echo "#### Wycheproof $WYCHEPROOF_COMMIT, $(uname -m), $(nproc) cores"

# Official stable Dart SDK (storage.googleapis.com/dart-archive), checked against its .sha256sum.
get_dart() {
    local U=https://storage.googleapis.com/dart-archive/channels/stable/release/3.14.1/sdk/dartsdk-linux-x64-release.zip
    ( cd "$W/downloads" && curl -sSfLO "$U" && curl -sSfLO "$U.sha256sum" \
        && sha256sum -c dartsdk-linux-x64-release.zip.sha256sum ) && unzip -q -o "$W/downloads/dartsdk-linux-x64-release.zip" -d "$W"
}

# Official Swift toolchain for Ubuntu 24.04 (download.swift.org), checked with its GPG signature and the swift.org keys
# (in a gpg home directory of its own inside $W).
get_swift() {
    local U=https://download.swift.org/swift-6.4.2-release/ubuntu2404/swift-6.4.2-RELEASE/swift-6.4.2-RELEASE-ubuntu24.04.tar.gz
    local F="$W/downloads/$(basename "$U")"
    mkdir -p -m 700 "$W/gpg-home"; mkdir -p "$W/swift"
    { [ -s "$F" ] || curl -sSfL "$U" -o "$F"; } && curl -sSfL "$U.sig" -o "$F.sig" \
        && curl -sSfL --compressed https://www.swift.org/keys/all-keys.asc -o "$W/downloads/swift-keys.asc" \
        && gpg --homedir "$W/gpg-home" --batch --quiet --import "$W/downloads/swift-keys.asc" \
        && gpg --homedir "$W/gpg-home" --batch --verify "$F.sig" "$F" \
        && tar xzf "$F" -C "$W/swift" --strip-components=1
}

# Dart: pub.dev packages at the versions pinned in dart/pubspec.yaml (pubspec.lock records the sha256 of each archive).
dart_() {
    local D="$W/dart-sdk/bin/dart" pkg
    [ -x "$D" ] || get_dart >"$O/dart-download.log" 2>&1 || { echo "## Dart: could not download the SDK"; tail -5 "$O/dart-download.log"; return 1; }
    echo "#### $("$D" --version 2>&1)"
    echo "   dart-archive SDK, published sha256: $(cut -c1-64 "$W/downloads/dartsdk-linux-x64-release.zip.sha256sum" 2>/dev/null)"
    ( cd "$SRC/dart" && "$D" pub get ) >"$O/dart-pub.log" 2>&1 || { echo "## dart pub get failed"; tail -20 "$O/dart-pub.log"; return 1; }
    awk '/^  (pqcrypto|cipherlib):/{n=$1} n && /sha256:/{print "   pub.dev", n, $2} n && /version:/{print "     ", $0; n=""}' "$SRC/dart/pubspec.lock"
    for pkg in pqcrypto cipherlib; do
        ( cd "$SRC/dart" && "$D" run bin/wycheproof.dart "$pkg" "$V" ) >"$O/dart-$pkg.out" 2>&1
        summary "$O/dart-$pkg.out"
    done
}

# NuGet: KyberNET from nuget.org (version pinned in nuget/WycheproofNuget.csproj), built for net10.0.
nuget_() {
    local f
    echo "#### dotnet $(dotnet --version), runtime $(dotnet --list-runtimes | grep -o 'NETCore.App 10[^ ]*' | head -1)"
    ( cd "$SRC/nuget" && dotnet build -c Release -nologo -v q ) >"$O/nuget-build.log" 2>&1 \
        || { echo "## DOES NOT BUILD"; grep -E 'error' "$O/nuget-build.log" | sort -u | head -20; return 1; }
    # provenance: nuget.org, with the sha512 of the .nupkg that NuGet stores
    for f in "$NUGET_PACKAGES"/kybernet/*/*.nupkg.sha512; do echo "   nuget.org $(basename "$(dirname "$f")") kybernet sha512(base64)=$(cat "$f")"; done
    ( cd "$SRC/nuget" && dotnet run -c Release --no-build -- "$V" ) >"$O/nuget-kybernet.out" 2>&1
    summary "$O/nuget-kybernet.out"
}

# npm: packages from registry.npmjs.org at the versions pinned in npm/package.json; npm install without install scripts
# (--ignore-scripts). package-lock.json records the "integrity" checksum of every archive; the direct dependencies are
# listed here.
npm_() {
    local pkg
    echo "#### node $(node --version), npm $(npm --version)"
    ( cd "$SRC/npm" && npm install --ignore-scripts --no-audit --no-fund ) >"$O/npm-install.log" 2>&1 \
        || { echo "## npm install failed"; tail -20 "$O/npm-install.log"; return 1; }
    ( cd "$SRC/npm" && node -e 'const d=Object.keys(require("./package.json").dependencies); const l=require("./package-lock.json").packages; for (const [k,v] of Object.entries(l)) { const n=k.replace("node_modules/",""); if (d.includes(n)) console.log("   npm", n, v.version, v.integrity) }' )
    for pkg in theqrl noqtis quick; do
        node "$SRC/npm/wycheproof_npm.mjs" "$pkg" "$V" >"$O/npm-$pkg.out" 2>&1
        summary "$O/npm-$pkg.out"
    done
}

# Swift: official swift.org toolchain for Ubuntu 24.04 unpacked in $W/swift (get_swift).
# SwiftKyber, SwiftDilithium and BigInt call SecRandomCopyBytes (Apple's Security.framework, which does not exist on
# Linux): they are put in edit mode (swift package edit, at the revision pinned by Package.resolved) and
# swift/shim/SecRandomLinux.swift, which only provides system randomness, is added to each. HOME points into $W for the
# SwiftPM and clang caches.
swift_() {
    local SW="$W/swift/usr/bin/swift" D="$SRC/swift" T dep e
    [ -x "$SW" ] || get_swift >"$O/swift-download.log" 2>&1 || { echo "## Swift: could not download the toolchain"; tail -5 "$O/swift-download.log"; return 1; }
    export HOME="$W/swift-home"; mkdir -p "$HOME"
    echo "#### $("$SW" --version 2>&1 | head -1)"
    T=$(ls "$W"/downloads/swift-*.tar.gz 2>/dev/null | head -1)
    echo "   signature of $(basename "$T"): $(gpg --homedir "$W/gpg-home" --batch --verify "$T.sig" "$T" 2>&1 | grep -E 'Good|BAD' | head -1)"
    ( cd "$D" && "$SW" package resolve ) >"$O/swift-resolve.log" 2>&1 || { echo "## swift package resolve failed"; tail -20 "$O/swift-resolve.log"; return 1; }
    for dep in BigInt SwiftKyber SwiftDilithium; do
        [ -d "$D/Packages/$dep" ] || ( cd "$D" && "$SW" package edit "$dep" ) >>"$O/swift-resolve.log" 2>&1
        cp "$D/shim/SecRandomLinux.swift" "$D/Packages/$dep/Sources/$dep/SecRandomLinux.swift"
        echo "   $dep: $(git -C "$D/Packages/$dep" describe --tags --always 2>/dev/null) $(git -C "$D/Packages/$dep" rev-parse HEAD 2>/dev/null)," \
             "changes: $(git -C "$D/Packages/$dep" status --porcelain | tr '\n' ' ')"
    done
    python3 -I -c 'import json,sys
for p in json.load(open(sys.argv[1]))["pins"]: print("   Package.resolved:", p["identity"], p["state"].get("version"), p["state"].get("revision"))' "$D/Package.resolved"
    ( cd "$D" && "$SW" build -c release ) >"$O/swift-build.log" 2>&1 \
        || { echo "## DOES NOT BUILD"; grep -E 'error:' "$O/swift-build.log" | sort -u | head -20; return 1; }
    for e in wycheproof-kyber wycheproof-dilithium; do
        "$D/.build/release/$e" "$V" >"$O/swift-$e.out" 2>&1
        summary "$O/swift-$e.out"
    done
}

# PHP: the system php and composer; paragonie/pqcrypto_compat from Packagist at the version pinned in php/composer.json
# (composer.lock records the commit reference and the archive checksum). No scripts or plugins.
php_() {
    export COMPOSER_HOME="$W/composer-home" COMPOSER_CACHE_DIR="$W/composer-cache" XDEBUG_MODE=off
    echo "#### $(php --version | head -1), $(composer --version 2>/dev/null | head -1)"
    ( cd "$SRC/php" && composer install --no-interaction --no-scripts --no-plugins --no-progress ) >"$O/php-composer.log" 2>&1 \
        || { echo "## composer install failed"; tail -20 "$O/php-composer.log"; return 1; }
    ( cd "$SRC/php" && php -r '$l=json_decode(file_get_contents("composer.lock"),true); foreach($l["packages"] as $p) echo "   packagist ", $p["name"], " ", $p["version"], " commit ", $p["source"]["reference"] ?? "?", " dist sha ", $p["dist"]["shasum"] ?: "(empty)", "\n";' )
    ( cd "$SRC/php" && php wycheproof.php "$V" ) >"$O/php.out" 2>&1
    summary "$O/php.out"
}

[ $# -eq 0 ] && set -- dart nuget npm swift php
for X in "$@"; do
    case "$X" in
        dart) dart_ ;;
        nuget) nuget_ ;;
        npm) npm_ ;;
        swift) ( swift_ ) ;;
        php) ( php_ ) ;;
        analyze) echo "######## analyze_vectors.py (diagnosis of the vectors, to explain the KyberNET result)"; python3 -I "$HERE/analyze_vectors.py" "$V" ;;
        *) echo "unknown: $X" ;;
    esac
done
