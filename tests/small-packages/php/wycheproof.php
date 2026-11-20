<?php
// Wycheproof ML-KEM and ML-DSA vectors against paragonie/pqcrypto_compat (pure PHP), through its public interface.
// Usage:  php wycheproof.php <directory with mlkem_*.txt and mldsa_*.txt>      (from the directory with vendor/)
//
// Vector format (hex, fields separated by "|"), produced by mlkem_to_text.py and wycheproof_to_text.py:
//   D|tcId|result|seed d||z|ek|c|K|comment     generate the key from the seed and decapsulate c
//   E|tcId|result|m|ek|c|K|comment             encapsulate with ek and the randomness m
//   X|tcId|result|dk|c|K||comment              decapsulate with the expanded decapsulation key
//   tcId|result|public key|message|context|signature|comment      (ML-DSA, verify)
//
// Public interface (src/MLKem*.php, src/Traits/MLKemTrait.php, src/MLDSA*/*.php, version 0.3.4):
//   ML-KEM: the package's decapsulation key IS the 64-byte seed d||z (MLKemXXX\DecapsulationKey($seed));
//     decapsulate($c) regenerates the key from the seed and throws MLKemInternalException if the seed or c do not have
//     the right length. There is no way to import the FIPS 203 expanded key: the X vectors count as "no interface".
//     (new MLKemXXX\EncapsulationKey($ek))->encapsulate() with internal randomness: used to check whether it accepts
//     the key. MLKemXXX::encapsulateInternal($ek, $m) (public, same key check) is only used for the valid vectors to
//     compare c and K; MLKemXXX::keyGenInternal($d, $z) only to compare the ek of the D vectors.
//   ML-DSA: MLDSAXX\VerificationKey::fromBytes($pk) and MLDSAXX\Signature::fromBytes($signature) throw
//     MLDSAInternalException if they cannot be decoded; $vk->verify($signature, $message, $ctx) -> bool (true = valid).
//     An exception counts as a rejection.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
declare(strict_types=1);
require __DIR__ . '/vendor/autoload.php';

use ParagonIE\PQCrypto\MLKem512;
use ParagonIE\PQCrypto\MLKem768;
use ParagonIE\PQCrypto\MLKem1024;

$dir = $argv[1];
$version = \Composer\InstalledVersions::getPrettyVersion('paragonie/pqcrypto_compat');
$name = "pqcrypto_compat $version";
$kinds = ['seed', 'encaps', 'expanded dk'];

/** Runs the operation; an exception from the library is a rejection and its class is recorded. PHP Errors (faults of
 *  this program: TypeError, Error for a missing class or method) are not counted as rejections: they are let through. */
function attempt(callable $f): array
{
    try {
        return ['ok' => true] + $f();
    } catch (\Exception $e) {
        return ['ok' => false, 'err' => (new \ReflectionClass($e))->getShortName()];
    }
}

foreach (['512' => MLKem512::class, '768' => MLKem768::class, '1024' => MLKem1024::class] as $p => $C) {
    $EK = $C . '\\EncapsulationKey';
    $DK = $C . '\\DecapsulationKey';
    $n = $acc = $fail = $none = [0, 0, 0];
    foreach (file("$dir/mlkem_$p.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $x = explode('|', $line);
        if (count($x) < 8) continue;
        $t = strpos('DEX', $x[0]);
        $valid = $x[2] === 'valid';
        $good = false;
        if ($t === 0) {
            $seed = hex2bin($x[3]);
            $r = attempt(function () use ($DK, $seed, $x) {
                return ['K' => (new $DK($seed))->decapsulate(hex2bin($x[5]))];
            });
            $good = $r['ok'] && $r['K'] === hex2bin($x[6]);
            if ($good && $x[4] !== '') {
                $ek = $C::keyGenInternal(substr($seed, 0, 32), substr($seed, 32, 32))['encapsulationKey'];
                $good = $ek === hex2bin($x[4]);
            }
        } elseif ($t === 1) {
            $r = attempt(function () use ($C, $EK, $x, $valid) {
                (new $EK(hex2bin($x[4])))->encapsulate();          // normal interface: if it throws, the key was rejected
                if (!$valid) return [];
                $s = $C::encapsulateInternal(hex2bin($x[4]), hex2bin($x[3]));
                return ['c' => $s['ciphertext'], 'K' => $s['sharedKey']];
            });
            $good = $r['ok'] && $r['c'] === hex2bin($x[5]) && $r['K'] === hex2bin($x[6]);
        } else {
            $none[2]++;                                          // no interface for the expanded key
            continue;
        }
        $n[$t]++;
        if ($valid && !$good) { $fail[$t]++; echo "  valid fails       [{$kinds[$t]}] tcId={$x[1]} (" . ($r['ok'] ? 'different result' : 'error ' . $r['err']) . ")  {$x[7]}\n"; }
        if (!$valid && $r['ok']) { $acc[$t]++; echo "  INVALID ACCEPTED  [{$kinds[$t]}] tcId={$x[1]}  {$x[7]}\n"; }
    }
    $s = str_pad("$name ML-KEM-$p", 30);
    for ($t = 0; $t < 3; $t++) {
        if ($n[$t] === 0 && $none[$t] > 0) { $s .= " | {$kinds[$t]}: no interface ({$none[$t]})"; continue; }
        $s .= " | {$kinds[$t]}: {$n[$t]} vectors, INVALID ACCEPTED={$acc[$t]}, valid fails={$fail[$t]}";
    }
    echo "$s\n";
}

foreach (['44', '65', '87'] as $p) {
    $VK = "ParagonIE\\PQCrypto\\MLDSA$p\\VerificationKey";
    $SG = "ParagonIE\\PQCrypto\\MLDSA$p\\Signature";
    $total = $acc = $rej = 0;
    foreach (file("$dir/mldsa_$p.txt", FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
        $x = explode('|', $line);
        if (count($x) < 7) continue;
        $valid = $x[1] === 'valid';
        $r = attempt(function () use ($VK, $SG, $x) {
            $vk = $VK::fromBytes(hex2bin($x[2]));
            return ['v' => $vk->verify($SG::fromBytes(hex2bin($x[5])), hex2bin($x[3]), hex2bin($x[4]))];
        });
        $ok = $r['ok'] && $r['v'] === true;                    // true = signature accepted
        $total++;
        if ($ok && !$valid) { $acc++; echo "  INVALID ACCEPTED  tcId={$x[0]}  {$x[6]}\n"; }
        if (!$ok && $valid) { $rej++; echo "  valid rejected    tcId={$x[0]} (" . ($r['ok'] ? 'false' : 'error ' . $r['err']) . ")  {$x[6]}\n"; }
    }
    echo str_pad("$name ML-DSA-$p", 34) . "  vectors=$total   INVALID ACCEPTED=$acc   valid rejected=$rej\n";
}
