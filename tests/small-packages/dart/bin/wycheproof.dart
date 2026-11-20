// Wycheproof ML-KEM and ML-DSA vectors against pure-Dart packages from pub.dev, through their public interface.
//
// Usage:  dart run bin/wycheproof.dart <pqcrypto|cipherlib> <directory with mlkem_*.txt and mldsa_*.txt>
//
// Vector format (hex, fields separated by "|"), produced by mlkem_to_text.py and wycheproof_to_text.py:
//   D|tcId|result|seed d||z|ek|c|K|comment     generate the key from the seed and decapsulate c
//   E|tcId|result|m|ek|c|K|comment             encapsulate with ek and the randomness m
//   X|tcId|result|dk|c|K||comment              decapsulate with the expanded decapsulation key
//   tcId|result|public key|message|context|signature|comment      (ML-DSA, verify)
//
// Return conventions, read in each package's code (nothing with a leading underscore is called):
//   pqcrypto 0.4.x (lib/src/algos/kyber/kem.dart and lib/src/algos/dilithium/dsa.dart):
//     PqcKem.kyberXXX.generateKeyPair(seed) -> (pk, sk); 64-byte seed = d||z (it also takes 32 = d, with a random z).
//     encapsulate(pk, m) -> (c, K); the randomness m is an optional public parameter.
//     decapsulate(sk, c) -> K. All three throw ArgumentError when they reject.
//     MlDsa.verify(pk, m, signature, parameters, ctx: context) -> bool; according to its documentation it never
//     throws: it returns false on any malformed input.
//   cipherlib 0.7.x (lib/src/algorithms/mlkem/mlkem.dart):
//     MLKEM.kemXXX().keygen(seed: d||z) -> KEMKeyPair(encapsulationKey, decapsulationKey).
//     encaps(ek) -> KEMSecret(cipherText, sharedSecret) with internal randomness; it is exactly $encaps(ek, random),
//     so acceptance of the key is checked with encaps() and, for the valid vectors, the output is compared with
//     $encaps(ek, m), which the package exposes (no leading underscore) for test vectors.
//     decaps(dk, c) -> HashDigest (.bytes). They throw ArgumentError when they reject.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import 'dart:io';
import 'dart:typed_data';

import 'package:cipherlib/cipherlib.dart' as cl;
import 'package:pqcrypto/pqcrypto.dart' as pq;

const kinds = ['seed', 'encaps', 'expanded dk'];

Uint8List h(String s) {
  final b = Uint8List(s.length ~/ 2);
  for (var i = 0; i < b.length; i++) {
    b[i] = int.parse(s.substring(2 * i, 2 * i + 2), radix: 16);
  }
  return b;
}

bool same(List<int>? a, List<int>? b) {
  if (a == null || b == null || a.length != b.length) return false;
  for (var i = 0; i < a.length; i++) {
    if (a[i] != b[i]) return false;
  }
  return true;
}

/// Version of a package according to pubspec.lock (what "dart pub get" actually resolved).
String version(String package) {
  try {
    final l = File('pubspec.lock').readAsLinesSync();
    final i = l.indexWhere((x) => x == '  $package:');
    for (var j = i + 1; j < l.length && j < i + 10; j++) {
      final m = RegExp(r'^    version: "(.*)"$').firstMatch(l[j]);
      if (m != null) return m.group(1)!;
    }
  } catch (_) {}
  return '?';
}

/// Result of an operation: ok = the library did it without error; whatever outputs there are.
class Res {
  final bool ok;
  final Uint8List? ek, c, k;
  final String? err;
  const Res(this.ok, {this.ek, this.c, this.k, this.err});
}

/// Runs the operation; an error or exception from the library is a rejection and its class is recorded.
/// The typical faults of this program (NoSuchMethodError, TypeError) are not counted as rejections: they are let through.
Res attempt(Res Function() f) {
  try {
    return f();
  } on NoSuchMethodError {
    rethrow;
  } on TypeError {
    rethrow;
  } catch (e) {
    return Res(false, err: e.runtimeType.toString());
  }
}

abstract class Adapter {
  String get name;
  Res seed(Uint8List seed, Uint8List c);
  Res encaps(Uint8List ek, Uint8List m, bool compare);
  Res decapsDk(Uint8List dk, Uint8List c);
  bool? verify(int p, Uint8List pk, Uint8List msg, Uint8List ctx, Uint8List sig) => null; // null = no interface
  bool get hasDsa => false;
}

class PqcryptoKem extends Adapter {
  final pq.KyberKem kem;
  PqcryptoKem(int p) : kem = {512: pq.PqcKem.kyber512, 768: pq.PqcKem.kyber768, 1024: pq.PqcKem.kyber1024}[p]!;
  @override
  String get name => 'pqcrypto (Dart) ${version('pqcrypto')}';
  @override
  Res seed(Uint8List seed, Uint8List c) {
    final (pk, sk) = kem.generateKeyPair(seed);
    return Res(true, ek: pk, k: kem.decapsulate(sk, c));
  }

  @override
  Res encaps(Uint8List ek, Uint8List m, bool compare) {
    final (ct, ss) = kem.encapsulate(ek, m);
    return Res(true, c: ct, k: ss);
  }

  @override
  Res decapsDk(Uint8List dk, Uint8List c) => Res(true, k: kem.decapsulate(dk, c));
}

class PqcryptoDsa extends Adapter {
  @override
  String get name => 'pqcrypto (Dart) ${version('pqcrypto')}';
  @override
  bool get hasDsa => true;
  @override
  Res seed(Uint8List seed, Uint8List c) => throw UnimplementedError();
  @override
  Res encaps(Uint8List ek, Uint8List m, bool compare) => throw UnimplementedError();
  @override
  Res decapsDk(Uint8List dk, Uint8List c) => throw UnimplementedError();
  @override
  bool? verify(int p, Uint8List pk, Uint8List msg, Uint8List ctx, Uint8List sig) {
    final par = {44: pq.DilithiumParams.mlDsa44, 65: pq.DilithiumParams.mlDsa65, 87: pq.DilithiumParams.mlDsa87}[p]!;
    return pq.MlDsa.verify(pk, msg, sig, par, ctx: ctx);   // empty context = Uint8List(0), as FIPS 204 requires
  }
}

class CipherlibKem extends Adapter {
  final cl.MLKEM kem;
  CipherlibKem(int p) : kem = {512: cl.MLKEM.kem512, 768: cl.MLKEM.kem768, 1024: cl.MLKEM.kem1024}[p]!();
  @override
  String get name => 'cipherlib (Dart) ${version('cipherlib')}';
  @override
  Res seed(Uint8List seed, Uint8List c) {
    final pair = kem.keygen(seed: seed);
    return Res(true, ek: pair.encapsulationKey, k: kem.decaps(pair.decapsulationKey, c).bytes);
  }

  @override
  Res encaps(Uint8List ek, Uint8List m, bool compare) {
    kem.encaps(ek); // normal interface: if it throws, the key was rejected
    if (!compare) return const Res(true);
    final s = kem.$encaps(ek, m); // same path with the vector's randomness, to compare c and K
    return Res(true, c: s.cipherText, k: s.sharedSecret.bytes);
  }

  @override
  Res decapsDk(Uint8List dk, Uint8List c) => Res(true, k: kem.decaps(dk, c).bytes);
}

void testKem(Adapter ad, String path, int p) {
  final n = [0, 0, 0], acc = [0, 0, 0], fail = [0, 0, 0];
  for (final line in File(path).readAsLinesSync()) {
    final x = line.split('|');
    if (x.length < 8) continue;
    final t = 'DEX'.indexOf(x[0]);
    final valid = x[2] == 'valid';
    late Res r;
    var good = false;
    if (t == 0) {
      r = attempt(() => ad.seed(h(x[3]), h(x[5])));
      good = r.ok && same(r.k, h(x[6])) && (x[4].isEmpty || same(r.ek, h(x[4])));
    } else if (t == 1) {
      r = attempt(() => ad.encaps(h(x[4]), h(x[3]), valid));
      good = r.ok && same(r.c, h(x[5])) && same(r.k, h(x[6]));
    } else {
      r = attempt(() => ad.decapsDk(h(x[3]), h(x[4])));
      good = r.ok && same(r.k, h(x[5]));
    }
    n[t]++;
    if (valid && !good) {
      fail[t]++;
      print('  valid fails       [${kinds[t]}] tcId=${x[1]} (${r.ok ? 'different result' : 'error ${r.err}'})  ${x[7]}');
    }
    if (!valid && r.ok) {
      acc[t]++;
      print('  INVALID ACCEPTED  [${kinds[t]}] tcId=${x[1]}  ${x[7]}');
    }
  }
  var s = '${ad.name.padRight(30)} ML-KEM-${p.toString().padRight(4)}';
  for (var t = 0; t < 3; t++) {
    s += ' | ${kinds[t]}: ${n[t]} vectors, INVALID ACCEPTED=${acc[t]}, valid fails=${fail[t]}';
  }
  print(s);
}

void testDsa(Adapter ad, String path, int p) {
  var total = 0, acc = 0, rej = 0;
  for (final line in File(path).readAsLinesSync()) {
    final x = line.split('|');
    if (x.length < 7) continue;
    final valid = x[1] == 'valid';
    bool ok;
    String? err;
    try {
      ok = ad.verify(p, h(x[2]), h(x[3]), h(x[4]), h(x[5])) == true;   // true = signature accepted
    } on NoSuchMethodError {
      rethrow;
    } on TypeError {
      rethrow;
    } catch (e) {
      ok = false;
      err = e.runtimeType.toString();
    }
    total++;
    if (ok && !valid) {
      acc++;
      print('  INVALID ACCEPTED  tcId=${x[0]}  ${x[6]}');
    }
    if (!ok && valid) {
      rej++;
      print('  valid rejected    tcId=${x[0]} (${err == null ? 'false' : 'error $err'})  ${x[6]}');
    }
  }
  print('${ad.name.padRight(34)} ML-DSA-$p  vectors=$total   INVALID ACCEPTED=$acc   valid rejected=$rej');
}

void main(List<String> a) {
  if (a.length < 2) {
    print('Usage: dart run bin/wycheproof.dart <pqcrypto|cipherlib> <vector directory>');
    exit(2);
  }
  final package = a[0], dir = a[1];
  for (final p in [512, 768, 1024]) {
    final ad = package == 'pqcrypto' ? PqcryptoKem(p) : CipherlibKem(p);
    testKem(ad, '$dir/mlkem_$p.txt', p);
  }
  if (package == 'pqcrypto') {
    for (final p in [44, 65, 87]) {
      testDsa(PqcryptoDsa(), '$dir/mldsa_$p.txt', p);
    }
  }
}
