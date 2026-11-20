// Wycheproof ML-KEM and ML-DSA vectors against npm packages with their own implementation, through their public interface.
// Usage:  node wycheproof_npm.mjs <theqrl|noqtis|quick> <directory with mlkem_*.txt and mldsa_*.txt>
//   theqrl  = @theqrl/mldsa87 (ML-DSA-87 only, pure JavaScript)
//   noqtis  = noqtis (its own C library compiled to WebAssembly; ML-KEM and ML-DSA)
//   quick   = @umbra-privacy/quick-mlkem768 (ML-KEM-768 only, pure JavaScript)
//
// Vector format (hex, fields separated by "|"), produced by mlkem_to_text.py and wycheproof_to_text.py:
//   D|tcId|result|seed d||z|ek|c|K|comment     generate the key from the seed and decapsulate c
//   E|tcId|result|m|ek|c|K|comment             encapsulate with ek and the randomness m
//   X|tcId|result|dk|c|K||comment              decapsulate with the expanded decapsulation key
//   tcId|result|public key|message|context|signature|comment      (ML-DSA, verify)
//
// Return conventions, read in each package's code (src/index.d.ts, lib/index.js, dist/mlkem768.js):
//   @theqrl/mldsa87: cryptoSignVerify(signature, message, pk, ctx) -> true if valid, false if not (also with wrong
//     lengths or a ctx longer than 255 bytes); throws TypeError if ctx is not a Uint8Array (a Uint8Array is always passed).
//   noqtis: init() must be called first (it loads noqtis.wasm). kem.keygen(alg, {seed: d||z}) -> {publicKey, secretKey};
//     kem.encap(alg, pk) -> {ciphertext, sharedSecret} with internal randomness, and kem.encap(alg, pk, {seed: m}) with
//     the given randomness ("for tests"): acceptance of the key is checked with the normal call and, for the valid
//     vectors, the output with the seeded one; kem.decap(alg, sk, c) -> K. They throw NoqtisError when they reject.
//     sign.verify(alg, pk, msg, sig, {ctx}) -> true / false (false also for a malformed signature); it throws if the
//     arguments are wrong (that counts as a rejection).
//   quick-mlkem768: deriveKeypairFromSeed(d||z) -> {publicKey, secretKey}; encapsulate(pk) with internal randomness is
//     encapsulateDeterministically(pk, random), so acceptance is checked with encapsulate() and the output with the
//     deterministic one; decapsulate(c, sk) -> K. They throw TypeError / Error when they reject.
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const [pkg, dir] = process.argv.slice(2);
const here = dirname(fileURLToPath(import.meta.url));
const version = (p) => JSON.parse(readFileSync(join(here, 'node_modules', p, 'package.json'), 'utf8')).version;
const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const same = (a, b) => !!a && !!b && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const lines = (f) => readFileSync(f, 'utf8').split('\n').filter(Boolean);
// An exception from the library is a rejection and its class is recorded; the typical faults of this program
// (ReferenceError, and a TypeError that does not come from the library) are let through.
const attempt = (f) => {
  try { return { ok: true, r: f() }; } catch (e) {
    if (e instanceof ReferenceError || (e instanceof TypeError && !/quick-mlkem768|ctx|noqtis/i.test(e.message))) throw e;
    return { ok: false, err: e?.constructor?.name ?? String(e) };
  }
};

// ---------- adapters: each one says which parameter sets it has and how each operation is done ----------
let kemSets = [], dsaSets = [], name, seed, encaps, decapsDk, verify;

if (pkg === 'theqrl') {
  const m = await import('@theqrl/mldsa87');
  name = `@theqrl/mldsa87 ${version('@theqrl/mldsa87')}`;
  dsaSets = ['87'];
  verify = (p, pk, msg, ctx, sig) => m.cryptoSignVerify(sig, msg, pk, ctx);
} else if (pkg === 'noqtis') {
  const nq = await import('noqtis');
  await nq.init();
  name = `noqtis ${version('noqtis')} (lib ${nq.version()})`;
  kemSets = ['512', '768', '1024'];
  dsaSets = ['44', '65', '87'];
  seed = (p, s, c) => { const kp = nq.kem.keygen(`ML-KEM-${p}`, { seed: s }); return { ek: kp.publicKey, K: nq.kem.decap(`ML-KEM-${p}`, kp.secretKey, c) }; };
  encaps = (p, ek, m, compare) => {
    nq.kem.encap(`ML-KEM-${p}`, ek);                              // normal interface: if it throws, the key was rejected
    if (!compare) return {};
    const r = nq.kem.encap(`ML-KEM-${p}`, ek, { seed: m });       // same computation with the vector's randomness
    return { c: r.ciphertext, K: r.sharedSecret };
  };
  decapsDk = (p, dk, c) => ({ K: nq.kem.decap(`ML-KEM-${p}`, dk, c) });
  verify = (p, pk, msg, ctx, sig) => nq.sign.verify(`ML-DSA-${p}`, pk, msg, sig, { ctx });   // empty ctx = Uint8Array(0)
} else if (pkg === 'quick') {
  const q = await import('@umbra-privacy/quick-mlkem768');
  name = `quick-mlkem768 ${version('@umbra-privacy/quick-mlkem768')}`;
  kemSets = ['768'];
  seed = (p, s, c) => { const kp = q.deriveKeypairFromSeed(s); return { ek: kp.publicKey, K: q.decapsulate(c, kp.secretKey) }; };
  encaps = (p, ek, m, compare) => {
    q.encapsulate(ek);
    if (!compare) return {};
    const r = q.encapsulateDeterministically(ek, m);
    return { c: r.ciphertext, K: r.sharedSecret };
  };
  decapsDk = (p, dk, c) => ({ K: q.decapsulate(c, dk) });
} else {
  console.log('Usage: node wycheproof_npm.mjs <theqrl|noqtis|quick> <vector directory>');
  process.exit(2);
}

// ---------- ML-KEM ----------
for (const p of kemSets) {
  const kinds = ['seed', 'encaps', 'expanded dk'];
  const n = [0, 0, 0], acc = [0, 0, 0], fail = [0, 0, 0];
  for (const l of lines(`${dir}/mlkem_${p}.txt`)) {
    const x = l.split('|');
    if (x.length < 8) continue;
    const valid = x[2] === 'valid';
    const t = 'DEX'.indexOf(x[0]);
    let r, good = false;
    if (t === 0) {
      r = attempt(() => seed(p, hex(x[3]), hex(x[5])));
      good = r.ok && same(r.r.K, hex(x[6])) && (x[4] === '' || same(r.r.ek, hex(x[4])));
    } else if (t === 1) {
      r = attempt(() => encaps(p, hex(x[4]), hex(x[3]), valid));
      good = r.ok && same(r.r.c, hex(x[5])) && same(r.r.K, hex(x[6]));
    } else {
      r = attempt(() => decapsDk(p, hex(x[3]), hex(x[4])));
      good = r.ok && same(r.r.K, hex(x[5]));
    }
    n[t]++;
    if (valid && !good) { fail[t]++; console.log(`  valid fails       [${kinds[t]}] tcId=${x[1]} (${r.ok ? 'different result' : 'error ' + r.err})  ${x[7]}`); }
    if (!valid && r.ok) { acc[t]++; console.log(`  INVALID ACCEPTED  [${kinds[t]}] tcId=${x[1]}  ${x[7]}`); }
  }
  console.log(`${name} ML-KEM-${p}`.padEnd(30) + kinds.map((s, t) => ` | ${s}: ${n[t]} vectors, INVALID ACCEPTED=${acc[t]}, valid fails=${fail[t]}`).join(''));
}

// ---------- ML-DSA ----------
for (const p of dsaSets) {
  let total = 0, acc = 0, rej = 0;
  for (const l of lines(`${dir}/mldsa_${p}.txt`)) {
    const x = l.split('|');
    if (x.length < 7) continue;
    const valid = x[1] === 'valid';
    const r = attempt(() => verify(p, hex(x[2]), hex(x[3]), hex(x[4]), hex(x[5])));
    const ok = r.ok && r.r === true;          // true = signature accepted
    total++;
    if (ok && !valid) { acc++; console.log(`  INVALID ACCEPTED  tcId=${x[0]}  ${x[6]}`); }
    if (!ok && valid) { rej++; console.log(`  valid rejected    tcId=${x[0]} (${r.ok ? 'false' : 'error ' + r.err})  ${x[6]}`); }
  }
  console.log(`${name} ML-DSA-${p}`.padEnd(34) + `  vectors=${total}   INVALID ACCEPTED=${acc}   valid rejected=${rej}`);
}
