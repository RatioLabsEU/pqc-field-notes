// Run the Wycheproof ML-KEM vectors against one installed version of @noble/post-quantum.
// Usage:  node noble.mjs <installed package name> <dir with mlkem_512.txt, mlkem_768.txt, mlkem_1024.txt>
//   e.g.  node noble.mjs n054 ~/pqc-lab-work/vectors      (npm alias for version 0.5.4)
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import { readFileSync } from 'node:fs';

const [pkg, dir] = process.argv.slice(2);
const version = JSON.parse(readFileSync(`node_modules/${pkg}/package.json`, 'utf8')).version;
const load = async (m) => {
  for (const s of [`${pkg}/${m}.js`, `${pkg}/${m}`]) {
    try { return await import(s); } catch { /* try the next form */ }
  }
  return null;
};
const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const same = (a, b) => a && b && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const attempt = (f) => { try { return f(); } catch { return undefined; } };

const kem = await load('ml-kem');
if (!kem) { console.log(`@noble/post-quantum ${version}: no ml-kem module`); process.exit(0); }
for (const p of ['512', '768', '1024']) {
  const k = kem[`ml_kem${p}`];
  if (!k) continue;
  const kinds = ['seed decaps', 'encaps', 'expanded dk'];
  const n = [0, 0, 0], accepted = [0, 0, 0], failed = [0, 0, 0];
  for (const line of readFileSync(`${dir}/mlkem_${p}.txt`, 'utf8').split('\n').filter(Boolean)) {
    const x = line.split('|');
    if (x.length < 8) continue;
    const expected = x[2] === 'valid';
    let t, ok = false, good = false;
    if (x[0] === 'D') {
      t = 0;
      const seed = hex(x[3]);
      const r = seed.length === 64 ? attempt(() => { const kp = k.keygen(seed); return [kp.publicKey, k.decapsulate(hex(x[5]), kp.secretKey)]; }) : undefined;
      ok = r !== undefined;
      good = ok && same(r[1], hex(x[6])) && (x[4] === '' || same(r[0], hex(x[4])));
    } else if (x[0] === 'E') {
      t = 1;
      const m = hex(x[3]);
      const r = m.length === 32 ? attempt(() => k.encapsulate(hex(x[4]), m)) : undefined;
      ok = r !== undefined;
      good = ok && same(r.cipherText, hex(x[5])) && same(r.sharedSecret, hex(x[6]));
    } else {
      t = 2;
      const r = attempt(() => k.decapsulate(hex(x[4]), hex(x[3])));
      ok = r !== undefined;
      good = ok && same(r, hex(x[5]));
    }
    n[t]++;
    if (expected && !good) { failed[t]++; console.log(`  VALID FAILED      [${kinds[t]}] tcId=${x[1]}  ${x[7]}`); }
    if (!expected && ok) { accepted[t]++; console.log(`  INVALID ACCEPTED  [${kinds[t]}] tcId=${x[1]}  ${x[7]}`); }
  }
  console.log(`@noble/post-quantum ${version} ML-KEM-${p}`.padEnd(40) + kinds.map((s, t) => ` | ${s}: ${n[t]} vectors, INVALID ACCEPTED=${accepted[t]}, VALID FAILED=${failed[t]}`).join(''));
}
