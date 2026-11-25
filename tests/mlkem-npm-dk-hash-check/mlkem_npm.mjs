// Runs the Wycheproof ML-KEM vectors (text form, see mlkem_to_text.py) against one installed version of the npm
// package "mlkem", through its public interface.
// Usage:  node mlkem_npm.mjs <npm alias of the installed version> <directory with the vectors>
//
// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.
import { readFileSync } from 'node:fs';

const [alias, dir] = process.argv.slice(2);
const { MlKem512, MlKem768, MlKem1024 } = await import(alias);
const version = JSON.parse(readFileSync(`node_modules/${alias}/package.json`, 'utf8')).version;
const hex = (s) => Uint8Array.from(Buffer.from(s, 'hex'));
const same = (a, b) => a && b && Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
const attempt = async (f) => { try { return await f(); } catch { return undefined; } };

for (const [p, C] of [['512', MlKem512], ['768', MlKem768], ['1024', MlKem1024]]) {
  const kinds = ['seed decaps', 'encaps', 'expanded dk'];
  const n = [0, 0, 0], accepted = [0, 0, 0], failed = [0, 0, 0];
  for (const l of readFileSync(`${dir}/mlkem_${p}.txt`, 'utf8').split('\n').filter(Boolean)) {
    const x = l.split('|');
    if (x.length < 8) continue;
    const expected = x[2] === 'valid';
    const k = new C();
    let t, ok = false, good = false;
    if (x[0] === 'D') {            // key generation from the 64-byte seed, then decapsulation
      t = 0;
      const seed = hex(x[3]);
      const r = seed.length === 64 ? await attempt(async () => { const [pk, sk] = await k.deriveKeyPair(seed); return [pk, await k.decap(hex(x[5]), sk)]; }) : undefined;
      ok = r !== undefined;
      good = ok && same(r[1], hex(x[6])) && (x[4] === '' || same(r[0], hex(x[4])));
    } else if (x[0] === 'E') {     // encapsulation with the given key and randomness
      t = 1;
      const m = hex(x[3]);
      const r = m.length === 32 ? await attempt(() => k.encap(hex(x[4]), m)) : undefined;
      ok = r !== undefined;
      good = ok && same(r[0], hex(x[5])) && same(r[1], hex(x[6]));
    } else {                       // decapsulation with an expanded decapsulation key
      t = 2;
      const r = await attempt(() => k.decap(hex(x[4]), hex(x[3])));
      ok = r !== undefined;
      good = ok && same(r, hex(x[5]));
    }
    n[t]++;
    if (expected && !good) { failed[t]++; console.log(`  VALID FAILED      [${kinds[t]}] tcId=${x[1]}  ${x[7]}`); }
    if (!expected && ok) { accepted[t]++; console.log(`  INVALID ACCEPTED  [${kinds[t]}] tcId=${x[1]}  ${x[7]}`); }
  }
  console.log(`mlkem ${version} ML-KEM-${p}`.padEnd(26) + kinds.map((s, t) => ` | ${s}: ${n[t]} vectors, INVALID ACCEPTED=${accepted[t]}, VALID FAILED=${failed[t]}`).join(''));
}
