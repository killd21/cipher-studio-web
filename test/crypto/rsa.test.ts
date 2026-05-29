import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { createHash } from 'crypto';
import { encrypt, decrypt, crtDecrypt, crtToStandard } from '../../src/crypto/rsa.ts';

// RSA — PKCS #1 · RFC 8017. Raw modular exponentiation + CRT support.

describe('RSA — basic encrypt / decrypt', () => {
  // Tiny RSA key for fast testing (16-bit prime).
  // n = p*q, p=11, q=13 → n=143; e=7, d=103 (7*103 mod 120 = 1)
  // hex: n=8F, e=07, d=67
  const n = '8F';
  const e = '07';
  const d = '67';

  it('encrypt then decrypt roundtrip', () => {
    const m = '05'; // plaintext < n
    const c = encrypt(n, e, m);
    expect(decrypt(n, d, c)).toBe(m);
  });
});

describe('RSA — CRT', () => {
  it('crtToStandard derives (n, d) from (p, q, e)', () => {
    const p = '0B'; // 11
    const q = '0D'; // 13
    const e = '07';
    const res = crtToStandard(p, q, e);
    // n = 11*13 = 143 = 0x8F
    expect(BigInt('0x' + res.n)).toBe(143n);
    // d = e^-1 mod φ(n) = 7^-1 mod 120 = 103
    expect(BigInt('0x' + res.d)).toBe(103n);
  });

  it('crtDecrypt reproduces the standard decryption result', () => {
    // Use the same small key as basic test
    const p = '0B'; const q = '0D'; const e = '07';
    const n = '8F'; const d = '67';
    const m = '05';
    const c = encrypt(n, e, m);

    // Compute dP, dQ, qInv
    const pN = 11n, qN = 13n, dN = 103n;
    const dP = dN % (pN - 1n);
    const dQ = dN % (qN - 1n);
    // qInv = q^-1 mod p
    function modInv(a: bigint, m: bigint): bigint {
      let [old_r, r] = [((a % m) + m) % m, m];
      let [old_s, s] = [1n, 0n];
      while (r !== 0n) {
        const qq = old_r / r;
        [old_r, r] = [r, old_r - qq * r];
        [old_s, s] = [s, old_s - qq * s];
      }
      return ((old_s % m) + m) % m;
    }
    const qInv = modInv(qN, pN);
    const toHex = (x: bigint) => x.toString(16).toUpperCase();
    const crt = crtDecrypt(toHex(pN), toHex(qN), toHex(dP), toHex(dQ), toHex(qInv), c);
    expect(BigInt('0x' + crt)).toBe(BigInt('0x' + m));
  });
});

// ═══════════════════════════════════════════════════════════════
// NIST CAVS RSA PKCS#1 v1.5 SigGen vectors (test/fixtures/SigGen15_186-3.txt)
// Verifies:
//   1) sign:   rsa.decrypt(n, d, paddedHash) == S   (M^D mod N)
//   2) verify: rsa.encrypt(n, e, S) == paddedHash   (S^E mod N)
// Skipped automatically when the fixture file is absent.
// ═══════════════════════════════════════════════════════════════

const DIGEST_INFO_PREFIX: Record<string, string> = {
  SHA224: '302d300d06096086480165030402040500041c',
  SHA256: '3031300d060960864801650304020105000420',
  SHA384: '3041300d060960864801650304020205000430',
  SHA512: '3051300d060960864801650304020305000440',
};

function hashHex(alg: string, msgHex: string): string {
  return createHash(alg.toLowerCase()).update(Buffer.from(msgHex, 'hex')).digest('hex').toUpperCase();
}

function buildPkcs1v15(alg: string, msgHex: string, modByteLen: number): string {
  const digest = hashHex(alg, msgHex);
  const digestInfo = DIGEST_INFO_PREFIX[alg]! + digest;
  const tLen = digestInfo.length / 2;
  const psLen = modByteLen - tLen - 3;
  return ('0001' + 'FF'.repeat(psLen) + '00' + digestInfo).toUpperCase();
}

interface SigGenTestCase { alg: string; msg: string; sig: string; }
interface SigGenSection { mod: number; n: string; e: string; d: string; tests: SigGenTestCase[]; }

function parseSigGen(filepath: string): SigGenSection[] {
  const lines = readFileSync(filepath, 'utf-8').split(/\r?\n/);
  const sections: SigGenSection[] = [];
  let cur: SigGenSection | null = null;
  let tc: SigGenTestCase | null = null;
  for (const line of lines) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const mm = t.match(/^\[mod\s*=\s*(\d+)\]/);
    if (mm) { cur = { mod: +mm[1]!, n: '', e: '', d: '', tests: [] }; sections.push(cur); continue; }
    if (!cur) continue;
    if (t.startsWith('n = ')) { cur.n = t.slice(4).trim(); continue; }
    if (t.startsWith('e = ')) { cur.e = t.slice(4).trim(); continue; }
    if (t.startsWith('d = ')) { cur.d = t.slice(4).trim(); continue; }
    if (t.startsWith('SHAAlg = ')) { tc = { alg: t.slice(9).trim(), msg: '', sig: '' }; cur.tests.push(tc); continue; }
    if (tc && t.startsWith('Msg = ')) { tc.msg = t.slice(6).trim(); continue; }
    if (tc && t.startsWith('S = '))   { tc.sig = t.slice(4).trim(); continue; }
  }
  return sections;
}

const fixturePath = 'test/fixtures/SigGen15_186-3.txt';
const sections = existsSync(fixturePath) ? parseSigGen(fixturePath) : [];

describe.skipIf(sections.length === 0)('RSA PKCS#1 v1.5 SigGen — NIST CAVS', () => {
  for (const sec of sections) {
    describe(`mod = ${sec.mod}`, () => {
      const modByteLen = sec.mod / 8;
      for (let i = 0; i < sec.tests.length; i++) {
        const t = sec.tests[i]!;
        it(`test case #${i + 1} (${t.alg})`, () => {
          const padded = buildPkcs1v15(t.alg, t.msg, modByteLen);
          const expectedSig = t.sig.toUpperCase();
          const signed = decrypt(sec.n, sec.d, padded);
          const verified = encrypt(sec.n, sec.e, t.sig);
          expect(signed).toBe(expectedSig);
          expect(verified).toBe(padded);
        });
      }
    });
  }
});
