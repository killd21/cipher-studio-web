/**
 * NIST CAVS RSA PKCS#1 v1.5 SigGen 테스트 벡터로
 * 우리 rsa.ts의 encrypt/decrypt 함수를 검증한다.
 *
 * 검증 방식:
 *   1) 서명 생성: rsa.decrypt(n, d, paddedHash) == S  (M^D mod N)
 *   2) 서명 검증: rsa.encrypt(n, e, S) == paddedHash  (S^E mod N)
 */
import { describe, it, expect } from 'vitest';
import { readFileSync } from 'fs';
import { createHash } from 'crypto';
import { encrypt, decrypt } from '../../src/crypto/rsa.ts';

// PKCS#1 v1.5 DigestInfo DER prefixes
const DIGEST_INFO_PREFIX: Record<string, string> = {
  SHA224: '302d300d06096086480165030402040500041c',
  SHA256: '3031300d060960864801650304020105000420',
  SHA384: '3041300d060960864801650304020205000430',
  SHA512: '3051300d060960864801650304020305000440',
};

function hashHex(alg: string, msgHex: string): string {
  const nodeAlg = alg.toLowerCase().replace('sha', 'sha');
  return createHash(nodeAlg).update(Buffer.from(msgHex, 'hex')).digest('hex').toUpperCase();
}

function buildPkcs1v15(alg: string, msgHex: string, modByteLen: number): string {
  const digest = hashHex(alg, msgHex);
  const digestInfo = DIGEST_INFO_PREFIX[alg]! + digest;
  const tLen = digestInfo.length / 2;
  const psLen = modByteLen - tLen - 3;
  return ('0001' + 'FF'.repeat(psLen) + '00' + digestInfo).toUpperCase();
}

// --- Parse ---
interface TestCase { alg: string; msg: string; sig: string; }
interface Section { mod: number; n: string; e: string; d: string; tests: TestCase[]; }

function parse(filepath: string): Section[] {
  const lines = readFileSync(filepath, 'utf-8').split(/\r?\n/);
  const sections: Section[] = [];
  let cur: Section | null = null;
  let tc: TestCase | null = null;

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

// --- Run ---
const sections = parse('test/fixtures/SigGen15_186-3.txt');

describe('RSA PKCS#1 v1.5 SigGen NIST Tests', () => {
  for (const sec of sections) {
    describe(`mod = ${sec.mod}`, () => {
      const modByteLen = sec.mod / 8;
      
      for (let i = 0; i < sec.tests.length; i++) {
        const t = sec.tests[i]!;
        
        it(`should verify test case #${i + 1} (${t.alg})`, () => {
          const padded = buildPkcs1v15(t.alg, t.msg, modByteLen);
          const expectedSig = t.sig.toUpperCase();

          // 1) 서명 생성: decrypt(n, d, padded) — 내부적으로 padded^D mod N
          const signed = decrypt(sec.n, sec.d, padded);

          // 2) 서명 검증: encrypt(n, e, sig) — 내부적으로 S^E mod N
          const verified = encrypt(sec.n, sec.e, t.sig);

          expect(signed).toBe(expectedSig);
          expect(verified).toBe(padded);
        });
      }
    });
  }
});

