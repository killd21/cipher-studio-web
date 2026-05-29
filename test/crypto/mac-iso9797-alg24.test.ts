import { describe, it, expect } from 'vitest';
import { desMac, desMacAlg2, desMacAlg4, desTdesMac } from '../../src/crypto/mac.ts';
import { ecbEncrypt } from '../../src/crypto/des.ts';

// ISO 9797-1 Algorithm 2 / 4 structural verification tests.
// Official test vectors are in ISO 9797-1 Annex B (not freely redistributable);
// these tests instead verify algorithm-defining structural properties.

describe('ISO 9797-1 Algorithm 2 (OT1: G = E_K\'(Hn))', () => {
  const msg = '0001020304050607' + '08090A0B0C0D0E0F' + '10'; // 17B
  const iv = '0000000000000000';

  it('produces 8-byte output for 16-byte key', () => {
    const key = '0123456789ABCDEF FEDCBA9876543210'.replace(/\s/g, '');
    const result = desMacAlg2(key, msg, iv, 'iso9797m2');
    expect(result.length).toBe(16); // 8 bytes
  });

  it('accepts 8-byte key (auto-derives K\' via KDM2)', () => {
    const result = desMacAlg2('0123456789ABCDEF', msg, iv, 'iso9797m2');
    expect(result.length).toBe(16);
  });

  it('rejects malformed key length (e.g., 6 bytes)', () => {
    expect(() => desMacAlg2('001122334455', msg, iv, 'iso9797m2'))
      .toThrow();
  });

  it('structural: when K = K\', result equals E_K(Alg1_output)', () => {
    // Alg 2 with K=K' should be: E_K(CBC-MAC_K(padded))
    // i.e., one extra DES encryption of the Algorithm 1 result
    const k = '0123456789ABCDEF';
    const keyDouble = k + k; // 16 bytes, K = K'

    const alg1 = desMac(k, msg, iv, 8, 'iso9797m2'); // single DES CBC-MAC with k
    const expected = ecbEncrypt(k, alg1); // E_k(alg1)
    const alg2 = desMacAlg2(keyDouble, msg, iv, 'iso9797m2');
    expect(alg2).toBe(expected);
  });

  it('differs from Algorithm 1 when K != K\'', () => {
    const key = '11223344556677880011223344556677'; // K1 != K2
    const k1 = key.substring(0, 16);
    const alg1 = desMac(k1, msg, iv, 8, 'iso9797m2');
    const alg2 = desMacAlg2(key, msg, iv, 'iso9797m2');
    expect(alg2).not.toBe(alg1);
  });
});

describe('ISO 9797-1 Algorithm 4 (OT2: G = E_K\'(D_K(Hn)))', () => {
  const msg = '0001020304050607' + '08090A0B0C0D0E0F' + '10'; // 17B
  const iv = '0000000000000000';

  it('produces 8-byte output for 16-byte key', () => {
    const key = '0123456789ABCDEFFEDCBA9876543210';
    const result = desMacAlg4(key, msg, iv, 'iso9797m2');
    expect(result.length).toBe(16);
  });

  it('accepts 8-byte key (auto-derives K\' via KDM2)', () => {
    const result = desMacAlg4('0123456789ABCDEF', msg, iv, 'iso9797m2');
    expect(result.length).toBe(16);
  });

  it('rejects malformed key length (e.g., 6 bytes)', () => {
    expect(() => desMacAlg4('001122334455', msg, iv, 'iso9797m2'))
      .toThrow();
  });

  it('structural: when K = K\', degenerates to Algorithm 1 (because E_K(D_K(Hn)) = Hn)', () => {
    const k = '0123456789ABCDEF';
    const keyDouble = k + k;
    const alg1 = desMac(k, msg, iv, 8, 'iso9797m2');
    const alg4 = desMacAlg4(keyDouble, msg, iv, 'iso9797m2');
    expect(alg4).toBe(alg1);
  });

  it('differs from Algorithm 3 (Retail MAC) when K != K\'', () => {
    const key = '11223344556677880011223344556677';
    const alg3 = desTdesMac(key, msg, iv, 'iso9797m2');
    const alg4 = desMacAlg4(key, msg, iv, 'iso9797m2');
    expect(alg4).not.toBe(alg3);
  });
});

describe('All four DES MAC algorithms differ with K != K\'', () => {
  it('Alg 1, 2, 3, 4 produce distinct outputs', () => {
    const key = '11223344556677880011223344556677';
    const k1 = key.substring(0, 16);
    const msg = '0001020304050607080910';
    const iv = '0000000000000000';

    const alg1 = desMac(k1, msg, iv, 8, 'iso9797m2');
    const alg2 = desMacAlg2(key, msg, iv, 'iso9797m2');
    const alg3 = desTdesMac(key, msg, iv, 'iso9797m2');
    const alg4 = desMacAlg4(key, msg, iv, 'iso9797m2');

    const set = new Set([alg1, alg2, alg3, alg4]);
    expect(set.size).toBe(4); // all four are distinct
  });
});
