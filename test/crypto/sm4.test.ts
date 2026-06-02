import { describe, it, expect } from 'vitest';
import { ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt } from '../../src/crypto/sm4.ts';

// SM4 — GM/T 0002 · ISO/IEC 18033-3:2010. 128-bit block, 128-bit key.

describe('SM4-ECB (GM/T 0002 standard vector)', () => {
  const key = '0123456789ABCDEFFEDCBA9876543210';
  const plaintext = '0123456789ABCDEFFEDCBA9876543210';
  const ciphertext = '681EDF34D206965E86B3E94F536E4246';

  it('encrypt matches standard vector', () => {
    expect(ecbEncrypt(key, plaintext)).toBe(ciphertext);
  });

  it('decrypt matches standard vector', () => {
    expect(ecbDecrypt(key, ciphertext)).toBe(plaintext);
  });
});

describe('SM4-ECB roundtrips', () => {
  const key = '0123456789ABCDEFFEDCBA9876543210';

  it('roundtrip 16B (no padding)', () => {
    const pt = 'AABBCCDDEEFF00112233445566778899';
    expect(ecbDecrypt(key, ecbEncrypt(key, pt))).toBe(pt);
  });

  it('roundtrip 32B (no padding)', () => {
    const pt = 'AABBCCDDEEFF00112233445566778899' + '00112233445566778899AABBCCDDEEFF';
    expect(ecbDecrypt(key, ecbEncrypt(key, pt))).toBe(pt);
  });

  it('PKCS#7 padding roundtrip (non-aligned 5B)', () => {
    const pt = '0102030405'; // 5 bytes → needs 11 bytes of 0x0B padding
    const ct = ecbEncrypt(key, pt, 'pkcs#7');
    expect(ct.length).toBe(32); // 16 bytes ciphertext
    expect(ecbDecrypt(key, ct, 'pkcs#7')).toBe(pt);
  });
});

describe('SM4-CBC', () => {
  const key = '0123456789ABCDEFFEDCBA9876543210';
  const iv = '00112233445566778899AABBCCDDEEFF';

  it('roundtrip 32B (no padding)', () => {
    const pt = 'AABBCCDDEEFF00112233445566778899' + '00112233445566778899AABBCCDDEEFF';
    expect(cbcDecrypt(key, cbcEncrypt(key, pt, iv), iv)).toBe(pt);
  });

  it('PKCS#7 padding roundtrip', () => {
    const pt = 'AABBCCDD';
    const ct = cbcEncrypt(key, pt, iv, 'pkcs#7');
    expect(cbcDecrypt(key, ct, iv, 'pkcs#7')).toBe(pt);
  });
});
