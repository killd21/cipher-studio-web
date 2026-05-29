import { describe, it, expect } from 'vitest';
import { ecbEncrypt, ecbDecrypt } from '../../src/crypto/seed.ts';

// SEED — RFC 4269 · TTAS.KO-12.0004. 128-bit block, 128-bit key.

describe('SEED', () => {
  it('SEED ECB test vector (RFC 4269)', () => {
    expect(ecbEncrypt('00000000000000000000000000000000', '000102030405060708090A0B0C0D0E0F'))
      .toBe('5EBAC6E0054E166819AFF1CC6D346CDB');
  });

  it('SEED ECB roundtrip', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    const pt = '00112233445566778899AABBCCDDEEFF';
    expect(ecbDecrypt(key, ecbEncrypt(key, pt))).toBe(pt.toUpperCase());
  });
});
