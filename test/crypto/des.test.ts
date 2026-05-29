import { describe, it, expect } from 'vitest';
import { ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt } from '../../src/crypto/des.ts';

// DES / 3DES — FIPS 46-3 · NIST SP 800-67. Single 8B / 2-key 16B / 3-key 24B.

describe('DES (single, 8-byte key)', () => {
  it('ECB vector (FIPS PUB 81)', () => {
    expect(ecbEncrypt('0123456789ABCDEF', '4E6F772069732074')).toBe('3FA40E8A984D4815');
  });

  it('CBC roundtrip', () => {
    const key = '0123456789ABCDEF';
    const iv = '1234567890ABCDEF';
    const pt = '4E6F772069732074';
    expect(cbcDecrypt(key, cbcEncrypt(key, pt, iv), iv)).toBe(pt.toUpperCase());
  });
});

describe('3DES', () => {
  const pt = '4E6F772069732074';

  it('2-key 3DES (16-byte key) roundtrip', () => {
    const key = '0123456789ABCDEF0123456789ABCDEF';
    expect(ecbDecrypt(key, ecbEncrypt(key, pt))).toBe(pt.toUpperCase());
  });

  it('3-key 3DES (24-byte key) roundtrip', () => {
    const key = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF';
    expect(ecbDecrypt(key, ecbEncrypt(key, pt))).toBe(pt.toUpperCase());
  });
});
