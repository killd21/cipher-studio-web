import { describe, it, expect } from 'vitest';
import { ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt } from '../../src/crypto/des.ts';

describe('Phase 3: DES & 3DES', () => {
  describe('DES', () => {
    it('DES ECB FIPS PUB 81 vector', () => {
      const key = '0123456789ABCDEF';
      const pt  = '4E6F772069732074'; // "Now is t"
      const expected = '3FA40E8A984D4815';
      expect(ecbEncrypt(key, pt)).toBe(expected);
    });

    it('DES CBC roundtrip', () => {
      const key = '0123456789ABCDEF';
      const iv  = '1234567890ABCDEF';
      const pt  = '4E6F772069732074';
      const ct = cbcEncrypt(key, pt, iv);
      const res = cbcDecrypt(key, ct, iv);
      expect(res).toBe(pt.toUpperCase());
    });
  });

  describe('3DES', () => {
    it('3DES (16-byte key) roundtrip', () => {
      const key = '0123456789ABCDEF0123456789ABCDEF';
      const pt  = '4E6F772069732074';
      const ct = ecbEncrypt(key, pt);
      const res = ecbDecrypt(key, ct);
      expect(res).toBe(pt.toUpperCase());
    });

    it('3DES (24-byte key) roundtrip', () => {
      const key = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF';
      const pt  = '4E6F772069732074';
      const ct = ecbEncrypt(key, pt);
      const res = ecbDecrypt(key, ct);
      expect(res).toBe(pt.toUpperCase());
    });
  });
});
