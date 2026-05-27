import { describe, it, expect } from 'vitest';
import { ecbEncrypt as ariaEcb, cbcEncrypt as ariaCbc, ecbDecrypt as ariaDec } from '../../src/crypto/aria.ts';
import { ecbEncrypt as seedEcb, cbcEncrypt as seedCbc, ecbDecrypt as seedDec } from '../../src/crypto/seed.ts';

describe('Phase 5: ARIA & SEED', () => {
  describe('ARIA', () => {
    it('ARIA-128 ECB test vector (RFC 5794)', () => {
      const key = '000102030405060708090A0B0C0D0E0F';
      const pt  = '00112233445566778899AABBCCDDEEFF';
      const expected = 'D718FBD6AB644C739DA95F3BE6451778';
      expect(ariaEcb(key, pt)).toBe(expected);
    });

    it('ARIA roundtrip', () => {
      const key = '000102030405060708090A0B0C0D0E0F';
      const pt  = '00112233445566778899AABBCCDDEEFF';
      const ct = ariaEcb(key, pt);
      expect(ariaDec(key, ct)).toBe(pt.toUpperCase());
    });
  });

  describe('SEED', () => {
    it('SEED ECB test vector (RFC 4269)', () => {
      const key = '00000000000000000000000000000000';
      const pt  = '000102030405060708090A0B0C0D0E0F';
      const expected = '5EBAC6E0054E166819AFF1CC6D346CDB';
      expect(seedEcb(key, pt)).toBe(expected);
    });

    it('SEED roundtrip', () => {
      const key = '000102030405060708090A0B0C0D0E0F';
      const pt  = '00112233445566778899AABBCCDDEEFF';
      const ct = seedEcb(key, pt);
      expect(seedDec(key, ct)).toBe(pt.toUpperCase());
    });
  });
});
