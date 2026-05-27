import { describe, it, expect } from 'vitest';
import { digest } from '../../src/crypto/hash.ts';
import { ecbEncrypt, cbcEncrypt, cbcDecrypt, ctrEncrypt } from '../../src/crypto/aes.ts';

describe('Phase 2: Hash & AES', () => {
  describe('Hash', () => {
    it('SHA-256 of empty string', async () => {
      const res = await digest('sha256', '');
      expect(res).toBe('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855');
    });

    it('SHA-1 of "abc" (616263)', async () => {
      const res = await digest('sha1', '616263');
      expect(res).toBe('A9993E364706816ABA3E25717850C26C9CD0D89D');
    });

    it('MD5 of empty string', async () => {
      const res = await digest('md5', '');
      expect(res).toBe('D41D8CD98F00B204E9800998ECF8427E');
    });
  });

  describe('AES', () => {
    it('NIST AES-128 ECB test vector', () => {
      const key = '2b7e151628aed2a6abf7158809cf4f3c';
      const pt  = '6bc1bee22e409f96e93d7e117393172a';
      const expected = '3AD77BB40D7A3660A89ECAF32466EF97';
      expect(ecbEncrypt(key, pt)).toBe(expected);
    });

    it('AES-128 CBC roundtrip', () => {
      const key = '2b7e151628aed2a6abf7158809cf4f3c';
      const iv  = '000102030405060708090a0b0c0d0e0f';
      const pt  = '6bc1bee22e409f96e93d7e117393172a';
      const ct = cbcEncrypt(key, pt, iv);
      const res = cbcDecrypt(key, ct, iv);
      expect(res).toBe(pt.toUpperCase());
    });

    it('AES-128 CTR roundtrip', () => {
      const key = '2b7e151628aed2a6abf7158809cf4f3c';
      const iv  = '000102030405060708090a0b0c0d0e0f';
      const pt  = '6bc1bee22e409f96e93d7e117393172a';
      const ct = ctrEncrypt(key, pt, iv);
      const res = ctrEncrypt(key, ct, iv); // CTR is symmetric
      expect(res).toBe(pt.toUpperCase());
    });
  });
});
