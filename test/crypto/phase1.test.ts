import { describe, it, expect } from 'vitest';
import { xor } from '../../src/crypto/bitwise.ts';
import { bytes } from '../../src/crypto/random.ts';
import { 
  iso9797m1, iso9797m2, iso9797m3, pkcs7, pkcs5, desPad, aesPad 
} from '../../src/crypto/padding.ts';

describe('Phase 1: XOR, Random, Padding', () => {
  describe('XOR', () => {
    it('should XOR two hex strings correctly', () => {
      expect(xor('AA BB', '12 34')).toBe('B88F');
    });
  });

  describe('Random', () => {
    it('should generate random hex strings of correct length', () => {
      const res1 = bytes(32);
      const res2 = bytes(32);
      expect(res1.length).toBe(64);
      expect(res2.length).toBe(64);
      expect(res1).not.toBe(res2);
    });
  });

  describe('Padding', () => {
    const data = '112233'; // 3 bytes
    
    it('ISO9797 M1', () => {
      // 3 bytes, block 8 -> pad 5 bytes of 00
      expect(iso9797m1(data, 8)).toBe('1122330000000000');
    });

    it('ISO9797 M2', () => {
      // 3 bytes, block 8 -> pad 80 00 00 00 00
      expect(iso9797m2(data, 8)).toBe('1122338000000000');
    });

    it('ISO9797 M3', () => {
      // 3 bytes -> 24 bits (0x18)
      // block 8. L is 8 bytes.
      // 24 bits = 0x18. L = 0000000000000018
      // data padded with zeros to 8: 1122330000000000
      // result: 00000000000000181122330000000000
      expect(iso9797m3(data, 8)).toBe('00000000000000181122330000000000');
    });

    it('PKCS#7', () => {
      // 3 bytes, block 8 -> pad 5 bytes of 05
      expect(pkcs7(data, 8)).toBe('1122330505050505');
    });

    it('PKCS#5', () => {
      expect(pkcs5(data)).toBe('1122330505050505');
    });

    it('desPad (M2 block 8)', () => {
      expect(desPad(data)).toBe('1122338000000000');
    });

    it('aesPad (M2 block 16)', () => {
      // 3 bytes, block 16 -> pad 80 + 12 bytes of 00
      expect(aesPad(data)).toBe('11223380' + '00'.repeat(12));
    });
  });
});
