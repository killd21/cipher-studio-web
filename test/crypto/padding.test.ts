import { describe, it, expect } from 'vitest';
import {
  iso9797m1, iso9797m2, iso9797m3, pkcs7, pkcs5, desPad, aesPad,
} from '../../src/crypto/padding.ts';

// Padding methods — ISO/IEC 9797-1 M1/M2/M3, PKCS #5/#7.

describe('Padding', () => {
  const data = '112233'; // 3 bytes

  it('ISO 9797-1 M1 (zero pad to block boundary)', () => {
    expect(iso9797m1(data, 8)).toBe('1122330000000000');
  });

  it('ISO 9797-1 M2 (0x80 + zero pad)', () => {
    expect(iso9797m2(data, 8)).toBe('1122338000000000');
  });

  it('ISO 9797-1 M3 (length prefix + M1)', () => {
    // 3 bytes = 24 bits = 0x18. L block = 0000000000000018.
    // Data zero-padded to 1122330000000000.
    expect(iso9797m3(data, 8)).toBe('00000000000000181122330000000000');
  });

  it('PKCS#7 (block 8) — pads with 0x05 × 5', () => {
    expect(pkcs7(data, 8)).toBe('1122330505050505');
  });

  it('PKCS#5 (8-byte block alias)', () => {
    expect(pkcs5(data)).toBe('1122330505050505');
  });

  it('desPad alias = M2 block 8', () => {
    expect(desPad(data)).toBe('1122338000000000');
  });

  it('aesPad alias = M2 block 16', () => {
    expect(aesPad(data)).toBe('11223380' + '00'.repeat(12));
  });
});
