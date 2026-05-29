import { describe, it, expect } from 'vitest';
import { ecbEncrypt, ecbDecrypt } from '../../src/crypto/aria.ts';

// ARIA — RFC 5794 · KS X 1213. 128-bit block, 128/192/256-bit key.

describe('ARIA', () => {
  it('ARIA-128 ECB test vector (RFC 5794)', () => {
    expect(ecbEncrypt('000102030405060708090A0B0C0D0E0F', '00112233445566778899AABBCCDDEEFF'))
      .toBe('D718FBD6AB644C739DA95F3BE6451778');
  });

  it('ARIA-128 ECB roundtrip', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    const pt = '00112233445566778899AABBCCDDEEFF';
    expect(ecbDecrypt(key, ecbEncrypt(key, pt))).toBe(pt.toUpperCase());
  });
});
