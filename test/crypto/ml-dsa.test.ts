import { describe, it, expect } from 'vitest';
import { dsaKeygen, dsaSign, dsaVerify } from '../../src/crypto/pqc.ts';

// ML-DSA — FIPS 204. Variants: 44, 65, 87.

describe('ML-DSA-65', () => {
  it('keygen / sign / verify roundtrip', () => {
    const { publicKey, secretKey } = dsaKeygen(65);
    const msg = '48656c6c6f';
    const sig = dsaSign(65, secretKey, msg);
    expect(dsaVerify(65, publicKey, msg, sig)).toBe(true);
  });

  it('verify rejects altered message', () => {
    const { publicKey, secretKey } = dsaKeygen(65);
    const msg = '48656c6c6f';
    const sig = dsaSign(65, secretKey, msg);
    expect(dsaVerify(65, publicKey, msg + '00', sig)).toBe(false);
  });
});
