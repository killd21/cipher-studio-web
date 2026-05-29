import { describe, it, expect } from 'vitest';
import { slhKeygen, slhSign, slhVerify } from '../../src/crypto/pqc.ts';

// SLH-DSA — FIPS 205 (SPHINCS+ family). Hash-based signatures, slow keygen.

describe('SLH-DSA', () => {
  it('SHAKE-128f keygen produces valid keys', { timeout: 30000 }, () => {
    const { publicKey, secretKey } = slhKeygen('shake-128f');
    expect(publicKey.length).toBe(64);
    expect(secretKey.length).toBe(128);
  });

  it('SHAKE-128f sign / verify roundtrip', { timeout: 60000 }, () => {
    const { publicKey, secretKey } = slhKeygen('shake-128f');
    const msg = '48656C6C6F20576F726C64';
    const sig = slhSign('shake-128f', secretKey, msg);
    expect(sig.length).toBeGreaterThan(0);
    expect(slhVerify('shake-128f', publicKey, msg, sig)).toBe(true);
  });

  it('SHA2-128f sign / verify roundtrip', { timeout: 60000 }, () => {
    const { publicKey, secretKey } = slhKeygen('sha2-128f');
    const msg = 'CAFEBABE';
    expect(slhVerify('sha2-128f', publicKey, msg, slhSign('sha2-128f', secretKey, msg))).toBe(true);
  });

  it('verify rejects tampered message', { timeout: 60000 }, () => {
    const { publicKey, secretKey } = slhKeygen('shake-128f');
    const msg = 'AABBCCDD';
    const sig = slhSign('shake-128f', secretKey, msg);
    expect(slhVerify('shake-128f', publicKey, msg + '00', sig)).toBe(false);
  });

  it('throws on unknown variant', () => {
    expect(() => slhKeygen('invalid' as any)).toThrow('Unknown SLH-DSA variant');
  });
});
