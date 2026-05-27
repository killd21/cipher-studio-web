import { describe, it, expect } from 'vitest';
import { 
  ecdhComputeSecret, ecdsaSign, ecdsaVerify, ecSdsaSign, ecSdsaVerify, derivePublicKey 
} from '../../src/crypto/ecc.ts';

describe('Phase 6: ECC', () => {
  const privA = '01'.repeat(32);
  const privB = '02'.repeat(32);
  const pubA = derivePublicKey(privA);
  const pubB = derivePublicKey(privB);

  it('ECDH shared secret consistency', () => {
    const s1 = ecdhComputeSecret(privA, pubB);
    const s2 = ecdhComputeSecret(privB, pubA);
    expect(s1).toBe(s2);
  });

  it('ECDSA roundtrip', () => {
    const msg = '48656c6c6f'; // "Hello"
    const sig = ecdsaSign(privA, msg);
    const ok = ecdsaVerify(pubA, msg, sig.r, sig.s);
    expect(ok).toBe(true);
  });

  it('EC-SDSA roundtrip', () => {
    const msg = '48656c6c6f';
    const sig = ecSdsaSign(privA, msg);
    const ok = ecSdsaVerify(pubA, msg, sig.e, sig.s);
    expect(ok).toBe(true);
  });

  it('EC-SDSA verification should fail with wrong message', () => {
    const msg = '48656c6c6f';
    const sig = ecSdsaSign(privA, msg);
    const ok = ecSdsaVerify(pubA, msg + '00', sig.e, sig.s);
    expect(ok).toBe(false);
  });
});
