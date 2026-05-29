import { describe, it, expect } from 'vitest';
import { ecSdsaSign, ecSdsaVerify, derivePublicKey } from '../../src/crypto/ecc.ts';

// EC-SDSA (EC-Schnorr) — ISO/IEC 14888-3. secp256r1 (P-256) only.

describe('EC-SDSA (P-256)', () => {
  const priv = '01'.repeat(32);
  const pub = derivePublicKey(priv);
  const msg = '48656c6c6f';

  it('sign/verify roundtrip', () => {
    const sig = ecSdsaSign(priv, msg);
    expect(ecSdsaVerify(pub, msg, sig.e, sig.s)).toBe(true);
  });

  it('verify rejects tampered message', () => {
    const sig = ecSdsaSign(priv, msg);
    expect(ecSdsaVerify(pub, msg + '00', sig.e, sig.s)).toBe(false);
  });
});
