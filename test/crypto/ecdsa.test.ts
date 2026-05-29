import { describe, it, expect } from 'vitest';
import { ecdsaSign, ecdsaVerify, derivePublicKey } from '../../src/crypto/ecc.ts';

// ECDSA — FIPS 186-5 · ANSI X9.62. Curves: P-256 (default), P-384, secp256k1.

describe('ECDSA — P-256 (default)', () => {
  const priv = '01'.repeat(32);
  const pub = derivePublicKey(priv);

  it('sign/verify roundtrip', () => {
    const msg = '48656c6c6f'; // "Hello"
    const sig = ecdsaSign(priv, msg);
    expect(ecdsaVerify(pub, msg, sig.r, sig.s)).toBe(true);
  });

  it('with explicit curve name', () => {
    const priv2 = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
    const pub2 = derivePublicKey(priv2);
    const msg = 'AABBCCDD';
    const { r, s } = ecdsaSign(priv2, msg);
    expect(ecdsaVerify(pub2, msg, r, s)).toBe(true);
  });
});

describe('ECDSA — P-384', () => {
  function p384Priv(): string {
    const b = new Uint8Array(48);
    crypto.getRandomValues(b);
    b[0] = 0x01;
    return Array.from(b).map(x => x.toString(16).padStart(2, '0').toUpperCase()).join('');
  }

  it('sign/verify roundtrip', () => {
    const priv = p384Priv();
    const pub = derivePublicKey(priv, 'p384');
    expect(pub.length).toBe(194); // 04 + 48*2 + 48*2 hex
    const msg = 'DEADBEEF';
    const { r, s } = ecdsaSign(priv, msg, 'p384');
    expect(ecdsaVerify(pub, msg, r, s, 'p384')).toBe(true);
  });
});

describe('ECDSA — secp256k1', () => {
  const priv = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';

  it('sign/verify roundtrip', () => {
    const pub = derivePublicKey(priv, 'secp256k1');
    expect(pub.length).toBe(130);
    const msg = 'CAFEBABE';
    const { r, s } = ecdsaSign(priv, msg, 'secp256k1');
    expect(ecdsaVerify(pub, msg, r, s, 'secp256k1')).toBe(true);
  });

  it('verify rejects key from a different curve', () => {
    const pubP256 = derivePublicKey(priv, 'p256');
    const msg = 'AABB';
    const { r, s } = ecdsaSign(priv, msg, 'secp256k1');
    expect(ecdsaVerify(pubP256, msg, r, s, 'secp256k1')).toBe(false);
  });
});
