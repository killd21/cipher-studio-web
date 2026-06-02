import { describe, it, expect } from 'vitest';
import { keygen, derivePublicKey, sign, verify, encrypt, decrypt } from '../../src/crypto/sm2.ts';

// SM2 — GM/T 0003 (signature) · ISO/IEC 18033-5 (encryption). sm2p256v1 curve.

describe('SM2 key generation', () => {
  it('produces 64-char (32B) private key and 128-char (64B) uncompressed public key', () => {
    const { publicKey, privateKey } = keygen();
    expect(privateKey).toHaveLength(64);
    // sm-crypto public key is 128 hex (without 04 prefix) — uncompressed X||Y
    expect(publicKey.length === 128 || publicKey.length === 130).toBe(true);
  });

  it('derivePublicKey matches keygen', () => {
    const { publicKey, privateKey } = keygen();
    expect(derivePublicKey(privateKey)).toBe(publicKey);
  });
});

describe('SM2 sign / verify', () => {
  it('roundtrip with default userId', () => {
    const { publicKey, privateKey } = keygen();
    const msg = '48656C6C6F20534D32'; // "Hello SM2"
    const sig = sign(privateKey, msg);
    expect(sig.length).toBeGreaterThan(0);
    expect(verify(publicKey, msg, sig)).toBe(true);
  });

  it('verify rejects altered message', () => {
    const { publicKey, privateKey } = keygen();
    const msg = '48656C6C6F';
    const sig = sign(privateKey, msg);
    expect(verify(publicKey, '48656C6C6F00', sig)).toBe(false);
  });

  it('verify rejects wrong public key', () => {
    const kp1 = keygen();
    const kp2 = keygen();
    const msg = 'AABBCCDD';
    const sig = sign(kp1.privateKey, msg);
    expect(verify(kp2.publicKey, msg, sig)).toBe(false);
  });

  it('custom userId roundtrip', () => {
    const { publicKey, privateKey } = keygen();
    const msg = 'AABB';
    const userId = '0102030405060708';
    const sig = sign(privateKey, msg, userId);
    expect(verify(publicKey, msg, sig, userId)).toBe(true);
    // Wrong userId should fail
    expect(verify(publicKey, msg, sig, '0807060504030201')).toBe(false);
  });
});

describe('SM2 encrypt / decrypt', () => {
  it('C1C3C2 (default, GM/T 0009) roundtrip', () => {
    const { publicKey, privateKey } = keygen();
    const pt = '48656C6C6F20536563726574'; // "Hello Secret"
    const ct = encrypt(publicKey, pt);
    expect(decrypt(privateKey, ct)).toBe(pt);
  });

  it('C1C2C3 (legacy) roundtrip', () => {
    const { publicKey, privateKey } = keygen();
    const pt = 'CAFEBABE';
    const ct = encrypt(publicKey, pt, 0);
    expect(decrypt(privateKey, ct, 0)).toBe(pt);
  });

  it('decrypt with wrong private key does not recover original', () => {
    const kp1 = keygen();
    const kp2 = keygen();
    const original = 'AABB';
    const ct = encrypt(kp1.publicKey, original);
    let recovered: string | null = null;
    try { recovered = decrypt(kp2.privateKey, ct); } catch { /* throw also acceptable */ }
    expect(recovered).not.toBe(original);
  });
});
