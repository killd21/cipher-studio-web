import { describe, it, expect } from 'vitest';
import {
  ed25519Keygen, ed25519Sign, ed25519Verify, ed25519DerivePublicKey,
} from '../../src/crypto/ecc.ts';

// Ed25519 — RFC 8032. Curve25519 (Edwards form).

describe('Ed25519', () => {
  it('keygen produces 32-byte key pair', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    expect(secretKey.length).toBe(64);
    expect(publicKey.length).toBe(64);
  });

  it('sign/verify roundtrip with 64-byte signature', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    const msg = '48656C6C6F20576F726C64';
    const sig = ed25519Sign(secretKey, msg);
    expect(sig.length).toBe(128);
    expect(ed25519Verify(publicKey, msg, sig)).toBe(true);
  });

  it('verify rejects altered message', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    const sig = ed25519Sign(secretKey, '48656C6C6F');
    expect(ed25519Verify(publicKey, '48656C6C6F00', sig)).toBe(false);
  });

  it('verify rejects wrong public key', () => {
    const kp1 = ed25519Keygen();
    const kp2 = ed25519Keygen();
    const sig = ed25519Sign(kp1.secretKey, 'AABBCCDD');
    expect(ed25519Verify(kp2.publicKey, 'AABBCCDD', sig)).toBe(false);
  });

  it('derivePublicKey matches keygen', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    expect(ed25519DerivePublicKey(secretKey)).toBe(publicKey);
  });

  it('deterministic sign/verify with known seed', () => {
    const sk = '9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60';
    const pk = ed25519DerivePublicKey(sk);
    expect(pk.length).toBe(64);
    const sig = ed25519Sign(sk, '');
    expect(sig.length).toBe(128);
    expect(ed25519Verify(pk, '', sig)).toBe(true);
    expect(ed25519Verify(pk, 'FF', sig)).toBe(false);
  });
});
