import { describe, it, expect } from 'vitest';
import {
  x25519Keygen, x25519ComputeSecret, x25519DerivePublicKey,
} from '../../src/crypto/ecc.ts';

// X25519 — RFC 7748. Curve25519 (Montgomery form), key agreement.

describe('X25519', () => {
  it('keygen produces 32-byte key pair', () => {
    const { privateKey, publicKey } = x25519Keygen();
    expect(privateKey.length).toBe(64);
    expect(publicKey.length).toBe(64);
  });

  it('two parties derive the same shared secret', () => {
    const alice = x25519Keygen();
    const bob = x25519Keygen();
    const sA = x25519ComputeSecret(alice.privateKey, bob.publicKey);
    const sB = x25519ComputeSecret(bob.privateKey, alice.publicKey);
    expect(sA).toBe(sB);
    expect(sA.length).toBe(64);
  });

  it('derivePublicKey matches keygen', () => {
    const { privateKey, publicKey } = x25519Keygen();
    expect(x25519DerivePublicKey(privateKey)).toBe(publicKey);
  });

  it('different peer keys produce different secrets', () => {
    const alice = x25519Keygen();
    const bob1 = x25519Keygen();
    const bob2 = x25519Keygen();
    expect(x25519ComputeSecret(alice.privateKey, bob1.publicKey))
      .not.toBe(x25519ComputeSecret(alice.privateKey, bob2.publicKey));
  });
});
