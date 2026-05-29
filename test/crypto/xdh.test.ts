import { describe, it, expect } from 'vitest';
import {
  xdhKeygen, xdhComputeSecret, xdhDerivePublicKey,
} from '../../src/crypto/ecc.ts';

// XDH — RFC 7748. Curves: X25519 (Curve25519) and X448 (Curve448).

describe('X25519 (default curve)', () => {
  it('keygen produces 32-byte key pair', () => {
    const { privateKey, publicKey } = xdhKeygen();
    expect(privateKey.length).toBe(64);
    expect(publicKey.length).toBe(64);
  });

  it('two parties derive the same shared secret', () => {
    const alice = xdhKeygen();
    const bob = xdhKeygen();
    const sA = xdhComputeSecret(alice.privateKey, bob.publicKey);
    const sB = xdhComputeSecret(bob.privateKey, alice.publicKey);
    expect(sA).toBe(sB);
    expect(sA.length).toBe(64);
  });

  it('derivePublicKey matches keygen', () => {
    const { privateKey, publicKey } = xdhKeygen();
    expect(xdhDerivePublicKey(privateKey)).toBe(publicKey);
  });

  it('different peer keys produce different secrets', () => {
    const alice = xdhKeygen();
    const bob1 = xdhKeygen();
    const bob2 = xdhKeygen();
    expect(xdhComputeSecret(alice.privateKey, bob1.publicKey))
      .not.toBe(xdhComputeSecret(alice.privateKey, bob2.publicKey));
  });
});

describe('X448', () => {
  it('keygen produces 56-byte key pair', () => {
    const { privateKey, publicKey } = xdhKeygen('x448');
    expect(privateKey.length).toBe(112); // 56 bytes
    expect(publicKey.length).toBe(112);
  });

  it('two parties derive the same shared secret', () => {
    const alice = xdhKeygen('x448');
    const bob = xdhKeygen('x448');
    const sA = xdhComputeSecret(alice.privateKey, bob.publicKey, 'x448');
    const sB = xdhComputeSecret(bob.privateKey, alice.publicKey, 'x448');
    expect(sA).toBe(sB);
    expect(sA.length).toBe(112); // 56 bytes
  });

  it('derivePublicKey matches keygen', () => {
    const { privateKey, publicKey } = xdhKeygen('x448');
    expect(xdhDerivePublicKey(privateKey, 'x448')).toBe(publicKey);
  });

  // RFC 7748 §6.2 Alice/Bob test vector
  it('RFC 7748 §6.2: Alice/Bob shared secret matches', () => {
    const alicePriv = '9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b';
    const alicePub  = '9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0';
    const bobPriv   = '1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d';
    const bobPub    = '3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609';
    const expected  = '07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d';

    expect(xdhDerivePublicKey(alicePriv, 'x448').toLowerCase()).toBe(alicePub);
    expect(xdhDerivePublicKey(bobPriv, 'x448').toLowerCase()).toBe(bobPub);
    expect(xdhComputeSecret(alicePriv, bobPub, 'x448').toLowerCase()).toBe(expected);
    expect(xdhComputeSecret(bobPriv, alicePub, 'x448').toLowerCase()).toBe(expected);
  });
});
