import { describe, it, expect } from 'vitest';
import {
  eddsaKeygen, eddsaSign, eddsaVerify, eddsaDerivePublicKey,
} from '../../src/crypto/ecc.ts';

// EdDSA — RFC 8032. Curves: Ed25519 (Curve25519) and Ed448 (Curve448).

describe('Ed25519 (default curve)', () => {
  it('keygen produces 32-byte key pair', () => {
    const { secretKey, publicKey } = eddsaKeygen();
    expect(secretKey.length).toBe(64);
    expect(publicKey.length).toBe(64);
  });

  it('sign/verify roundtrip with 64-byte signature', () => {
    const { secretKey, publicKey } = eddsaKeygen();
    const msg = '48656C6C6F20576F726C64';
    const sig = eddsaSign(secretKey, msg);
    expect(sig.length).toBe(128);
    expect(eddsaVerify(publicKey, msg, sig)).toBe(true);
  });

  it('verify rejects altered message', () => {
    const { secretKey, publicKey } = eddsaKeygen();
    const sig = eddsaSign(secretKey, '48656C6C6F');
    expect(eddsaVerify(publicKey, '48656C6C6F00', sig)).toBe(false);
  });

  it('verify rejects wrong public key', () => {
    const kp1 = eddsaKeygen();
    const kp2 = eddsaKeygen();
    const sig = eddsaSign(kp1.secretKey, 'AABBCCDD');
    expect(eddsaVerify(kp2.publicKey, 'AABBCCDD', sig)).toBe(false);
  });

  it('derivePublicKey matches keygen', () => {
    const { secretKey, publicKey } = eddsaKeygen();
    expect(eddsaDerivePublicKey(secretKey)).toBe(publicKey);
  });

  it('deterministic sign/verify with known seed', () => {
    const sk = '9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60';
    const pk = eddsaDerivePublicKey(sk);
    expect(pk.length).toBe(64);
    const sig = eddsaSign(sk, '');
    expect(sig.length).toBe(128);
    expect(eddsaVerify(pk, '', sig)).toBe(true);
    expect(eddsaVerify(pk, 'FF', sig)).toBe(false);
  });
});

describe('Ed448', () => {
  it('keygen produces 57-byte key pair', () => {
    const { secretKey, publicKey } = eddsaKeygen('ed448');
    expect(secretKey.length).toBe(114); // 57 bytes
    expect(publicKey.length).toBe(114);
  });

  it('sign/verify roundtrip with 114-byte signature', () => {
    const { secretKey, publicKey } = eddsaKeygen('ed448');
    const msg = '48656C6C6F20576F726C64';
    const sig = eddsaSign(secretKey, msg, 'ed448');
    expect(sig.length).toBe(228); // 114 bytes
    expect(eddsaVerify(publicKey, msg, sig, 'ed448')).toBe(true);
  });

  it('verify rejects altered message', () => {
    const { secretKey, publicKey } = eddsaKeygen('ed448');
    const sig = eddsaSign(secretKey, 'AABB', 'ed448');
    expect(eddsaVerify(publicKey, 'AABBCC', sig, 'ed448')).toBe(false);
  });

  it('derivePublicKey matches keygen', () => {
    const { secretKey, publicKey } = eddsaKeygen('ed448');
    expect(eddsaDerivePublicKey(secretKey, 'ed448')).toBe(publicKey);
  });

  // RFC 8032 §7.4 "Blank" test vector
  it('RFC 8032 §7.4 "Blank" vector: SK → PK matches', () => {
    const sk = '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b';
    const pk = '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180';
    expect(eddsaDerivePublicKey(sk, 'ed448').toLowerCase()).toBe(pk);
  });

  it('RFC 8032 §7.4 "Blank" vector: empty message signature matches', () => {
    const sk = '6c82a562cb808d10d632be89c8513ebf6c929f34ddfa8c9f63c9960ef6e348a3528c8a3fcc2f044e39a3fc5b94492f8f032e7549a20098f95b';
    const pk = '5fd7449b59b461fd2ce787ec616ad46a1da1342485a70e1f8a0ea75d80e96778edf124769b46c7061bd6783df1e50f6cd1fa1abeafe8256180';
    const expectedSig = '533a37f6bbe457251f023c0d88f976ae2dfb504a843e34d2074fd823d41a591f2b233f034f628281f2fd7a22ddd47d7828c59bd0a21bfd3980ff0d2028d4b18a9df63e006c5d1c2d345b925d8dc00b4104852db99ac5c7cdda8530a113a0f4dbb61149f05a7363268c71d95808ff2e652600';
    expect(eddsaSign(sk, '', 'ed448').toLowerCase()).toBe(expectedSig);
    expect(eddsaVerify(pk, '', expectedSig, 'ed448')).toBe(true);
  });
});
