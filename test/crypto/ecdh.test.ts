import { describe, it, expect } from 'vitest';
import { ecdhComputeSecret, derivePublicKey } from '../../src/crypto/ecc.ts';

// ECDH — NIST SP 800-56A · RFC 5903. Curves: P-256 (default), P-384, secp256k1.

describe('ECDH — P-256 (default)', () => {
  const privA = '01'.repeat(32);
  const privB = '02'.repeat(32);
  const pubA = derivePublicKey(privA);
  const pubB = derivePublicKey(privB);

  it('shared secret is symmetric', () => {
    const s1 = ecdhComputeSecret(privA, pubB);
    const s2 = ecdhComputeSecret(privB, pubA);
    expect(s1).toBe(s2);
  });
});

describe('ECDH — P-384', () => {
  function p384Priv(): string {
    const b = new Uint8Array(48);
    crypto.getRandomValues(b);
    b[0] = 0x01;
    return Array.from(b).map(x => x.toString(16).padStart(2, '0').toUpperCase()).join('');
  }

  it('key agreement produces matching 48-byte secret', () => {
    const privA = p384Priv();
    const pubA = derivePublicKey(privA, 'p384');
    const privB = p384Priv();
    const pubB = derivePublicKey(privB, 'p384');
    const s1 = ecdhComputeSecret(privA, pubB, 'p384');
    const s2 = ecdhComputeSecret(privB, pubA, 'p384');
    expect(s1).toBe(s2);
    expect(s1.length).toBe(96); // 48 bytes
  });
});

describe('ECDH — secp256k1', () => {
  it('key agreement produces matching 32-byte secret', () => {
    const privA = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
    const pubA = derivePublicKey(privA, 'secp256k1');
    const privB = 'A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF';
    const pubB = derivePublicKey(privB, 'secp256k1');
    const s1 = ecdhComputeSecret(privA, pubB, 'secp256k1');
    const s2 = ecdhComputeSecret(privB, pubA, 'secp256k1');
    expect(s1).toBe(s2);
    expect(s1.length).toBe(64);
  });
});
