import { describe, it, expect } from 'vitest';
import { encrypt, decrypt } from '../../src/crypto/chacha.ts';
import {
  ed25519Keygen, ed25519Sign, ed25519Verify, ed25519DerivePublicKey,
  x25519Keygen, x25519ComputeSecret, x25519DerivePublicKey,
  ecdsaSign, ecdsaVerify, ecdhComputeSecret, derivePublicKey,
} from '../../src/crypto/ecc.ts';

// ═══════════════════════════════════════════════════════════
// Task 2.1: ChaCha20-Poly1305
// ═══════════════════════════════════════════════════════════
describe('ChaCha20-Poly1305', () => {
  const key = '808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F';
  const nonce = '070000004041424344454647';

  it('encrypt then decrypt roundtrip', () => {
    const plaintext = '4C616469657320616E642047656E746C656D656E';
    const ct = encrypt(key, plaintext, nonce);
    expect(ct.length).toBeGreaterThan(plaintext.length); // includes 16-byte tag
    const pt = decrypt(key, ct, nonce);
    expect(pt).toBe(plaintext);
  });

  it('encrypt with AAD roundtrip', () => {
    const plaintext = '48656C6C6F';
    const aad = 'FEEDFACEDEADBEEF';
    const ct = encrypt(key, plaintext, nonce, aad);
    const pt = decrypt(key, ct, nonce, aad);
    expect(pt).toBe(plaintext);
  });

  it('decrypt with wrong key fails', () => {
    const plaintext = '48656C6C6F';
    const ct = encrypt(key, plaintext, nonce);
    const wrongKey = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
    expect(() => decrypt(wrongKey, ct, nonce)).toThrow();
  });

  it('decrypt with tampered ciphertext fails', () => {
    const plaintext = '48656C6C6F';
    const ct = encrypt(key, plaintext, nonce);
    const tampered = ct.substring(0, ct.length - 2) + '00';
    expect(() => decrypt(key, tampered, nonce)).toThrow();
  });

  it('decrypt with wrong AAD fails', () => {
    const plaintext = '48656C6C6F';
    const aad = 'FEEDFACE';
    const ct = encrypt(key, plaintext, nonce, aad);
    expect(() => decrypt(key, ct, nonce, 'DEADBEEF')).toThrow();
  });

  it('throws on invalid key length', () => {
    expect(() => encrypt('0011', '48656C6C6F', nonce)).toThrow('key must be 32 bytes');
  });

  it('throws on invalid nonce length', () => {
    expect(() => encrypt(key, '48656C6C6F', '0011')).toThrow('nonce must be 12 bytes');
  });
});

// ═══════════════════════════════════════════════════════════
// Task 2.2: Ed25519
// ═══════════════════════════════════════════════════════════
describe('Ed25519', () => {
  it('keygen produces 32-byte key pair', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    expect(secretKey.length).toBe(64); // 32 bytes = 64 hex
    expect(publicKey.length).toBe(64);
  });

  it('sign/verify roundtrip', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    const msg = '48656C6C6F20576F726C64';
    const sig = ed25519Sign(secretKey, msg);
    expect(sig.length).toBe(128); // 64-byte signature
    const ok = ed25519Verify(publicKey, msg, sig);
    expect(ok).toBe(true);
  });

  it('verify rejects altered message', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    const msg = '48656C6C6F';
    const sig = ed25519Sign(secretKey, msg);
    expect(ed25519Verify(publicKey, msg + '00', sig)).toBe(false);
  });

  it('verify rejects wrong public key', () => {
    const kp1 = ed25519Keygen();
    const kp2 = ed25519Keygen();
    const msg = 'AABBCCDD';
    const sig = ed25519Sign(kp1.secretKey, msg);
    expect(ed25519Verify(kp2.publicKey, msg, sig)).toBe(false);
  });

  it('derivePublicKey matches keygen', () => {
    const { secretKey, publicKey } = ed25519Keygen();
    const derived = ed25519DerivePublicKey(secretKey);
    expect(derived).toBe(publicKey);
  });

  it('deterministic sign/verify with known key', () => {
    const sk = '9D61B19DEFFD5A60BA844AF492EC2CC44449C5697B326919703BAC031CAE7F60';
    const pk = ed25519DerivePublicKey(sk);
    expect(pk.length).toBe(64);
    const sig = ed25519Sign(sk, ''); // empty message
    expect(sig.length).toBe(128);
    expect(ed25519Verify(pk, '', sig)).toBe(true);
    expect(ed25519Verify(pk, 'FF', sig)).toBe(false);
  });
});

// ═══════════════════════════════════════════════════════════
// Task 2.3: X25519
// ═══════════════════════════════════════════════════════════
describe('X25519', () => {
  it('keygen produces 32-byte key pair', () => {
    const { privateKey, publicKey } = x25519Keygen();
    expect(privateKey.length).toBe(64);
    expect(publicKey.length).toBe(64);
  });

  it('two parties derive same shared secret', () => {
    const alice = x25519Keygen();
    const bob = x25519Keygen();
    const secretA = x25519ComputeSecret(alice.privateKey, bob.publicKey);
    const secretB = x25519ComputeSecret(bob.privateKey, alice.publicKey);
    expect(secretA).toBe(secretB);
    expect(secretA.length).toBe(64); // 32-byte secret
  });

  it('derivePublicKey matches keygen', () => {
    const { privateKey, publicKey } = x25519Keygen();
    const derived = x25519DerivePublicKey(privateKey);
    expect(derived).toBe(publicKey);
  });

  it('different key pairs produce different secrets', () => {
    const alice = x25519Keygen();
    const bob1 = x25519Keygen();
    const bob2 = x25519Keygen();
    const s1 = x25519ComputeSecret(alice.privateKey, bob1.publicKey);
    const s2 = x25519ComputeSecret(alice.privateKey, bob2.publicKey);
    expect(s1).not.toBe(s2);
  });
});

// ═══════════════════════════════════════════════════════════
// Task 2.4: Multi-curve ECC (P-384, secp256k1)
// ═══════════════════════════════════════════════════════════
describe('Multi-curve ECC', () => {
  describe('P-256 (default, regression)', () => {
    it('ECDSA sign/verify roundtrip', () => {
      const priv = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
      const pub = derivePublicKey(priv);
      const msg = 'AABBCCDD';
      const { r, s } = ecdsaSign(priv, msg);
      expect(ecdsaVerify(pub, msg, r, s)).toBe(true);
    });
  });

  describe('P-384', () => {
    it('ECDSA sign/verify roundtrip', () => {
      const priv = deriveP384PrivKey();
      const pub = derivePublicKey(priv, 'p384');
      expect(pub.length).toBe(194); // 04 + 48*2 + 48*2 = 194 hex chars
      const msg = 'DEADBEEF';
      const { r, s } = ecdsaSign(priv, msg, 'p384');
      expect(ecdsaVerify(pub, msg, r, s, 'p384')).toBe(true);
    });

    it('ECDH key agreement', () => {
      const privA = deriveP384PrivKey();
      const pubA = derivePublicKey(privA, 'p384');
      const privB = deriveP384PrivKey();
      const pubB = derivePublicKey(privB, 'p384');
      const secretA = ecdhComputeSecret(privA, pubB, 'p384');
      const secretB = ecdhComputeSecret(privB, pubA, 'p384');
      expect(secretA).toBe(secretB);
      expect(secretA.length).toBe(96); // 48 bytes
    });
  });

  describe('secp256k1', () => {
    it('ECDSA sign/verify roundtrip', () => {
      const priv = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
      const pub = derivePublicKey(priv, 'secp256k1');
      expect(pub.length).toBe(130); // 04 + 32*2 + 32*2
      const msg = 'CAFEBABE';
      const { r, s } = ecdsaSign(priv, msg, 'secp256k1');
      expect(ecdsaVerify(pub, msg, r, s, 'secp256k1')).toBe(true);
    });

    it('ECDH key agreement', () => {
      const privA = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
      const pubA = derivePublicKey(privA, 'secp256k1');
      const privB = 'A0A1A2A3A4A5A6A7A8A9AAABACADAEAFB0B1B2B3B4B5B6B7B8B9BABBBCBDBEBF';
      const pubB = derivePublicKey(privB, 'secp256k1');
      const secretA = ecdhComputeSecret(privA, pubB, 'secp256k1');
      const secretB = ecdhComputeSecret(privB, pubA, 'secp256k1');
      expect(secretA).toBe(secretB);
      expect(secretA.length).toBe(64); // 32 bytes
    });

    it('verify rejects wrong curve key', () => {
      const priv = 'C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721';
      const pubP256 = derivePublicKey(priv, 'p256');
      const msg = 'AABB';
      const { r, s } = ecdsaSign(priv, msg, 'secp256k1');
      expect(ecdsaVerify(pubP256, msg, r, s, 'secp256k1')).toBe(false);
    });
  });
});

function deriveP384PrivKey(): string {
  const bytes = new Uint8Array(48);
  crypto.getRandomValues(bytes);
  bytes[0] = 0x01;
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('');
}
