import { describe, it, expect } from 'vitest';
import { encrypt, decrypt } from '../../src/crypto/chacha.ts';

// ChaCha20-Poly1305 — RFC 8439. 256-bit key, 96-bit nonce, AEAD with 128-bit tag.

describe('ChaCha20-Poly1305', () => {
  const key = '808182838485868788898A8B8C8D8E8F909192939495969798999A9B9C9D9E9F';
  const nonce = '070000004041424344454647';

  it('encrypt then decrypt roundtrip', () => {
    const plaintext = '4C616469657320616E642047656E746C656D656E';
    const ct = encrypt(key, plaintext, nonce);
    expect(ct.length).toBeGreaterThan(plaintext.length);
    expect(decrypt(key, ct, nonce)).toBe(plaintext);
  });

  it('encrypt with AAD roundtrip', () => {
    const plaintext = '48656C6C6F';
    const aad = 'FEEDFACEDEADBEEF';
    expect(decrypt(key, encrypt(key, plaintext, nonce, aad), nonce, aad)).toBe(plaintext);
  });

  it('decrypt with wrong key fails', () => {
    const ct = encrypt(key, '48656C6C6F', nonce);
    const wrongKey = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
    expect(() => decrypt(wrongKey, ct, nonce)).toThrow();
  });

  it('decrypt with tampered ciphertext fails', () => {
    const ct = encrypt(key, '48656C6C6F', nonce);
    const tampered = ct.substring(0, ct.length - 2) + '00';
    expect(() => decrypt(key, tampered, nonce)).toThrow();
  });

  it('decrypt with wrong AAD fails', () => {
    const ct = encrypt(key, '48656C6C6F', nonce, 'FEEDFACE');
    expect(() => decrypt(key, ct, nonce, 'DEADBEEF')).toThrow();
  });

  it('throws on invalid key length', () => {
    expect(() => encrypt('0011', '48656C6C6F', nonce)).toThrow('key must be 32 bytes');
  });

  it('throws on invalid nonce length', () => {
    expect(() => encrypt(key, '48656C6C6F', '0011')).toThrow('nonce must be 12 bytes');
  });
});
