import { describe, it, expect } from 'vitest';
import { ccmEncrypt, ccmDecrypt } from '../../src/crypto/aes.ts';

// AES-CCM test vectors from RFC 3610 §8 (Packet Vectors) and NIST SP 800-38C App. C

describe('AES-CCM', () => {

  // ═══════════════════════════════════════════════════════════
  // RFC 3610 Packet Vector #1
  //   Key: AES-128
  //   Nonce: 13 bytes (L=2)
  //   AAD: 8 bytes
  //   Plaintext: 23 bytes
  //   Tag: 8 bytes
  // ═══════════════════════════════════════════════════════════
  describe('RFC 3610 Packet Vector #1', () => {
    const key = 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF';
    const nonce = '00000003020100A0A1A2A3A4A5';
    const aad = '0001020304050607';
    const plaintext = '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E';
    // Expected per RFC 3610: ciphertext (23B) || tag (8B)
    const expected = '588C979A61C663D2F066D0C2C0F989806D5F6B61DAC384'.toUpperCase()
                   + '17E8D12CFDF926E0'.toUpperCase();

    it('encrypt matches RFC 3610 PV#1', () => {
      expect(ccmEncrypt(key, plaintext, nonce, aad, 8)).toBe(expected);
    });

    it('decrypt matches RFC 3610 PV#1', () => {
      expect(ccmDecrypt(key, expected, nonce, aad, 8)).toBe(plaintext);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // RFC 3610 Packet Vector #2 — 24-byte plaintext, same key
  // ═══════════════════════════════════════════════════════════
  describe('RFC 3610 Packet Vector #2', () => {
    const key = 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF';
    const nonce = '00000004030201A0A1A2A3A4A5';
    const aad = '0001020304050607';
    const plaintext = '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
    const expected = '72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3B'.toUpperCase()
                   + 'A091D56E10400916'.toUpperCase();

    it('encrypt matches RFC 3610 PV#2', () => {
      expect(ccmEncrypt(key, plaintext, nonce, aad, 8)).toBe(expected);
    });

    it('decrypt matches RFC 3610 PV#2', () => {
      expect(ccmDecrypt(key, expected, nonce, aad, 8)).toBe(plaintext);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // NIST SP 800-38C Appendix C.1 — AES-128, tag=4, nonce=7, AAD=8
  // ═══════════════════════════════════════════════════════════
  describe('NIST SP 800-38C Appendix C.1', () => {
    const key = '404142434445464748494A4B4C4D4E4F';
    const nonce = '10111213141516';
    const aad = '0001020304050607';
    const plaintext = '20212223';
    // Expected per NIST C.1: ciphertext (4B) || tag (4B) = 7162015B 4DAC255D
    const expected = '7162015B4DAC255D';

    it('encrypt matches NIST C.1', () => {
      expect(ccmEncrypt(key, plaintext, nonce, aad, 4)).toBe(expected);
    });

    it('decrypt matches NIST C.1', () => {
      expect(ccmDecrypt(key, expected, nonce, aad, 4)).toBe(plaintext);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Roundtrips with different key sizes
  // ═══════════════════════════════════════════════════════════
  describe('Roundtrips', () => {
    const nonce = '00112233445566778899AABB'; // 12 bytes
    const plaintext = '48656C6C6F20576F726C64'; // "Hello World"
    const aad = 'FEEDFACEDEADBEEF';

    it('AES-128 roundtrip with AAD', () => {
      const key = '000102030405060708090A0B0C0D0E0F';
      const ct = ccmEncrypt(key, plaintext, nonce, aad, 16);
      expect(ccmDecrypt(key, ct, nonce, aad, 16)).toBe(plaintext);
    });

    it('AES-192 roundtrip with AAD', () => {
      const key = '000102030405060708090A0B0C0D0E0F1011121314151617';
      const ct = ccmEncrypt(key, plaintext, nonce, aad, 16);
      expect(ccmDecrypt(key, ct, nonce, aad, 16)).toBe(plaintext);
    });

    it('AES-256 roundtrip with AAD', () => {
      const key = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
      const ct = ccmEncrypt(key, plaintext, nonce, aad, 16);
      expect(ccmDecrypt(key, ct, nonce, aad, 16)).toBe(plaintext);
    });

    it('roundtrip without AAD', () => {
      const key = '000102030405060708090A0B0C0D0E0F';
      const ct = ccmEncrypt(key, plaintext, nonce, undefined, 16);
      expect(ccmDecrypt(key, ct, nonce, undefined, 16)).toBe(plaintext);
    });

    it('roundtrip with empty plaintext', () => {
      const key = '000102030405060708090A0B0C0D0E0F';
      const ct = ccmEncrypt(key, '', nonce, aad, 16);
      expect(ct.length).toBe(32); // just the 16-byte tag
      expect(ccmDecrypt(key, ct, nonce, aad, 16)).toBe('');
    });

    it('different tag lengths produce different ciphertexts', () => {
      const key = '000102030405060708090A0B0C0D0E0F';
      const ct8 = ccmEncrypt(key, plaintext, nonce, aad, 8);
      const ct16 = ccmEncrypt(key, plaintext, nonce, aad, 16);
      expect(ct16.length - ct8.length).toBe(16); // 8 extra bytes = 16 hex chars
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Negative / Authentication
  // ═══════════════════════════════════════════════════════════
  describe('Authentication failures', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    const nonce = '00112233445566778899AABB';
    const plaintext = 'AABBCCDD';
    const aad = 'CAFEBABE';

    it('tag tamper fails', () => {
      const ct = ccmEncrypt(key, plaintext, nonce, aad, 16);
      const tampered = ct.substring(0, ct.length - 2) + (ct.endsWith('00') ? '01' : '00');
      expect(() => ccmDecrypt(key, tampered, nonce, aad, 16)).toThrow(/authentication failed/);
    });

    it('ciphertext tamper fails', () => {
      const ct = ccmEncrypt(key, plaintext, nonce, aad, 16);
      const tampered = (ct.startsWith('00') ? '01' : '00') + ct.substring(2);
      expect(() => ccmDecrypt(key, tampered, nonce, aad, 16)).toThrow(/authentication failed/);
    });

    it('wrong AAD fails', () => {
      const ct = ccmEncrypt(key, plaintext, nonce, aad, 16);
      expect(() => ccmDecrypt(key, ct, nonce, 'DEADBEEF', 16)).toThrow(/authentication failed/);
    });

    it('wrong key fails', () => {
      const ct = ccmEncrypt(key, plaintext, nonce, aad, 16);
      const wrongKey = 'FF0102030405060708090A0B0C0D0E0F';
      expect(() => ccmDecrypt(wrongKey, ct, nonce, aad, 16)).toThrow(/authentication failed/);
    });
  });

  // ═══════════════════════════════════════════════════════════
  // Parameter validation
  // ═══════════════════════════════════════════════════════════
  describe('Parameter validation', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    const nonce12 = '00112233445566778899AABB';

    it('rejects invalid key length', () => {
      expect(() => ccmEncrypt('0011', 'AA', nonce12, undefined, 16))
        .toThrow(/key must be 16\/24\/32 bytes/);
    });

    it('rejects nonce shorter than 7 bytes', () => {
      expect(() => ccmEncrypt(key, 'AA', '001122334455', undefined, 16)) // 6 bytes
        .toThrow(/nonce must be 7-13 bytes/);
    });

    it('rejects nonce longer than 13 bytes', () => {
      expect(() => ccmEncrypt(key, 'AA', '00112233445566778899AABBCCDD', undefined, 16)) // 14 bytes
        .toThrow(/nonce must be 7-13 bytes/);
    });

    it('rejects invalid tag length', () => {
      expect(() => ccmEncrypt(key, 'AA', nonce12, undefined, 5))
        .toThrow(/tag length must be one of/);
      expect(() => ccmEncrypt(key, 'AA', nonce12, undefined, 18))
        .toThrow(/tag length must be one of/);
    });

    it('rejects input shorter than tag on decrypt', () => {
      expect(() => ccmDecrypt(key, 'AABB', nonce12, undefined, 16))
        .toThrow(/input shorter than tag length/);
    });
  });
});
