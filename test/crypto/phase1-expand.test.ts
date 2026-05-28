import { describe, it, expect } from 'vitest';
import { digest } from '../../src/crypto/hash.ts';
import { kemKeygen, kemEncapsulate, kemDecapsulate } from '../../src/crypto/pqc.ts';
import { xor, and, or, not, shiftLeft, shiftRight } from '../../src/crypto/bitwise.ts';
import { cfbEncrypt, cfbDecrypt } from '../../src/crypto/aes.ts';

// ═══════════════════════════════════════════════════════════
// Task 1.1: SHA-3 Family
// ═══════════════════════════════════════════════════════════
describe('SHA-3 Family', () => {
  // NIST test vectors: SHA3-256("abc") = 3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532
  it('SHA3-256 of "abc"', async () => {
    const result = await digest('sha3-256', '616263');
    expect(result).toBe('3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532');
  });

  // SHA3-384("abc")
  it('SHA3-384 of "abc"', async () => {
    const result = await digest('sha3-384', '616263');
    expect(result).toBe('EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25');
  });

  // SHA3-512("abc")
  it('SHA3-512 of "abc"', async () => {
    const result = await digest('sha3-512', '616263');
    expect(result).toBe('B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0');
  });

  // SHA3-256 of empty string
  it('SHA3-256 of empty string', async () => {
    const result = await digest('sha3-256', '');
    expect(result).toBe('A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A');
  });

  // SHAKE128 with default output length (32 bytes)
  it('SHAKE128 produces 32-byte output by default', async () => {
    const result = await digest('shake128', '616263');
    expect(result.length).toBe(64); // 32 bytes = 64 hex chars
  });

  // SHAKE256 with default output length (64 bytes)
  it('SHAKE256 produces 64-byte output by default', async () => {
    const result = await digest('shake256', '616263');
    expect(result.length).toBe(128); // 64 bytes = 128 hex chars
  });

  // SHAKE128 with custom output length
  it('SHAKE128 with custom output length 16 bytes', async () => {
    const result = await digest('shake128', '616263', 16);
    expect(result.length).toBe(32); // 16 bytes = 32 hex chars
  });

  // SHAKE256 with custom output length
  it('SHAKE256 with custom output length 48 bytes', async () => {
    const result = await digest('shake256', '616263', 48);
    expect(result.length).toBe(96); // 48 bytes = 96 hex chars
  });

  // Existing algorithms still work
  it('SHA-256 still works', async () => {
    const result = await digest('sha256', '616263');
    expect(result).toBe('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD');
  });
});

// ═══════════════════════════════════════════════════════════
// Task 1.2: ML-KEM-1024
// ═══════════════════════════════════════════════════════════
describe('ML-KEM-1024', () => {
  it('keygen produces valid keys', () => {
    const { ek, dk } = kemKeygen(1024);
    expect(ek.length).toBeGreaterThan(0);
    expect(dk.length).toBeGreaterThan(0);
  });

  it('encapsulate/decapsulate roundtrip produces matching shared secret', () => {
    const { ek, dk } = kemKeygen(1024);
    const { ciphertext, sharedSecret: ss1 } = kemEncapsulate(1024, ek);
    const ss2 = kemDecapsulate(1024, dk, ciphertext);
    expect(ss1).toBe(ss2);
    expect(ss1.length).toBe(64); // 32-byte shared secret = 64 hex chars
  });

  it('different encapsulations produce different shared secrets', () => {
    const { ek, dk } = kemKeygen(1024);
    const { sharedSecret: ss1 } = kemEncapsulate(1024, ek);
    const { sharedSecret: ss2 } = kemEncapsulate(1024, ek);
    expect(ss1).not.toBe(ss2);
  });

  it('string variant "1024" also works', () => {
    const { ek, dk } = kemKeygen('1024');
    const { ciphertext, sharedSecret: ss1 } = kemEncapsulate('1024', ek);
    const ss2 = kemDecapsulate('1024', dk, ciphertext);
    expect(ss1).toBe(ss2);
  });
});

// ═══════════════════════════════════════════════════════════
// Task 1.3: Bitwise Operations
// ═══════════════════════════════════════════════════════════
describe('Bitwise Operations', () => {
  describe('AND', () => {
    it('FF AND 0F = 0F', () => {
      expect(and('FF', '0F')).toBe('0F');
    });
    it('AABB AND FF00 = AA00', () => {
      expect(and('AABB', 'FF00')).toBe('AA00');
    });
  });

  describe('OR', () => {
    it('F0 OR 0F = FF', () => {
      expect(or('F0', '0F')).toBe('FF');
    });
    it('AA00 OR 00BB = AABB', () => {
      expect(or('AA00', '00BB')).toBe('AABB');
    });
  });

  describe('NOT', () => {
    it('NOT FF = 00', () => {
      expect(not('FF')).toBe('00');
    });
    it('NOT 00 = FF', () => {
      expect(not('00')).toBe('FF');
    });
    it('NOT A5 = 5A', () => {
      expect(not('A5')).toBe('5A');
    });
  });

  describe('Shift Left', () => {
    it('01 << 4 = 10', () => {
      expect(shiftLeft('01', 4)).toBe('10');
    });
    it('01 << 1 = 02', () => {
      expect(shiftLeft('01', 1)).toBe('02');
    });
    it('0080 << 1 = 0100', () => {
      expect(shiftLeft('0080', 1)).toBe('0100');
    });
    it('FF << 8 = 00 (shift out)', () => {
      expect(shiftLeft('FF', 8)).toBe('00');
    });
    it('00FF << 4 = 0FF0', () => {
      expect(shiftLeft('00FF', 4)).toBe('0FF0');
    });
  });

  describe('Shift Right', () => {
    it('80 >> 1 = 40', () => {
      expect(shiftRight('80', 1)).toBe('40');
    });
    it('10 >> 4 = 01', () => {
      expect(shiftRight('10', 4)).toBe('01');
    });
    it('0100 >> 1 = 0080', () => {
      expect(shiftRight('0100', 1)).toBe('0080');
    });
    it('FF >> 8 = 00 (shift out)', () => {
      expect(shiftRight('FF', 8)).toBe('00');
    });
    it('FF00 >> 4 = 0FF0', () => {
      expect(shiftRight('FF00', 4)).toBe('0FF0');
    });
  });

  describe('XOR (regression)', () => {
    it('FF XOR FF = 00', () => {
      expect(xor('FF', 'FF')).toBe('00');
    });
    it('AA XOR 55 = FF', () => {
      expect(xor('AA', '55')).toBe('FF');
    });
  });
});

// ═══════════════════════════════════════════════════════════
// Task 1.4: AES-CFB Mode
// ═══════════════════════════════════════════════════════════
describe('AES-CFB', () => {
  // NIST SP 800-38A F.3.13: CFB128-AES128 Encrypt
  const key128 = '2B7E151628AED2A6ABF7158809CF4F3C';
  const iv = '000102030405060708090A0B0C0D0E0F';
  const plaintext = '6BC1BEE22E409F96E93D7E117393172A';
  const ciphertext = '3B3FD92EB72DAD20333449F8E83CFB4A';

  it('encrypt matches NIST vector', () => {
    const result = cfbEncrypt(key128, plaintext, iv);
    expect(result).toBe(ciphertext);
  });

  it('decrypt matches NIST vector', () => {
    const result = cfbDecrypt(key128, ciphertext, iv);
    expect(result).toBe(plaintext);
  });

  it('encrypt then decrypt roundtrip', () => {
    const key = '0123456789ABCDEF0123456789ABCDEF';
    const nonce = '00112233445566778899AABBCCDDEEFF';
    const data = 'DEADBEEFCAFEBABE';
    const encrypted = cfbEncrypt(key, data, nonce);
    const decrypted = cfbDecrypt(key, encrypted, nonce);
    expect(decrypted).toBe(data);
  });

  it('CFB handles non-block-aligned data (stream mode)', () => {
    const key = '0123456789ABCDEF0123456789ABCDEF';
    const nonce = '00112233445566778899AABBCCDDEEFF';
    const data = 'AABB'; // only 2 bytes, not 16
    const encrypted = cfbEncrypt(key, data, nonce);
    expect(encrypted.length).toBe(4); // 2 bytes output
    const decrypted = cfbDecrypt(key, encrypted, nonce);
    expect(decrypted).toBe(data);
  });

  it('AES-256 CFB roundtrip', () => {
    const key256 = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF';
    const nonce = '00112233445566778899AABBCCDDEEFF';
    const data = '48656C6C6F20576F726C64';
    const encrypted = cfbEncrypt(key256, data, nonce);
    const decrypted = cfbDecrypt(key256, encrypted, nonce);
    expect(decrypted).toBe(data);
  });

  it('throws on invalid IV length', () => {
    const key = '0123456789ABCDEF0123456789ABCDEF';
    expect(() => cfbEncrypt(key, 'AABB', '0011')).toThrow('IV must be 16 bytes');
  });
});
