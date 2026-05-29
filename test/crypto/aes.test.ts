import { describe, it, expect } from 'vitest';
import {
  ecbEncrypt, ecbDecrypt, cbcEncrypt, cbcDecrypt, ctrEncrypt,
  cfbEncrypt, cfbDecrypt, gcmEncrypt, gcmDecrypt,
  ccmEncrypt, ccmDecrypt,
} from '../../src/crypto/aes.ts';

// AES — FIPS 197. Modes: ECB, CBC, CTR, CFB, GCM (AEAD), CCM (AEAD).

describe('AES-ECB (NIST SP 800-38A vectors)', () => {
  it('AES-128 encrypt', () => {
    expect(ecbEncrypt('2b7e151628aed2a6abf7158809cf4f3c', '6bc1bee22e409f96e93d7e117393172a'))
      .toBe('3AD77BB40D7A3660A89ECAF32466EF97');
  });
  it('AES-128 decrypt', () => {
    expect(ecbDecrypt('2b7e151628aed2a6abf7158809cf4f3c', 'F5D3D58503B9699DE785895A96FDBAAF'))
      .toBe('AE2D8A571E03AC9C9EB76FAC45AF8E51');
  });
  it('AES-192 encrypt', () => {
    expect(ecbEncrypt('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B', '6bc1bee22e409f96e93d7e117393172a'))
      .toBe('BD334F1D6E45F25FF712A214571FA5CC');
  });
  it('AES-192 decrypt', () => {
    expect(ecbDecrypt('8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B', '974104846D0AD3AD7734ECB3ECEE4EEF'))
      .toBe('AE2D8A571E03AC9C9EB76FAC45AF8E51');
  });
  it('AES-256 encrypt', () => {
    expect(ecbEncrypt('603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4', '6bc1bee22e409f96e93d7e117393172a'))
      .toBe('F3EED1BDB5D2A03C064B5A7E3DB181F8');
  });
  it('AES-256 decrypt', () => {
    expect(ecbDecrypt('603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4', '591CCB10D410ED26DC5BA74A31362870'))
      .toBe('AE2D8A571E03AC9C9EB76FAC45AF8E51');
  });
});

describe('AES-CBC', () => {
  it('AES-128 roundtrip', () => {
    const key = '2b7e151628aed2a6abf7158809cf4f3c';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const pt = '6bc1bee22e409f96e93d7e117393172a';
    expect(cbcDecrypt(key, cbcEncrypt(key, pt, iv), iv)).toBe(pt.toUpperCase());
  });
});

describe('AES-CTR', () => {
  it('AES-128 roundtrip (symmetric)', () => {
    const key = '2b7e151628aed2a6abf7158809cf4f3c';
    const iv = '000102030405060708090a0b0c0d0e0f';
    const pt = '6bc1bee22e409f96e93d7e117393172a';
    const ct = ctrEncrypt(key, pt, iv);
    expect(ctrEncrypt(key, ct, iv)).toBe(pt.toUpperCase());
  });
});

describe('AES-CFB (NIST SP 800-38A F.3.13)', () => {
  const key128 = '2B7E151628AED2A6ABF7158809CF4F3C';
  const iv = '000102030405060708090A0B0C0D0E0F';
  const plaintext = '6BC1BEE22E409F96E93D7E117393172A';
  const ciphertext = '3B3FD92EB72DAD20333449F8E83CFB4A';

  it('encrypt matches NIST vector', () => {
    expect(cfbEncrypt(key128, plaintext, iv)).toBe(ciphertext);
  });
  it('decrypt matches NIST vector', () => {
    expect(cfbDecrypt(key128, ciphertext, iv)).toBe(plaintext);
  });
  it('AES-256 CFB roundtrip', () => {
    const key256 = '0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF';
    const nonce = '00112233445566778899AABBCCDDEEFF';
    const data = '48656C6C6F20576F726C64';
    expect(cfbDecrypt(key256, cfbEncrypt(key256, data, nonce), nonce)).toBe(data);
  });
  it('CFB handles non-block-aligned data (stream mode)', () => {
    const key = '0123456789ABCDEF0123456789ABCDEF';
    const nonce = '00112233445566778899AABBCCDDEEFF';
    const data = 'AABB';
    const encrypted = cfbEncrypt(key, data, nonce);
    expect(encrypted.length).toBe(4);
    expect(cfbDecrypt(key, encrypted, nonce)).toBe(data);
  });
  it('throws on invalid IV length', () => {
    expect(() => cfbEncrypt('0123456789ABCDEF0123456789ABCDEF', 'AABB', '0011'))
      .toThrow('IV must be 16 bytes');
  });
});

describe('AES-GCM (NIST vectors + AEAD roundtrip)', () => {
  it('AES-128 GCM matches NIST vector (no AAD)', () => {
    const key = 'feffe9928665731c6d6a8f9467308308';
    const nonce = 'cafebabefacedbaddecaf888';
    const pt = 'd9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39';
    const expected = '42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091cc15abcc191161501aabab46b8fbac85';
    expect(gcmEncrypt(key, pt, nonce)).toBe(expected.toUpperCase());
  });

  it('AES-128 GCM roundtrip with AAD', () => {
    const key = 'feffe9928665731c6d6a8f9467308308';
    const nonce = 'cafebabefacedbaddecaf888';
    const pt = 'd9313225f88406e5a55909c5aff5269a';
    const aad = 'feedfacedeadbeeffeedfacedeadbeefabaddad2';
    expect(gcmDecrypt(key, gcmEncrypt(key, pt, nonce, aad), nonce, aad)).toBe(pt.toUpperCase());
  });
});

// ═══════════════════════════════════════════════════════════════
// AES-CCM — NIST SP 800-38C · RFC 3610
// ═══════════════════════════════════════════════════════════════

describe('AES-CCM — RFC 3610 Packet Vector #1', () => {
  const key = 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF';
  const nonce = '00000003020100A0A1A2A3A4A5';
  const aad = '0001020304050607';
  const plaintext = '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E';
  const expected = '588C979A61C663D2F066D0C2C0F989806D5F6B61DAC38417E8D12CFDF926E0';

  it('encrypt matches RFC 3610 PV#1', () => {
    expect(ccmEncrypt(key, plaintext, nonce, aad, 8)).toBe(expected);
  });
  it('decrypt matches RFC 3610 PV#1', () => {
    expect(ccmDecrypt(key, expected, nonce, aad, 8)).toBe(plaintext);
  });
});

describe('AES-CCM — RFC 3610 Packet Vector #2', () => {
  const key = 'C0C1C2C3C4C5C6C7C8C9CACBCCCDCECF';
  const nonce = '00000004030201A0A1A2A3A4A5';
  const aad = '0001020304050607';
  const plaintext = '08090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
  const expected = '72C91A36E135F8CF291CA894085C87E3CC15C439C9E43A3BA091D56E10400916';

  it('encrypt matches RFC 3610 PV#2', () => {
    expect(ccmEncrypt(key, plaintext, nonce, aad, 8)).toBe(expected);
  });
  it('decrypt matches RFC 3610 PV#2', () => {
    expect(ccmDecrypt(key, expected, nonce, aad, 8)).toBe(plaintext);
  });
});

describe('AES-CCM — NIST SP 800-38C Appendix C.1', () => {
  const key = '404142434445464748494A4B4C4D4E4F';
  const nonce = '10111213141516';
  const aad = '0001020304050607';
  const plaintext = '20212223';
  const expected = '7162015B4DAC255D';

  it('encrypt matches NIST C.1', () => {
    expect(ccmEncrypt(key, plaintext, nonce, aad, 4)).toBe(expected);
  });
  it('decrypt matches NIST C.1', () => {
    expect(ccmDecrypt(key, expected, nonce, aad, 4)).toBe(plaintext);
  });
});

describe('AES-CCM — Roundtrips (128 / 192 / 256-bit keys)', () => {
  const nonce = '00112233445566778899AABB';
  const plaintext = '48656C6C6F20576F726C64';
  const aad = 'FEEDFACEDEADBEEF';

  it('AES-128 with AAD', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    expect(ccmDecrypt(key, ccmEncrypt(key, plaintext, nonce, aad, 16), nonce, aad, 16)).toBe(plaintext);
  });
  it('AES-192 with AAD', () => {
    const key = '000102030405060708090A0B0C0D0E0F1011121314151617';
    expect(ccmDecrypt(key, ccmEncrypt(key, plaintext, nonce, aad, 16), nonce, aad, 16)).toBe(plaintext);
  });
  it('AES-256 with AAD', () => {
    const key = '000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F';
    expect(ccmDecrypt(key, ccmEncrypt(key, plaintext, nonce, aad, 16), nonce, aad, 16)).toBe(plaintext);
  });
  it('without AAD', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    expect(ccmDecrypt(key, ccmEncrypt(key, plaintext, nonce, undefined, 16), nonce, undefined, 16)).toBe(plaintext);
  });
  it('empty plaintext (tag only)', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    const ct = ccmEncrypt(key, '', nonce, aad, 16);
    expect(ct.length).toBe(32); // 16-byte tag
    expect(ccmDecrypt(key, ct, nonce, aad, 16)).toBe('');
  });
  it('different tag lengths produce different output sizes', () => {
    const key = '000102030405060708090A0B0C0D0E0F';
    const ct8 = ccmEncrypt(key, plaintext, nonce, aad, 8);
    const ct16 = ccmEncrypt(key, plaintext, nonce, aad, 16);
    expect(ct16.length - ct8.length).toBe(16);
  });
});

describe('AES-CCM — authentication failures', () => {
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
    expect(() => ccmDecrypt('FF0102030405060708090A0B0C0D0E0F', ct, nonce, aad, 16)).toThrow(/authentication failed/);
  });
});

describe('AES-CCM — parameter validation', () => {
  const key = '000102030405060708090A0B0C0D0E0F';
  const nonce12 = '00112233445566778899AABB';

  it('rejects invalid key length', () => {
    expect(() => ccmEncrypt('0011', 'AA', nonce12, undefined, 16)).toThrow(/key must be 16\/24\/32 bytes/);
  });
  it('rejects nonce < 7 bytes', () => {
    expect(() => ccmEncrypt(key, 'AA', '001122334455', undefined, 16)).toThrow(/nonce must be 7-13 bytes/);
  });
  it('rejects nonce > 13 bytes', () => {
    expect(() => ccmEncrypt(key, 'AA', '00112233445566778899AABBCCDD', undefined, 16)).toThrow(/nonce must be 7-13 bytes/);
  });
  it('rejects invalid tag length', () => {
    expect(() => ccmEncrypt(key, 'AA', nonce12, undefined, 5)).toThrow(/tag length must be one of/);
    expect(() => ccmEncrypt(key, 'AA', nonce12, undefined, 18)).toThrow(/tag length must be one of/);
  });
  it('rejects input shorter than tag on decrypt', () => {
    expect(() => ccmDecrypt(key, 'AABB', nonce12, undefined, 16)).toThrow(/input shorter than tag length/);
  });
});
