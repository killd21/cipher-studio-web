import { describe, it, expect } from 'vitest';
import { digest } from '../../src/crypto/hash.ts';
import { hkdfDerive, hkdfExtract, hkdfExpand, pbkdf2Derive } from '../../src/crypto/kdf.ts';
import { slhKeygen, slhSign, slhVerify } from '../../src/crypto/pqc.ts';
import { hexToBase64, base64ToHex, hexToBase64Url, base64UrlToHex } from '../../src/crypto/base64.ts';

// ═══════════════════════════════════════════════════════════
// Task 3.1: KDF (HKDF, PBKDF2)
// ═══════════════════════════════════════════════════════════
describe('HKDF (RFC 5869)', () => {
  // RFC 5869 Test Case 1: SHA-256 basic
  const ikm = '0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B0B';
  const salt = '000102030405060708090A0B0C';
  const info = 'F0F1F2F3F4F5F6F7F8F9';
  const expectedPrk = '077709362C2E32DF0DDC3F0DC47BBA6390B6C73BB50F9C3122EC844AD7C2B3E5';
  const expectedOkm = '3CB25F25FAACD57A90434F64D0362F2A2D2D0A90CF1A5A4C5DB02D56ECC4C5BF34007208D5B887185865';

  it('Extract phase produces correct PRK', () => {
    expect(hkdfExtract('sha256', ikm, salt)).toBe(expectedPrk);
  });

  it('Expand phase produces correct OKM (42 bytes)', () => {
    expect(hkdfExpand('sha256', expectedPrk, info, 42)).toBe(expectedOkm);
  });

  it('Full HKDF derive produces correct OKM', () => {
    expect(hkdfDerive('sha256', ikm, salt, info, 42)).toBe(expectedOkm);
  });

  it('HKDF with empty salt works', () => {
    const result = hkdfDerive('sha256', '0B0B0B', '', '', 32);
    expect(result.length).toBe(64); // 32 bytes
  });

  it('HKDF with SHA-512 produces different output', () => {
    const r256 = hkdfDerive('sha256', ikm, salt, info, 32);
    const r512 = hkdfDerive('sha512', ikm, salt, info, 32);
    expect(r256).not.toBe(r512);
  });

  it('HKDF with SHA3-256 works', () => {
    const result = hkdfDerive('sha3-256', ikm, salt, info, 32);
    expect(result.length).toBe(64);
  });
});

describe('PBKDF2 (RFC 6070)', () => {
  // RFC 6070 Test Case 1
  it('SHA-1 with 1 iteration, "password"/"salt"', async () => {
    const password = '70617373776F7264'; // "password"
    const salt = '73616C74'; // "salt"
    const result = await pbkdf2Derive('sha1', password, salt, 1, 20);
    expect(result).toBe('0C60C80F961F0E71F3A9B524AF6012062FE037A6');
  });

  it('SHA-1 with 2 iterations', async () => {
    const password = '70617373776F7264';
    const salt = '73616C74';
    const result = await pbkdf2Derive('sha1', password, salt, 2, 20);
    expect(result).toBe('EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957');
  });

  it('SHA-256 with 1000 iterations', async () => {
    const password = '70617373776F7264';
    const salt = '73616C74';
    const result = await pbkdf2Derive('sha256', password, salt, 1000, 32);
    expect(result.length).toBe(64); // 32 bytes
  });

  it('PBKDF2 SHA-512 produces different output', async () => {
    const password = '70617373776F7264';
    const salt = '73616C74';
    const r256 = await pbkdf2Derive('sha256', password, salt, 100, 32);
    const r512 = await pbkdf2Derive('sha512', password, salt, 100, 32);
    expect(r256).not.toBe(r512);
  });
});

// ═══════════════════════════════════════════════════════════
// Task 3.2: SLH-DSA (FIPS 205)
// ═══════════════════════════════════════════════════════════
describe('SLH-DSA (FIPS 205)', () => {
  it('SHAKE-128f keygen produces valid keys', { timeout: 30000 }, () => {
    const { publicKey, secretKey } = slhKeygen('shake-128f');
    expect(publicKey.length).toBe(64);  // 32 bytes
    expect(secretKey.length).toBe(128); // 64 bytes
  });

  it('SHAKE-128f sign/verify roundtrip', { timeout: 60000 }, () => {
    const { publicKey, secretKey } = slhKeygen('shake-128f');
    const msg = '48656C6C6F20576F726C64';
    const sig = slhSign('shake-128f', secretKey, msg);
    expect(sig.length).toBeGreaterThan(0);
    expect(slhVerify('shake-128f', publicKey, msg, sig)).toBe(true);
  });

  it('SHA2-128f sign/verify roundtrip', { timeout: 60000 }, () => {
    const { publicKey, secretKey } = slhKeygen('sha2-128f');
    const msg = 'CAFEBABE';
    const sig = slhSign('sha2-128f', secretKey, msg);
    expect(slhVerify('sha2-128f', publicKey, msg, sig)).toBe(true);
  });

  it('verify rejects tampered message', { timeout: 60000 }, () => {
    const { publicKey, secretKey } = slhKeygen('shake-128f');
    const msg = 'AABBCCDD';
    const sig = slhSign('shake-128f', secretKey, msg);
    expect(slhVerify('shake-128f', publicKey, msg + '00', sig)).toBe(false);
  });

  it('throws on unknown variant', () => {
    expect(() => slhKeygen('invalid' as any)).toThrow('Unknown SLH-DSA variant');
  });
});

// ═══════════════════════════════════════════════════════════
// Task 3.3: Base64 Encoding
// ═══════════════════════════════════════════════════════════
describe('Base64', () => {
  it('hexToBase64: "Hello" → "SGVsbG8="', () => {
    expect(hexToBase64('48656C6C6F')).toBe('SGVsbG8=');
  });

  it('base64ToHex: "SGVsbG8=" → "Hello"', () => {
    expect(base64ToHex('SGVsbG8=')).toBe('48656C6C6F'.toUpperCase());
  });

  it('roundtrip: hex → base64 → hex', () => {
    const original = 'DEADBEEFCAFEBABE0102030405';
    const b64 = hexToBase64(original);
    const back = base64ToHex(b64);
    expect(back).toBe(original);
  });

  it('Base64url: hex → base64url (no padding, - and _)', () => {
    // "??>>" encodes to bytes that need + and / in standard base64
    const hex = 'FBEFFF';
    const b64 = hexToBase64(hex);
    const b64url = hexToBase64Url(hex);
    expect(b64).toContain('+');
    expect(b64url).not.toContain('+');
    expect(b64url).not.toContain('/');
    expect(b64url).not.toContain('=');
  });

  it('Base64url roundtrip', () => {
    const original = 'FBEFFFAABBCCDD';
    const url = hexToBase64Url(original);
    expect(base64UrlToHex(url)).toBe(original);
  });

  it('empty input', () => {
    expect(hexToBase64('')).toBe('');
    expect(base64ToHex('')).toBe('');
  });
});

// ═══════════════════════════════════════════════════════════
// Task 3.4: BLAKE2b/s, BLAKE3, RIPEMD-160
// ═══════════════════════════════════════════════════════════
describe('BLAKE / RIPEMD hashes', () => {
  // BLAKE2b-512 of empty string (RFC 7693)
  it('BLAKE2b-512 of empty string', async () => {
    const result = await digest('blake2b', '', 64);
    expect(result).toBe('786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE');
  });

  // BLAKE2b-256 of "abc"
  it('BLAKE2b-256 of "abc"', async () => {
    const result = await digest('blake2b', '616263', 32);
    expect(result.length).toBe(64);
  });

  // BLAKE2s-256 of empty string
  it('BLAKE2s-256 of empty string', async () => {
    const result = await digest('blake2s', '', 32);
    expect(result).toBe('69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9');
  });

  // BLAKE3 of empty string
  it('BLAKE3 of empty string', async () => {
    const result = await digest('blake3', '', 32);
    expect(result).toBe('AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262');
  });

  // BLAKE3 variable output length
  it('BLAKE3 with custom output length', async () => {
    const result = await digest('blake3', '616263', 64);
    expect(result.length).toBe(128); // 64 bytes
  });

  // RIPEMD-160 of empty string
  it('RIPEMD-160 of empty string', async () => {
    const result = await digest('ripemd160', '');
    expect(result).toBe('9C1185A5C5E9FC54612808977EE8F548B2258D31');
  });

  // RIPEMD-160 of "abc"
  it('RIPEMD-160 of "abc"', async () => {
    const result = await digest('ripemd160', '616263');
    expect(result).toBe('8EB208F7E05D987A9B044A8E98C6B087F15A0BFC');
  });
});
