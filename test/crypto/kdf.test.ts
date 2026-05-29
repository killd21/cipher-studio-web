import { describe, it, expect } from 'vitest';
import { hkdfDerive, hkdfExtract, hkdfExpand, pbkdf2Derive } from '../../src/crypto/kdf.ts';

// KDF — RFC 5869 (HKDF) · RFC 8018 (PBKDF2).

describe('HKDF (RFC 5869 Test Case 1)', () => {
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

  it('Full HKDF derive matches Extract+Expand', () => {
    expect(hkdfDerive('sha256', ikm, salt, info, 42)).toBe(expectedOkm);
  });

  it('empty salt is allowed', () => {
    expect(hkdfDerive('sha256', '0B0B0B', '', '', 32).length).toBe(64);
  });

  it('SHA-512 produces different output from SHA-256', () => {
    expect(hkdfDerive('sha256', ikm, salt, info, 32))
      .not.toBe(hkdfDerive('sha512', ikm, salt, info, 32));
  });

  it('SHA3-256 works', () => {
    expect(hkdfDerive('sha3-256', ikm, salt, info, 32).length).toBe(64);
  });
});

describe('PBKDF2 (RFC 6070)', () => {
  const password = '70617373776F7264'; // "password"
  const salt = '73616C74';              // "salt"

  it('SHA-1 with 1 iteration', async () => {
    expect(await pbkdf2Derive('sha1', password, salt, 1, 20)).toBe('0C60C80F961F0E71F3A9B524AF6012062FE037A6');
  });

  it('SHA-1 with 2 iterations', async () => {
    expect(await pbkdf2Derive('sha1', password, salt, 2, 20)).toBe('EA6C014DC72D6F8CCD1ED92ACE1D41F0D8DE8957');
  });

  it('SHA-256 with 1000 iterations produces 32-byte key', async () => {
    expect((await pbkdf2Derive('sha256', password, salt, 1000, 32)).length).toBe(64);
  });

  it('SHA-512 produces different output from SHA-256', async () => {
    const r256 = await pbkdf2Derive('sha256', password, salt, 100, 32);
    const r512 = await pbkdf2Derive('sha512', password, salt, 100, 32);
    expect(r256).not.toBe(r512);
  });
});
