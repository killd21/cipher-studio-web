import { describe, it, expect } from 'vitest';
import { hexToBase64, base64ToHex, hexToBase64Url, base64UrlToHex } from '../../src/crypto/base64.ts';

// Base64 / Base64url encoding — RFC 4648.

describe('Base64', () => {
  it('hexToBase64: "Hello" → "SGVsbG8="', () => {
    expect(hexToBase64('48656C6C6F')).toBe('SGVsbG8=');
  });

  it('base64ToHex: "SGVsbG8=" → "Hello"', () => {
    expect(base64ToHex('SGVsbG8=')).toBe('48656C6C6F');
  });

  it('roundtrip: hex → base64 → hex', () => {
    const hex = 'DEADBEEFCAFEBABE0102030405';
    expect(base64ToHex(hexToBase64(hex))).toBe(hex);
  });

  it('empty input', () => {
    expect(hexToBase64('')).toBe('');
    expect(base64ToHex('')).toBe('');
  });
});

describe('Base64url (URL-safe)', () => {
  it('base64url has no + / =', () => {
    const hex = 'FBEFFF';
    expect(hexToBase64(hex)).toContain('+');
    const url = hexToBase64Url(hex);
    expect(url).not.toContain('+');
    expect(url).not.toContain('/');
    expect(url).not.toContain('=');
  });

  it('roundtrip: hex → base64url → hex', () => {
    const hex = 'FBEFFFAABBCCDD';
    expect(base64UrlToHex(hexToBase64Url(hex))).toBe(hex);
  });
});
