import { describe, it, expect } from 'vitest';
import { hmac, cmacAes, desMac, retailMac } from '../../src/crypto/mac.ts';
import { ecbEncrypt } from '../../src/crypto/des.ts';

describe('Phase 4: MAC', () => {
  it('HMAC-SHA256', () => {
    const key = '6b6579'; // "key"
    const data = '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67'; // "The quick brown fox jumps over the lazy dog"
    const expected = 'F7BC83F430538424B13298E6AA6FB143EF4D59A14946175997479DBC2D1A3CD8';
    expect(hmac('sha256', key, data)).toBe(expected);
  });

  it('AES-CMAC RFC 4493 (empty message)', () => {
    const key = '2b7e151628aed2a6abf7158809cf4f3c';
    const data = '';
    const expected = 'BB1D6929E95937287FA37D129B756746';
    expect(cmacAes(key, data)).toBe(expected);
  });

  it('AES-CMAC RFC 4493 (16-byte message)', () => {
    const key = '2b7e151628aed2a6abf7158809cf4f3c';
    const data = '6bc1bee22e409f96e93d7e117393172a';
    const expected = '070A16B46B4D4144F79BDD9DD04A287C';
    expect(cmacAes(key, data)).toBe(expected);
  });

  it('DES Mac (CBC-MAC) simple check', () => {
    const key = '0123456789ABCDEF';
    const data = '1122334455667788';
    const res = desMac(key, data, '0000000000000000', 8, 'none');
    // For 1 block CBC-MAC is just ECB
    expect(res).toBe(ecbEncrypt(key, data));
  });

  it('Retail MAC check', () => {
    const key = '0123456789ABCDEF0123456789ABCDEF';
    const data = '1122334455667788';
    const res = retailMac(key, data, '0000000000000000', 'none');
    expect(res.length).toBe(16);
  });
});
