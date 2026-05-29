import { describe, it, expect } from 'vitest';
import { digest } from '../../src/crypto/hash.ts';

// Hash functions — FIPS 180-4 (SHA-1/2) · FIPS 202 (SHA-3/SHAKE) · RFC 1321 (MD5) · RFC 7693 (BLAKE2).

describe('MD5 (RFC 1321)', () => {
  it('MD5 of empty string', async () => {
    expect(await digest('md5', '')).toBe('D41D8CD98F00B204E9800998ECF8427E');
  });
});

describe('SHA-1 (FIPS 180-4)', () => {
  it('SHA-1 of "abc"', async () => {
    expect(await digest('sha1', '616263')).toBe('A9993E364706816ABA3E25717850C26C9CD0D89D');
  });
});

describe('SHA-2 (FIPS 180-4)', () => {
  it('SHA-256 of empty string', async () => {
    expect(await digest('sha256', '')).toBe('E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855');
  });
  it('SHA-256 of "abc"', async () => {
    expect(await digest('sha256', '616263')).toBe('BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD');
  });
});

describe('SHA-3 (FIPS 202)', () => {
  it('SHA3-256 of "abc"', async () => {
    expect(await digest('sha3-256', '616263')).toBe('3A985DA74FE225B2045C172D6BD390BD855F086E3E9D525B46BFE24511431532');
  });
  it('SHA3-384 of "abc"', async () => {
    expect(await digest('sha3-384', '616263')).toBe('EC01498288516FC926459F58E2C6AD8DF9B473CB0FC08C2596DA7CF0E49BE4B298D88CEA927AC7F539F1EDF228376D25');
  });
  it('SHA3-512 of "abc"', async () => {
    expect(await digest('sha3-512', '616263')).toBe('B751850B1A57168A5693CD924B6B096E08F621827444F70D884F5D0240D2712E10E116E9192AF3C91A7EC57647E3934057340B4CF408D5A56592F8274EEC53F0');
  });
  it('SHA3-256 of empty string', async () => {
    expect(await digest('sha3-256', '')).toBe('A7FFC6F8BF1ED76651C14756A061D662F580FF4DE43B49FA82D80A4B80F8434A');
  });
});

describe('SHAKE (FIPS 202)', () => {
  it('SHAKE128 default 32-byte output', async () => {
    expect((await digest('shake128', '616263')).length).toBe(64);
  });
  it('SHAKE128 custom output length 16 bytes', async () => {
    expect((await digest('shake128', '616263', 16)).length).toBe(32);
  });
  it('SHAKE256 default 64-byte output', async () => {
    expect((await digest('shake256', '616263')).length).toBe(128);
  });
  it('SHAKE256 custom output length 48 bytes', async () => {
    expect((await digest('shake256', '616263', 48)).length).toBe(96);
  });
});

describe('BLAKE2 (RFC 7693)', () => {
  it('BLAKE2b-512 of empty string', async () => {
    expect(await digest('blake2b', '', 64)).toBe('786A02F742015903C6C6FD852552D272912F4740E15847618A86E217F71F5419D25E1031AFEE585313896444934EB04B903A685B1448B755D56F701AFE9BE2CE');
  });
  it('BLAKE2b-256 of "abc"', async () => {
    expect((await digest('blake2b', '616263', 32)).length).toBe(64);
  });
  it('BLAKE2s-256 of empty string', async () => {
    expect(await digest('blake2s', '', 32)).toBe('69217A3079908094E11121D042354A7C1F55B6482CA1A51E1B250DFD1ED0EEF9');
  });
});

describe('BLAKE3', () => {
  it('BLAKE3 of empty string', async () => {
    expect(await digest('blake3', '', 32)).toBe('AF1349B9F5F9A1A6A0404DEA36DCC9499BCB25C9ADC112B7CC9A93CAE41F3262');
  });
  it('BLAKE3 with custom output length 64 bytes', async () => {
    expect((await digest('blake3', '616263', 64)).length).toBe(128);
  });
});

describe('RIPEMD-160', () => {
  it('RIPEMD-160 of empty string', async () => {
    expect(await digest('ripemd160', '')).toBe('9C1185A5C5E9FC54612808977EE8F548B2258D31');
  });
  it('RIPEMD-160 of "abc"', async () => {
    expect(await digest('ripemd160', '616263')).toBe('8EB208F7E05D987A9B044A8E98C6B087F15A0BFC');
  });
});
