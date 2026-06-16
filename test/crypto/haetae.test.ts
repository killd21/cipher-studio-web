import { describe, it, expect } from 'vitest';
import { haetaeKeygen, haetaeSign, haetaeVerify } from '../../src/crypto/pqc.ts';

// HAETAE — KpqC competition signature scheme. Lattice-based (Module-LWE / NTRU).
// Variants: haetae2 (128-bit), haetae3 (192-bit), haetae5 (256-bit).

describe('HAETAE-Mode2 (128-bit security)', () => {
  it('keygen / sign / verify roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await haetaeKeygen('2');
    expect(publicKey.length).toBeGreaterThan(0);
    expect(secretKey.length).toBeGreaterThan(0);
    const msg = '48656C6C6F20484145544145';
    const sig = await haetaeSign('2', secretKey, msg);
    expect(sig.length).toBeGreaterThan(0);
    expect(await haetaeVerify('2', publicKey, msg, sig)).toBe(true);
  });

  it('verify rejects tampered message', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await haetaeKeygen('2');
    const sig = await haetaeSign('2', secretKey, 'AABB');
    expect(await haetaeVerify('2', publicKey, 'AABB00', sig)).toBe(false);
  });

  it('verify rejects wrong public key', { timeout: 60000 }, async () => {
    const kp1 = await haetaeKeygen('2');
    const kp2 = await haetaeKeygen('2');
    const sig = await haetaeSign('2', kp1.secretKey, 'CAFEBABE');
    expect(await haetaeVerify('2', kp2.publicKey, 'CAFEBABE', sig)).toBe(false);
  });
});

describe('HAETAE-Mode3 (192-bit)', () => {
  it('keygen / sign / verify roundtrip', { timeout: 120000 }, async () => {
    const { publicKey, secretKey } = await haetaeKeygen('3');
    const msg = 'DEADBEEF';
    const sig = await haetaeSign('3', secretKey, msg);
    expect(await haetaeVerify('3', publicKey, msg, sig)).toBe(true);
  });
});

describe('HAETAE-Mode5 (256-bit)', () => {
  it('keygen / sign / verify roundtrip', { timeout: 120000 }, async () => {
    const { publicKey, secretKey } = await haetaeKeygen('5');
    const msg = '0102030405060708';
    const sig = await haetaeSign('5', secretKey, msg);
    expect(await haetaeVerify('5', publicKey, msg, sig)).toBe(true);
  });
});

describe('HAETAE error handling', () => {
  it('throws on unknown variant', async () => {
    await expect(haetaeKeygen('99' as never)).rejects.toThrow('Unknown HAETAE variant');
  });
});
