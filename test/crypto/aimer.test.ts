import { describe, it, expect } from 'vitest';
import { aimerKeygen, aimerSign, aimerVerify } from '../../src/crypto/pqc.ts';

// AIMer — KpqC (Korean Post-Quantum Cryptography) competition winner.
// MPCitH (MPC-in-the-Head) signature scheme. 6 parameter sets across 3 security levels.

describe('AIMer-128f (fast, 128-bit security)', () => {
  it('keygen / sign / verify roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await aimerKeygen('128f');
    expect(publicKey.length).toBeGreaterThan(0);
    expect(secretKey.length).toBeGreaterThan(0);
    const msg = '48656C6C6F20416C4D6572'; // "Hello AlMer"
    const sig = await aimerSign('128f', secretKey, msg);
    expect(sig.length).toBeGreaterThan(0);
    expect(await aimerVerify('128f', publicKey, msg, sig)).toBe(true);
  });

  it('verify rejects tampered message', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await aimerKeygen('128f');
    const msg = 'AABBCCDD';
    const sig = await aimerSign('128f', secretKey, msg);
    expect(await aimerVerify('128f', publicKey, msg + '00', sig)).toBe(false);
  });

  it('verify rejects wrong public key', { timeout: 60000 }, async () => {
    const kp1 = await aimerKeygen('128f');
    const kp2 = await aimerKeygen('128f');
    const msg = 'CAFEBABE';
    const sig = await aimerSign('128f', kp1.secretKey, msg);
    expect(await aimerVerify('128f', kp2.publicKey, msg, sig)).toBe(false);
  });
});

describe('AIMer-192s (small, 192-bit security)', () => {
  it('keygen / sign / verify roundtrip', { timeout: 120000 }, async () => {
    const { publicKey, secretKey } = await aimerKeygen('192s');
    const msg = 'DEADBEEF';
    const sig = await aimerSign('192s', secretKey, msg);
    expect(await aimerVerify('192s', publicKey, msg, sig)).toBe(true);
  });
});

describe('AIMer-256f (fast, 256-bit security)', () => {
  it('keygen / sign / verify roundtrip', { timeout: 120000 }, async () => {
    const { publicKey, secretKey } = await aimerKeygen('256f');
    const msg = '0102030405060708';
    const sig = await aimerSign('256f', secretKey, msg);
    expect(await aimerVerify('256f', publicKey, msg, sig)).toBe(true);
  });
});

describe('AIMer with context (domain binding)', () => {
  it('same context → verify succeeds', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await aimerKeygen('128f');
    const msg = 'AABB';
    const ctx = '4170703A4D7950726F64'; // "App:MyProd"
    const sig = await aimerSign('128f', secretKey, msg, ctx);
    expect(await aimerVerify('128f', publicKey, msg, sig, ctx)).toBe(true);
  });

  it('different context → verify fails', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await aimerKeygen('128f');
    const msg = 'AABB';
    const sig = await aimerSign('128f', secretKey, msg, '4170703A41');
    expect(await aimerVerify('128f', publicKey, msg, sig, '4170703A42')).toBe(false);
  });

  it('signing with context, verifying without context → fails', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await aimerKeygen('128f');
    const msg = 'AABB';
    const sig = await aimerSign('128f', secretKey, msg, 'F00D');
    expect(await aimerVerify('128f', publicKey, msg, sig)).toBe(false);
  });
});

describe('AIMer error handling', () => {
  it('throws on unknown variant', async () => {
    await expect(aimerKeygen('999x' as never)).rejects.toThrow('Unknown AIMer variant');
  });
});
