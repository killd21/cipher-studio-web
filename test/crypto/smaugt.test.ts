import { describe, it, expect } from 'vitest';
import { smaugtKeygen, smaugtEncapsulate, smaugtDecapsulate } from '../../src/crypto/pqc.ts';

// SMAUG-T / TiMER — KpqC competition KEM. Lattice-based (Module-LWE / Module-LWR).
// Variants: smaugt128, smaugt192, smaugt256, timer (related cipher published together).

describe('SMAUG-T 128', () => {
  it('keygen / encap / decap roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await smaugtKeygen('128');
    expect(publicKey.length).toBeGreaterThan(0);
    expect(secretKey.length).toBeGreaterThan(0);
    const { ciphertext, sharedSecret: ss1 } = await smaugtEncapsulate('128', publicKey);
    const ss2 = await smaugtDecapsulate('128', secretKey, ciphertext);
    expect(ss2).toBe(ss1);
  });

  it('different encapsulations yield different shared secrets', { timeout: 60000 }, async () => {
    const { publicKey } = await smaugtKeygen('128');
    const e1 = await smaugtEncapsulate('128', publicKey);
    const e2 = await smaugtEncapsulate('128', publicKey);
    expect(e1.sharedSecret).not.toBe(e2.sharedSecret);
  });
});

describe('SMAUG-T 192', () => {
  it('roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await smaugtKeygen('192');
    const { ciphertext, sharedSecret: ss1 } = await smaugtEncapsulate('192', publicKey);
    expect(await smaugtDecapsulate('192', secretKey, ciphertext)).toBe(ss1);
  });
});

describe('SMAUG-T 256', () => {
  it('roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await smaugtKeygen('256');
    const { ciphertext, sharedSecret: ss1 } = await smaugtEncapsulate('256', publicKey);
    expect(await smaugtDecapsulate('256', secretKey, ciphertext)).toBe(ss1);
  });
});

describe('TiMER (related cipher)', () => {
  it('roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await smaugtKeygen('timer');
    const { ciphertext, sharedSecret: ss1 } = await smaugtEncapsulate('timer', publicKey);
    expect(await smaugtDecapsulate('timer', secretKey, ciphertext)).toBe(ss1);
  });
});

describe('SMAUG-T error handling', () => {
  it('throws on unknown variant', async () => {
    await expect(smaugtKeygen('999' as never)).rejects.toThrow('Unknown SMAUG-T variant');
  });
});
