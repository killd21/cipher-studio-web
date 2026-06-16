import { describe, it, expect } from 'vitest';
import { ntruplusKeygen, ntruplusEncapsulate, ntruplusDecapsulate } from '../../src/crypto/pqc.ts';

// NTRU+ — KpqC competition KEM. Lattice-based (NTRU).
// Variants: ntruplus768, ntruplus864, ntruplus1152.

describe('NTRU+768', () => {
  it('keygen / encap / decap roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await ntruplusKeygen('768');
    expect(publicKey.length).toBeGreaterThan(0);
    expect(secretKey.length).toBeGreaterThan(0);
    const { ciphertext, sharedSecret: ss1 } = await ntruplusEncapsulate('768', publicKey);
    expect(ciphertext.length).toBeGreaterThan(0);
    expect(ss1.length).toBeGreaterThan(0);
    const ss2 = await ntruplusDecapsulate('768', secretKey, ciphertext);
    expect(ss2).toBe(ss1);
  });

  it('different encapsulations yield different shared secrets', { timeout: 60000 }, async () => {
    const { publicKey } = await ntruplusKeygen('768');
    const e1 = await ntruplusEncapsulate('768', publicKey);
    const e2 = await ntruplusEncapsulate('768', publicKey);
    expect(e1.sharedSecret).not.toBe(e2.sharedSecret);
  });
});

describe('NTRU+864', () => {
  it('roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await ntruplusKeygen('864');
    const { ciphertext, sharedSecret: ss1 } = await ntruplusEncapsulate('864', publicKey);
    expect(await ntruplusDecapsulate('864', secretKey, ciphertext)).toBe(ss1);
  });
});

describe('NTRU+1152', () => {
  it('roundtrip', { timeout: 60000 }, async () => {
    const { publicKey, secretKey } = await ntruplusKeygen('1152');
    const { ciphertext, sharedSecret: ss1 } = await ntruplusEncapsulate('1152', publicKey);
    expect(await ntruplusDecapsulate('1152', secretKey, ciphertext)).toBe(ss1);
  });
});

describe('NTRU+ error handling', () => {
  it('throws on unknown variant', async () => {
    await expect(ntruplusKeygen('999' as never)).rejects.toThrow('Unknown NTRU+ variant');
  });
});
