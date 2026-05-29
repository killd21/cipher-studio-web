import { describe, it, expect } from 'vitest';
import { kemKeygen, kemEncapsulate, kemDecapsulate } from '../../src/crypto/pqc.ts';

// ML-KEM — FIPS 203. Variants: 512, 768, 1024.

describe('ML-KEM-512', () => {
  it('keygen / encap / decap roundtrip', () => {
    const { ek, dk } = kemKeygen(512);
    const { ciphertext, sharedSecret: ss1 } = kemEncapsulate(512, ek);
    expect(kemDecapsulate(512, dk, ciphertext)).toBe(ss1);
  });
});

describe('ML-KEM-768', () => {
  it('keygen / encap / decap roundtrip', () => {
    const { ek, dk } = kemKeygen(768);
    const { ciphertext, sharedSecret: ss1 } = kemEncapsulate(768, ek);
    expect(kemDecapsulate(768, dk, ciphertext)).toBe(ss1);
  });
});

describe('ML-KEM-1024', () => {
  it('keygen produces valid keys', () => {
    const { ek, dk } = kemKeygen(1024);
    expect(ek.length).toBeGreaterThan(0);
    expect(dk.length).toBeGreaterThan(0);
  });

  it('encap / decap roundtrip — 32-byte shared secret', () => {
    const { ek, dk } = kemKeygen(1024);
    const { ciphertext, sharedSecret: ss1 } = kemEncapsulate(1024, ek);
    const ss2 = kemDecapsulate(1024, dk, ciphertext);
    expect(ss1).toBe(ss2);
    expect(ss1.length).toBe(64);
  });

  it('different encapsulations yield different shared secrets', () => {
    const { ek } = kemKeygen(1024);
    expect(kemEncapsulate(1024, ek).sharedSecret)
      .not.toBe(kemEncapsulate(1024, ek).sharedSecret);
  });

  it('string variant "1024" works', () => {
    const { ek, dk } = kemKeygen('1024');
    const { ciphertext, sharedSecret: ss1 } = kemEncapsulate('1024', ek);
    expect(kemDecapsulate('1024', dk, ciphertext)).toBe(ss1);
  });
});
