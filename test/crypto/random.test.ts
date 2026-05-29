import { describe, it, expect } from 'vitest';
import { bytes } from '../../src/crypto/random.ts';

// CSPRNG — Web Crypto getRandomValues wrapper.

describe('Random (CSPRNG)', () => {
  it('produces hex string of correct length', () => {
    const res = bytes(32);
    expect(res.length).toBe(64); // 32 bytes = 64 hex chars
  });

  it('two calls produce different output', () => {
    const a = bytes(32);
    const b = bytes(32);
    expect(a).not.toBe(b);
  });
});
