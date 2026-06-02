import { describe, it, expect } from 'vitest';
import { hash } from '../../src/crypto/sm3.ts';
import { digest } from '../../src/crypto/hash.ts';

// SM3 — GM/T 0004 · ISO/IEC 10118-3:2018. 256-bit hash.
// Official test vectors from GM/T 0004-2012 Appendix A.

describe('SM3 (GM/T 0004)', () => {
  it('empty input → 1AB21D8355...', () => {
    expect(hash('')).toBe('1AB21D8355CFA17F8E61194831E81A8F22BEC8C728FEFB747ED035EB5082AA2B');
  });

  it('"abc" (616263) → 66C7F0F4...', () => {
    expect(hash('616263')).toBe('66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0');
  });

  // GM/T 0004 Appendix A.2: 64 bytes of "abcd" repeated
  it('GM/T 0004 §A.2: 64 bytes ("abcd"×16) → DEBE9FF9...', () => {
    const abcd = '61626364';
    const data = abcd.repeat(16); // 64 bytes
    expect(hash(data)).toBe('DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732');
  });
});

describe('SM3 via hash.digest() dispatcher', () => {
  it('routes "sm3" → matches direct hash()', async () => {
    expect(await digest('sm3', '616263')).toBe('66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0');
  });
});
