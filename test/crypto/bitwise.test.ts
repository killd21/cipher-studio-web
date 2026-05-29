import { describe, it, expect } from 'vitest';
import { xor, and, or, not, shiftLeft, shiftRight } from '../../src/crypto/bitwise.ts';

// Bitwise operations on hex strings.

describe('XOR', () => {
  it('AABB XOR 1234 = B88F', () => {
    expect(xor('AA BB', '12 34')).toBe('B88F');
  });
  it('FF XOR FF = 00', () => {
    expect(xor('FF', 'FF')).toBe('00');
  });
  it('AA XOR 55 = FF', () => {
    expect(xor('AA', '55')).toBe('FF');
  });
});

describe('AND', () => {
  it('FF AND 0F = 0F', () => expect(and('FF', '0F')).toBe('0F'));
  it('AABB AND FF00 = AA00', () => expect(and('AABB', 'FF00')).toBe('AA00'));
});

describe('OR', () => {
  it('F0 OR 0F = FF', () => expect(or('F0', '0F')).toBe('FF'));
  it('AA00 OR 00BB = AABB', () => expect(or('AA00', '00BB')).toBe('AABB'));
});

describe('NOT', () => {
  it('NOT FF = 00', () => expect(not('FF')).toBe('00'));
  it('NOT 00 = FF', () => expect(not('00')).toBe('FF'));
  it('NOT A5 = 5A', () => expect(not('A5')).toBe('5A'));
});

describe('Shift Left', () => {
  it('01 << 4 = 10', () => expect(shiftLeft('01', 4)).toBe('10'));
  it('01 << 1 = 02', () => expect(shiftLeft('01', 1)).toBe('02'));
  it('0080 << 1 = 0100', () => expect(shiftLeft('0080', 1)).toBe('0100'));
  it('FF << 8 = 00 (shift out)', () => expect(shiftLeft('FF', 8)).toBe('00'));
  it('00FF << 4 = 0FF0', () => expect(shiftLeft('00FF', 4)).toBe('0FF0'));
});

describe('Shift Right', () => {
  it('80 >> 1 = 40', () => expect(shiftRight('80', 1)).toBe('40'));
  it('10 >> 4 = 01', () => expect(shiftRight('10', 4)).toBe('01'));
  it('0100 >> 1 = 0080', () => expect(shiftRight('0100', 1)).toBe('0080'));
  it('FF >> 8 = 00 (shift out)', () => expect(shiftRight('FF', 8)).toBe('00'));
  it('FF00 >> 4 = 0FF0', () => expect(shiftRight('FF00', 4)).toBe('0FF0'));
});
