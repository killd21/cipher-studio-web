import { sm3 as sm3Lib } from 'sm-crypto';
import { toBuf } from './hex-utils.ts';

// SM3 — GM/T 0004 · ISO/IEC 10118-3:2018. 256-bit hash.
// Input/output: hex string (matches project convention).

export function hash(dataHex: string): string {
  const bytes = Array.from(toBuf(dataHex));
  return sm3Lib(bytes).toUpperCase();
}
