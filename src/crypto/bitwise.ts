import { toBuf, toHex } from './hex-utils.ts';

export function xor(hexA: string, hexB: string): string {
  const a = toBuf(hexA);
  const b = toBuf(hexB);
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i]! ^ b[i]!;
  }
  return toHex(result);
}
