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

export function and(hexA: string, hexB: string): string {
  const a = toBuf(hexA);
  const b = toBuf(hexB);
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i]! & b[i]!;
  }
  return toHex(result);
}

export function or(hexA: string, hexB: string): string {
  const a = toBuf(hexA);
  const b = toBuf(hexB);
  const len = Math.min(a.length, b.length);
  const result = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    result[i] = a[i]! | b[i]!;
  }
  return toHex(result);
}

export function not(hexA: string): string {
  const a = toBuf(hexA);
  const result = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i++) {
    result[i] = ~a[i]! & 0xFF;
  }
  return toHex(result);
}

export function shiftLeft(hexA: string, bits: number): string {
  const a = toBuf(hexA);
  const result = new Uint8Array(a.length);
  const byteShift = Math.floor(bits / 8);
  const bitShift = bits % 8;
  for (let i = 0; i < a.length; i++) {
    const srcIdx = i + byteShift;
    if (srcIdx < a.length) {
      result[i] = (a[srcIdx]! << bitShift) & 0xFF;
      if (bitShift > 0 && srcIdx + 1 < a.length) {
        result[i]! |= a[srcIdx + 1]! >>> (8 - bitShift);
      }
    }
  }
  return toHex(result);
}

export function shiftRight(hexA: string, bits: number): string {
  const a = toBuf(hexA);
  const result = new Uint8Array(a.length);
  const byteShift = Math.floor(bits / 8);
  const bitShift = bits % 8;
  for (let i = a.length - 1; i >= 0; i--) {
    const srcIdx = i - byteShift;
    if (srcIdx >= 0) {
      result[i] = a[srcIdx]! >>> bitShift;
      if (bitShift > 0 && srcIdx - 1 >= 0) {
        result[i]! |= (a[srcIdx - 1]! << (8 - bitShift)) & 0xFF;
      }
    }
  }
  return toHex(result);
}
