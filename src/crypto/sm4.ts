import { sm4 as sm4Lib } from 'sm-crypto';
import { toBuf, toHex } from './hex-utils.ts';

// SM4 — GM/T 0002 · ISO/IEC 18033-3:2010. 128-bit block, 128-bit key.
// Modes: ECB, CBC. Padding: 'pkcs#7' or 'none'.
// Pass byte arrays to sm-crypto to keep raw bytes (avoid UTF-8 interpretation).

type Padding = 'none' | 'pkcs#7';

function bytes(hex: string): number[] {
  return Array.from(toBuf(hex));
}

function asHex(out: string | number[]): string {
  return Array.isArray(out) ? toHex(Uint8Array.from(out)) : out.toUpperCase();
}

export function ecbEncrypt(keyHex: string, dataHex: string, padding: Padding = 'none'): string {
  const out = sm4Lib.encrypt(bytes(dataHex), bytes(keyHex), { mode: 'ecb', padding });
  return asHex(out);
}

export function ecbDecrypt(keyHex: string, dataHex: string, padding: Padding = 'none'): string {
  const out = sm4Lib.decrypt(bytes(dataHex), bytes(keyHex), { mode: 'ecb', padding, output: 'array' });
  return asHex(out);
}

export function cbcEncrypt(keyHex: string, dataHex: string, ivHex: string, padding: Padding = 'none'): string {
  const out = sm4Lib.encrypt(bytes(dataHex), bytes(keyHex), { mode: 'cbc', iv: bytes(ivHex), padding });
  return asHex(out);
}

export function cbcDecrypt(keyHex: string, dataHex: string, ivHex: string, padding: Padding = 'none'): string {
  const out = sm4Lib.decrypt(bytes(dataHex), bytes(keyHex), { mode: 'cbc', iv: bytes(ivHex), padding, output: 'array' });
  return asHex(out);
}
