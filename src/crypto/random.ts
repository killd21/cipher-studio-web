import { toHex } from './hex-utils.ts';

export function bytes(length: number): string {
  const buf = new Uint8Array(length);
  crypto.getRandomValues(buf);
  return toHex(buf);
}
