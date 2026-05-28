import { toBuf, toHex } from './hex-utils.ts';
import { chacha20poly1305 } from '@noble/ciphers/chacha.js';

export function encrypt(keyHex: string, dataHex: string, nonceHex: string, aadHex?: string): string {
  const k = toBuf(keyHex);
  const d = toBuf(dataHex);
  const n = toBuf(nonceHex);
  if (k.length !== 32) throw new Error(`ChaCha20-Poly1305: key must be 32 bytes, got ${k.length}`);
  if (n.length !== 12) throw new Error(`ChaCha20-Poly1305: nonce must be 12 bytes, got ${n.length}`);
  const aad = aadHex ? toBuf(aadHex) : undefined;
  const cipher = chacha20poly1305(k, n, aad);
  return toHex(cipher.encrypt(d));
}

export function decrypt(keyHex: string, dataHex: string, nonceHex: string, aadHex?: string): string {
  const k = toBuf(keyHex);
  const d = toBuf(dataHex);
  const n = toBuf(nonceHex);
  if (k.length !== 32) throw new Error(`ChaCha20-Poly1305: key must be 32 bytes, got ${k.length}`);
  if (n.length !== 12) throw new Error(`ChaCha20-Poly1305: nonce must be 12 bytes, got ${n.length}`);
  const aad = aadHex ? toBuf(aadHex) : undefined;
  const cipher = chacha20poly1305(k, n, aad);
  return toHex(cipher.decrypt(d));
}
