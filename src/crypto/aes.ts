import { toBuf, toHex } from './hex-utils.ts';
import { ecb, cbc, ctr } from '@noble/ciphers/aes.js';

export function ecbEncrypt(key: string, data: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  if (d.length % 16 !== 0) throw new Error(`AES ECB: data length must be multiple of 16 bytes, got ${d.length}`);
  const cipher = ecb(k, { disablePadding: true });
  return toHex(cipher.encrypt(d));
}

export function ecbDecrypt(key: string, data: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  if (d.length % 16 !== 0) throw new Error(`AES ECB: data length must be multiple of 16 bytes, got ${d.length}`);
  const cipher = ecb(k, { disablePadding: true });
  return toHex(cipher.decrypt(d));
}

export function cbcEncrypt(key: string, data: string, iv?: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  const ivBuf = iv ? toBuf(iv) : new Uint8Array(16);
  if (d.length % 16 !== 0) throw new Error(`AES CBC: data length must be multiple of 16 bytes, got ${d.length}`);
  if (ivBuf.length !== 16) throw new Error(`AES CBC: IV must be 16 bytes, got ${ivBuf.length}`);
  const cipher = cbc(k, ivBuf, { disablePadding: true });
  return toHex(cipher.encrypt(d));
}

export function cbcDecrypt(key: string, data: string, iv?: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  const ivBuf = iv ? toBuf(iv) : new Uint8Array(16);
  if (d.length % 16 !== 0) throw new Error(`AES CBC: data length must be multiple of 16 bytes, got ${d.length}`);
  if (ivBuf.length !== 16) throw new Error(`AES CBC: IV must be 16 bytes, got ${ivBuf.length}`);
  const cipher = cbc(k, ivBuf, { disablePadding: true });
  return toHex(cipher.decrypt(d));
}

export function ctrEncrypt(key: string, data: string, nonce?: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  const nonceBuf = nonce ? toBuf(nonce) : new Uint8Array(16);
  if (nonceBuf.length !== 16) throw new Error(`AES CTR: nonce must be 16 bytes, got ${nonceBuf.length}`);
  const cipher = ctr(k, nonceBuf);
  return toHex(cipher.encrypt(d));
}

export function ctrDecrypt(key: string, data: string, nonce?: string): string {
  return ctrEncrypt(key, data, nonce);
}
