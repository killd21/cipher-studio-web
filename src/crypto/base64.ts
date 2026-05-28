import { toBuf, toHex } from './hex-utils.ts';

function bytesToBase64(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]!);
  return btoa(s);
}

function base64ToBytes(b64: string): Uint8Array {
  const s = atob(b64);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

export function hexToBase64(hex: string): string {
  return bytesToBase64(toBuf(hex));
}

export function base64ToHex(b64: string): string {
  const normalized = b64.replace(/\s+/g, '');
  return toHex(base64ToBytes(normalized));
}

export function hexToBase64Url(hex: string): string {
  return bytesToBase64(toBuf(hex))
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function base64UrlToHex(b64url: string): string {
  let s = b64url.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4 !== 0) s += '=';
  return toHex(base64ToBytes(s));
}
