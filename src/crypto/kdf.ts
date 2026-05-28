import { toBuf, toHex } from './hex-utils.ts';
import { hkdf, extract, expand } from '@noble/hashes/hkdf.js';
import { pbkdf2Async } from '@noble/hashes/pbkdf2.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_384, sha3_512 } from '@noble/hashes/sha3.js';

function getHash(alg: string) {
  switch (alg.toLowerCase()) {
    case 'sha1':
    case 'sha-1':    return sha1;
    case 'sha256':
    case 'sha-256':  return sha256;
    case 'sha384':
    case 'sha-384':  return sha384;
    case 'sha512':
    case 'sha-512':  return sha512;
    case 'sha3-256': return sha3_256;
    case 'sha3-384': return sha3_384;
    case 'sha3-512': return sha3_512;
    default: throw new Error(`Unsupported hash: ${alg}`);
  }
}

export function hkdfDerive(
  hashAlg: string, ikmHex: string, saltHex: string, infoHex: string, length: number,
): string {
  const hash = getHash(hashAlg);
  const ikm = toBuf(ikmHex);
  const salt = saltHex ? toBuf(saltHex) : new Uint8Array(0);
  const info = infoHex ? toBuf(infoHex) : new Uint8Array(0);
  return toHex(hkdf(hash, ikm, salt, info, length));
}

export function hkdfExtract(hashAlg: string, ikmHex: string, saltHex: string): string {
  const hash = getHash(hashAlg);
  const ikm = toBuf(ikmHex);
  const salt = saltHex ? toBuf(saltHex) : new Uint8Array(0);
  return toHex(extract(hash, ikm, salt));
}

export function hkdfExpand(hashAlg: string, prkHex: string, infoHex: string, length: number): string {
  const hash = getHash(hashAlg);
  const prk = toBuf(prkHex);
  const info = infoHex ? toBuf(infoHex) : new Uint8Array(0);
  return toHex(expand(hash, prk, info, length));
}

export async function pbkdf2Derive(
  hashAlg: string, passwordHex: string, saltHex: string, iterations: number, dkLen: number,
): Promise<string> {
  const hash = getHash(hashAlg);
  const password = toBuf(passwordHex);
  const salt = saltHex ? toBuf(saltHex) : new Uint8Array(0);
  const result = await pbkdf2Async(hash, password, salt, { c: iterations, dkLen });
  return toHex(result);
}
