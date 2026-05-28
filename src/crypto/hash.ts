import { toBuf, toHex } from './hex-utils.ts';
import { md5 as md5Hash } from 'js-md5';
import { sha3_256, sha3_384, sha3_512, shake128, shake256 } from '@noble/hashes/sha3.js';

export async function digest(algorithm: string, dataHex: string, outputLen?: number): Promise<string> {
  const alg = algorithm.toLowerCase();
  const buf = toBuf(dataHex);

  if (alg === 'md5') {
    const hash = md5Hash.arrayBuffer(buf);
    return toHex(new Uint8Array(hash));
  }

  const sha3Map: Record<string, (data: Uint8Array) => Uint8Array> = {
    'sha3-256': (d) => sha3_256(d),
    'sha3-384': (d) => sha3_384(d),
    'sha3-512': (d) => sha3_512(d),
  };

  if (sha3Map[alg]) {
    return toHex(sha3Map[alg](buf));
  }

  if (alg === 'shake128') {
    const len = outputLen ?? 32;
    return toHex(shake128(buf, { dkLen: len }));
  }
  if (alg === 'shake256') {
    const len = outputLen ?? 64;
    return toHex(shake256(buf, { dkLen: len }));
  }

  const webCryptoAlg: Record<string, string> = {
    sha1: 'SHA-1',
    'sha-1': 'SHA-1',
    sha256: 'SHA-256',
    'sha-256': 'SHA-256',
    sha384: 'SHA-384',
    'sha-384': 'SHA-384',
    sha512: 'SHA-512',
    'sha-512': 'SHA-512',
  };

  const name = webCryptoAlg[alg];
  if (!name) throw new Error(`Unsupported hash algorithm: ${algorithm}`);

  const result = await crypto.subtle.digest(name, buf.buffer as ArrayBuffer);
  return toHex(new Uint8Array(result));
}

export async function sha1(dataHex: string): Promise<string> {
  return digest('sha1', dataHex);
}

export async function sha256(dataHex: string): Promise<string> {
  return digest('sha256', dataHex);
}

export async function md5(dataHex: string): Promise<string> {
  return digest('md5', dataHex);
}
