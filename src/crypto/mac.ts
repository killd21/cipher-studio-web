import { toBuf, toHex } from './hex-utils.ts';
import * as des from './des.ts';
import * as padding from './padding.ts';
import { hmac as nobleHmac } from '@noble/hashes/hmac.js';
import { sha1 } from '@noble/hashes/legacy.js';
import { sha256, sha384, sha512 } from '@noble/hashes/sha2.js';
import { sha3_256, sha3_384, sha3_512 } from '@noble/hashes/sha3.js';
import * as aes from './aes.ts';

const hashFns: Record<string, (key: Uint8Array, msg: Uint8Array) => Uint8Array> = {
  'sha1':     (k, m) => nobleHmac(sha1, k, m),
  'sha-1':    (k, m) => nobleHmac(sha1, k, m),
  'sha256':   (k, m) => nobleHmac(sha256, k, m),
  'sha-256':  (k, m) => nobleHmac(sha256, k, m),
  'sha384':   (k, m) => nobleHmac(sha384, k, m),
  'sha-384':  (k, m) => nobleHmac(sha384, k, m),
  'sha512':   (k, m) => nobleHmac(sha512, k, m),
  'sha-512':  (k, m) => nobleHmac(sha512, k, m),
  'sha3-256': (k, m) => nobleHmac(sha3_256, k, m),
  'sha3-384': (k, m) => nobleHmac(sha3_384, k, m),
  'sha3-512': (k, m) => nobleHmac(sha3_512, k, m),
};

export function hmac(type: string, key: string, msg: string): string {
  const fn = hashFns[type.toLowerCase()];
  if (!fn) throw new Error(`Unsupported HMAC type: ${type}`);
  return toHex(fn(toBuf(key), toBuf(msg)));
}

function applyDesPad(msg: string, padMethod: string): string {
  if (padMethod === 'none') return msg;
  if (padMethod === 'iso9797m1') return padding.iso9797m1(msg, 8);
  if (padMethod === 'iso9797m3') return padding.iso9797m3(msg, 8);
  return padding.iso9797m2(msg, 8);
}

export function desMac(
  key: string, msg: string, iv = '0000000000000000', len = 8, padMethod = 'iso9797m2',
): string {
  const padded = applyDesPad(msg, padMethod);
  const result = des.cbcEncrypt(key, padded, iv);
  const lastBlock = result.substring(result.length - 16);
  return lastBlock.substring(0, len * 2);
}

export function retailMac(
  key: string, msg: string, iv = '0000000000000000', padMethod = 'iso9797m2',
): string {
  if (key.length !== 32) throw new Error('Retail MAC requires 16-byte (32 hex char) key.');
  const key1 = key.substring(0, 16);
  const key2 = key.substring(16, 32);
  const padded = applyDesPad(msg, padMethod);
  const encrypted = des.cbcEncrypt(key1, padded, iv);
  const hq = encrypted.substring(encrypted.length - 16);
  const tmp = des.ecbDecrypt(key2, hq);
  return des.ecbEncrypt(key1, tmp);
}

export function desTdesMac(
  key: string, msg: string, iv = '0000000000000000', padMethod = 'iso9797m2',
): string {
  if (key.length !== 32 && key.length !== 48) {
    throw new Error('DES/TDES MAC requires 16-byte (32 hex) or 24-byte (48 hex) key.');
  }
  const k1 = key.substring(0, 16);
  const k2 = key.substring(16, 32);
  const k3 = key.length === 48 ? key.substring(32, 48) : k1;
  const padded = applyDesPad(msg, padMethod);
  const cbcResult = des.cbcEncrypt(k1, padded, iv);
  const lastBlock = cbcResult.substring(cbcResult.length - 16);
  const tmp = des.ecbDecrypt(k2, lastBlock);
  return des.ecbEncrypt(k3, tmp);
}

export function desFullMac(key: string, msg: string, padMethod = 'iso9797m2'): string {
  if (key.length !== 32) throw new Error('desFullMac requires 16-byte (32 hex char) key.');
  const padded = applyDesPad(msg, padMethod);
  const encrypted = des.cbcEncrypt(key, padded, '0000000000000000');
  return encrypted.substring(encrypted.length - 16);
}

export function cmacAes(keyHex: string, msgHex: string): string {
  const blockSize = 16;

  function dbl(buf: Uint8Array): Uint8Array {
    const out = new Uint8Array(blockSize);
    let carry = 0;
    for (let i = blockSize - 1; i >= 0; i--) {
      const tmp = (buf[i]! << 1) | carry;
      out[i] = tmp & 0xff;
      carry = buf[i]! >>> 7;
    }
    if (buf[0]! & 0x80) out[blockSize - 1]! ^= 0x87;
    return out;
  }

  const zeroBlock = '00000000000000000000000000000000';
  const L = toBuf(aes.ecbEncrypt(keyHex, zeroBlock));
  const K1 = dbl(L);
  const K2 = dbl(K1);

  const M = toBuf(msgHex);
  const n = Math.ceil(M.length / blockSize) || 1;
  const isComplete = M.length > 0 && M.length % blockSize === 0;

  const lastBlock = new Uint8Array(blockSize);
  if (M.length > 0) {
    const start = (n - 1) * blockSize;
    lastBlock.set(M.subarray(start, Math.min(start + blockSize, M.length)));
  }

  if (isComplete) {
    for (let i = 0; i < blockSize; i++) lastBlock[i]! ^= K1[i]!;
  } else {
    const rem = M.length % blockSize;
    lastBlock[rem] = 0x80;
    for (let i = rem + 1; i < blockSize; i++) lastBlock[i] = 0x00;
    for (let i = 0; i < blockSize; i++) lastBlock[i]! ^= K2[i]!;
  }

  let X: Uint8Array = new Uint8Array(blockSize);
  const Y = new Uint8Array(blockSize);

  for (let i = 0; i < n - 1; i++) {
    for (let j = 0; j < blockSize; j++) Y[j] = X[j]! ^ M[i * blockSize + j]!;
    X = Uint8Array.from(toBuf(aes.ecbEncrypt(keyHex, toHex(Y))));
  }

  for (let j = 0; j < blockSize; j++) Y[j] = X[j]! ^ lastBlock[j]!;
  return aes.ecbEncrypt(keyHex, toHex(Y));
}
