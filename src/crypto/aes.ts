import { toBuf, toHex } from './hex-utils.ts';
import { ecb, cbc, ctr, gcm, cfb } from '@noble/ciphers/aes.js';

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

// AES-GCM (AEAD)
export function gcmEncrypt(key: string, data: string, nonce: string, aad?: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  const n = toBuf(nonce);
  const a = aad ? toBuf(aad) : undefined;
  const cipher = gcm(k, n, a);
  return toHex(cipher.encrypt(d)); // Returns ciphertext + 16-byte tag
}

export function gcmDecrypt(key: string, data: string, nonce: string, aad?: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  const n = toBuf(nonce);
  const a = aad ? toBuf(aad) : undefined;
  const cipher = gcm(k, n, a);
  return toHex(cipher.decrypt(d));
}

export function cfbEncrypt(key: string, data: string, iv?: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  const ivBuf = iv ? toBuf(iv) : new Uint8Array(16);
  if (ivBuf.length !== 16) throw new Error(`AES CFB: IV must be 16 bytes, got ${ivBuf.length}`);
  const cipher = cfb(k, ivBuf);
  return toHex(cipher.encrypt(d));
}

export function cfbDecrypt(key: string, data: string, iv?: string): string {
  const k = toBuf(key);
  const d = toBuf(data);
  const ivBuf = iv ? toBuf(iv) : new Uint8Array(16);
  if (ivBuf.length !== 16) throw new Error(`AES CFB: IV must be 16 bytes, got ${ivBuf.length}`);
  const cipher = cfb(k, ivBuf);
  return toHex(cipher.decrypt(d));
}

// ═══════════════════════════════════════════════════════════
// AES-CCM (NIST SP 800-38C / RFC 3610)
// ═══════════════════════════════════════════════════════════
const VALID_TAG_LENS = [4, 6, 8, 10, 12, 14, 16];

function validateCcmParams(k: Uint8Array, nonce: Uint8Array, tagLen: number): number {
  if (k.length !== 16 && k.length !== 24 && k.length !== 32) {
    throw new Error(`AES CCM: key must be 16/24/32 bytes, got ${k.length}`);
  }
  if (nonce.length < 7 || nonce.length > 13) {
    throw new Error(`AES CCM: nonce must be 7-13 bytes, got ${nonce.length}`);
  }
  if (!VALID_TAG_LENS.includes(tagLen)) {
    throw new Error(`AES CCM: tag length must be one of 4,6,8,10,12,14,16, got ${tagLen}`);
  }
  return 15 - nonce.length; // L
}

function formatB0(nonce: Uint8Array, aadLen: number, plainLen: number, tagLen: number, L: number): Uint8Array {
  // Validate plaintext length fits in L bytes
  if (L < 8) {
    const maxLen = Math.pow(2, 8 * L);
    if (plainLen >= maxLen) {
      throw new Error(`AES CCM: plaintext too long for nonce length (max ${maxLen}, got ${plainLen})`);
    }
  }
  const b0 = new Uint8Array(16);
  const flags = (aadLen > 0 ? 0x40 : 0) | (((tagLen - 2) / 2) << 3) | (L - 1);
  b0[0] = flags;
  b0.set(nonce, 1);
  // Encode plainLen as big-endian in last L bytes
  let len = plainLen;
  for (let i = 15; i >= 16 - L; i--) {
    b0[i] = len & 0xff;
    len = Math.floor(len / 256);
  }
  return b0;
}

function formatAadBlocks(aad: Uint8Array): Uint8Array {
  if (aad.length === 0) return new Uint8Array(0);
  let prefix: Uint8Array;
  const a = aad.length;
  if (a < 0xff00) {
    prefix = new Uint8Array(2);
    prefix[0] = (a >>> 8) & 0xff;
    prefix[1] = a & 0xff;
  } else if (a < 0x100000000) {
    prefix = new Uint8Array(6);
    prefix[0] = 0xff; prefix[1] = 0xfe;
    prefix[2] = (a >>> 24) & 0xff;
    prefix[3] = (a >>> 16) & 0xff;
    prefix[4] = (a >>> 8) & 0xff;
    prefix[5] = a & 0xff;
  } else {
    throw new Error('AES CCM: AAD too long');
  }
  const total = prefix.length + aad.length;
  const padded = Math.ceil(total / 16) * 16;
  const out = new Uint8Array(padded);
  out.set(prefix, 0);
  out.set(aad, prefix.length);
  return out;
}

function formatA0(nonce: Uint8Array, L: number): Uint8Array {
  const a0 = new Uint8Array(16);
  a0[0] = L - 1; // Flags: only L-1 in bits 2-0
  a0.set(nonce, 1);
  // Last L bytes (counter) stay zero
  return a0;
}

function cbcMacOver(keyHex: string, blocks: Uint8Array): Uint8Array {
  const x = new Uint8Array(16);
  const xored = new Uint8Array(16);
  for (let i = 0; i < blocks.length; i += 16) {
    for (let j = 0; j < 16; j++) xored[j] = x[j]! ^ blocks[i + j]!;
    const enc = toBuf(ecbEncrypt(keyHex, toHex(xored)));
    x.set(enc);
  }
  return x;
}

function ctEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

function zeroPadToBlock(data: Uint8Array): Uint8Array {
  if (data.length === 0) return new Uint8Array(0);
  const padded = Math.ceil(data.length / 16) * 16;
  const out = new Uint8Array(padded);
  out.set(data, 0);
  return out;
}

export function ccmEncrypt(
  keyHex: string, dataHex: string, nonceHex: string,
  aadHex?: string, tagLen: number = 16,
): string {
  const k = toBuf(keyHex);
  const p = toBuf(dataHex);
  const n = toBuf(nonceHex);
  const a = aadHex ? toBuf(aadHex) : new Uint8Array(0);
  const L = validateCcmParams(k, n, tagLen);

  // Step 1-3: format MAC input
  const b0 = formatB0(n, a.length, p.length, tagLen, L);
  const aadBlocks = formatAadBlocks(a);
  const pBlocks = zeroPadToBlock(p);
  const macInput = new Uint8Array(b0.length + aadBlocks.length + pBlocks.length);
  macInput.set(b0, 0);
  macInput.set(aadBlocks, b0.length);
  macInput.set(pBlocks, b0.length + aadBlocks.length);

  // Step 4: CBC-MAC → T
  const fullTag = cbcMacOver(keyHex, macInput);
  const T = fullTag.subarray(0, tagLen);

  // Step 5-7: CTR encryption + tag wrapping
  const a0 = formatA0(n, L);
  const stream = ctr(k, a0);
  const ctrInput = new Uint8Array(16 + p.length);
  ctrInput.set(p, 16); // zeros for S0, then plaintext
  const ctrOut = stream.encrypt(ctrInput);
  const S0 = ctrOut.subarray(0, 16);
  const C = ctrOut.subarray(16);

  const U = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) U[i] = T[i]! ^ S0[i]!;

  const out = new Uint8Array(C.length + tagLen);
  out.set(C, 0);
  out.set(U, C.length);
  return toHex(out);
}

export function ccmDecrypt(
  keyHex: string, dataHex: string, nonceHex: string,
  aadHex?: string, tagLen: number = 16,
): string {
  const k = toBuf(keyHex);
  const input = toBuf(dataHex);
  const n = toBuf(nonceHex);
  const a = aadHex ? toBuf(aadHex) : new Uint8Array(0);
  const L = validateCcmParams(k, n, tagLen);

  if (input.length < tagLen) {
    throw new Error(`AES CCM: input shorter than tag length (got ${input.length}, need >= ${tagLen})`);
  }
  const C = input.subarray(0, input.length - tagLen);
  const U = input.subarray(input.length - tagLen);

  // CTR decrypt
  const a0 = formatA0(n, L);
  const stream = ctr(k, a0);
  const ctrInput = new Uint8Array(16 + C.length);
  ctrInput.set(C, 16);
  const ctrOut = stream.encrypt(ctrInput);
  const S0 = ctrOut.subarray(0, 16);
  const P = ctrOut.subarray(16);

  // Recompute T'
  const Tprime = new Uint8Array(tagLen);
  for (let i = 0; i < tagLen; i++) Tprime[i] = U[i]! ^ S0[i]!;

  // Recompute MAC
  const b0 = formatB0(n, a.length, P.length, tagLen, L);
  const aadBlocks = formatAadBlocks(a);
  const pBlocks = zeroPadToBlock(P);
  const macInput = new Uint8Array(b0.length + aadBlocks.length + pBlocks.length);
  macInput.set(b0, 0);
  macInput.set(aadBlocks, b0.length);
  macInput.set(pBlocks, b0.length + aadBlocks.length);
  const expectedTag = cbcMacOver(keyHex, macInput).subarray(0, tagLen);

  if (!ctEq(Tprime, expectedTag)) {
    throw new Error('AES CCM: authentication failed');
  }
  return toHex(P);
}
