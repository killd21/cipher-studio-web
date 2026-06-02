import { sm2 as sm2Lib } from 'sm-crypto';
import { toBuf, toHex } from './hex-utils.ts';

// SM2 — GM/T 0003 · ISO/IEC 14888-3 (signature) · ISO/IEC 18033-5 (encryption).
// Public-key cryptography on sm2p256v1 curve.
// Operations: Keygen, Sign/Verify (with default userId 1234567812345678), Encrypt/Decrypt.

export type CipherMode = 0 | 1; // 0 = C1C2C3 (legacy), 1 = C1C3C2 (current, GM/T 0009)

export function keygen(): { publicKey: string; privateKey: string } {
  const kp = sm2Lib.generateKeyPairHex();
  return { publicKey: kp.publicKey.toUpperCase(), privateKey: kp.privateKey.toUpperCase() };
}

export function derivePublicKey(privateKeyHex: string): string {
  return sm2Lib.getPublicKeyFromPrivateKey(privateKeyHex).toUpperCase();
}

// Sign: input is hex message. hash:true → SM3 is applied internally (with ZA per GM/T 0003.2).
export function sign(privateKeyHex: string, messageHex: string, userId?: string): string {
  const msgBytes = Array.from(toBuf(messageHex));
  const opts: { hash: boolean; userId?: string } = { hash: true };
  if (userId !== undefined && userId !== '') opts.userId = userId;
  return sm2Lib.doSignature(msgBytes, privateKeyHex, opts).toUpperCase();
}

export function verify(publicKeyHex: string, messageHex: string, signatureHex: string, userId?: string): boolean {
  const msgBytes = Array.from(toBuf(messageHex));
  const opts: { hash: boolean; userId?: string } = { hash: true };
  if (userId !== undefined && userId !== '') opts.userId = userId;
  try {
    return sm2Lib.doVerifySignature(msgBytes, signatureHex, publicKeyHex, opts);
  } catch {
    return false;
  }
}

// Encrypt: returns concatenated C1||C3||C2 (or C1||C2||C3) as hex.
export function encrypt(publicKeyHex: string, dataHex: string, cipherMode: CipherMode = 1): string {
  const msgBytes = Array.from(toBuf(dataHex));
  return sm2Lib.doEncrypt(msgBytes, publicKeyHex, cipherMode).toUpperCase();
}

export function decrypt(privateKeyHex: string, cipherHex: string, cipherMode: CipherMode = 1): string {
  // Pass output:'array' so we get raw bytes rather than UTF-8 decoded string
  const out = sm2Lib.doDecrypt(cipherHex, privateKeyHex, cipherMode, { output: 'array' });
  return Array.isArray(out) ? toHex(Uint8Array.from(out)) : out;
}
