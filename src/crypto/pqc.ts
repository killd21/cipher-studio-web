import { toBuf, toHex } from './hex-utils.ts';
import { ml_kem512, ml_kem768 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';

function getKem(variant: number | string) {
  if (variant === 512 || variant === '512') return ml_kem512;
  if (variant === 768 || variant === '768') return ml_kem768;
  throw new Error(`ML-KEM variant must be 512 or 768, got: ${variant}`);
}

function getDsa(variant: number | string) {
  if (variant === 44 || variant === '44') return ml_dsa44;
  if (variant === 65 || variant === '65') return ml_dsa65;
  if (variant === 87 || variant === '87') return ml_dsa87;
  throw new Error(`ML-DSA variant must be 44, 65, or 87, got: ${variant}`);
}

export function kemKeygen(variant: number | string): { ek: string; dk: string } {
  const { publicKey, secretKey } = getKem(variant).keygen();
  return { ek: toHex(publicKey), dk: toHex(secretKey) };
}

export function kemEncapsulate(
  variant: number | string, ekHex: string, mHex?: string,
): { ciphertext: string; sharedSecret: string } {
  const m = mHex ? toBuf(mHex) : undefined;
  const { cipherText, sharedSecret } = getKem(variant).encapsulate(toBuf(ekHex), m);
  return { ciphertext: toHex(cipherText), sharedSecret: toHex(sharedSecret) };
}

export function kemDecapsulate(variant: number | string, dkHex: string, ciphertextHex: string): string {
  return toHex(getKem(variant).decapsulate(toBuf(ciphertextHex), toBuf(dkHex)));
}

export function dsaKeygen(variant: number | string): { publicKey: string; secretKey: string } {
  const { publicKey, secretKey } = getDsa(variant).keygen();
  return { publicKey: toHex(publicKey), secretKey: toHex(secretKey) };
}

export function dsaSign(variant: number | string, secretKeyHex: string, messageHex: string): string {
  return toHex(getDsa(variant).sign(toBuf(messageHex), toBuf(secretKeyHex)));
}

export function dsaVerify(
  variant: number | string, publicKeyHex: string, messageHex: string, signatureHex: string,
): boolean {
  return getDsa(variant).verify(toBuf(signatureHex), toBuf(messageHex), toBuf(publicKeyHex));
}
