import { toBuf, toHex } from './hex-utils.ts';
import { ml_kem512, ml_kem768, ml_kem1024 } from '@noble/post-quantum/ml-kem.js';
import { ml_dsa44, ml_dsa65, ml_dsa87 } from '@noble/post-quantum/ml-dsa.js';
import {
  slh_dsa_shake_128f, slh_dsa_shake_192f, slh_dsa_shake_256f,
  slh_dsa_sha2_128f, slh_dsa_sha2_192f, slh_dsa_sha2_256f,
} from '@noble/post-quantum/slh-dsa.js';
import {
  aimer128f, aimer128s,
  aimer192f, aimer192s,
  aimer256f, aimer256s,
} from '@killd21/kpqc/aimer';
import {
  haetae2, haetae3, haetae5,
} from '@killd21/kpqc/haetae';
import {
  ntruplus768, ntruplus864, ntruplus1152,
} from '@killd21/kpqc/ntruplus';
import {
  smaugt128, smaugt192, smaugt256, timer as smaugtTimer,
} from '@killd21/kpqc/smaugt';

function getKem(variant: number | string) {
  if (variant === 512 || variant === '512') return ml_kem512;
  if (variant === 768 || variant === '768') return ml_kem768;
  if (variant === 1024 || variant === '1024') return ml_kem1024;
  throw new Error(`ML-KEM variant must be 512, 768, or 1024, got: ${variant}`);
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

// --- SLH-DSA (FIPS 205, SPHINCS+) ---
function getSlhDsa(variant: string) {
  switch (variant) {
    case 'shake-128f': return slh_dsa_shake_128f;
    case 'shake-192f': return slh_dsa_shake_192f;
    case 'shake-256f': return slh_dsa_shake_256f;
    case 'sha2-128f':  return slh_dsa_sha2_128f;
    case 'sha2-192f':  return slh_dsa_sha2_192f;
    case 'sha2-256f':  return slh_dsa_sha2_256f;
    default: throw new Error(`Unknown SLH-DSA variant: ${variant}`);
  }
}

export function slhKeygen(variant: string): { publicKey: string; secretKey: string } {
  const { publicKey, secretKey } = getSlhDsa(variant).keygen();
  return { publicKey: toHex(publicKey), secretKey: toHex(secretKey) };
}

export function slhSign(variant: string, secretKeyHex: string, messageHex: string): string {
  return toHex(getSlhDsa(variant).sign(toBuf(messageHex), toBuf(secretKeyHex)));
}

export function slhVerify(
  variant: string, publicKeyHex: string, messageHex: string, signatureHex: string,
): boolean {
  return getSlhDsa(variant).verify(toBuf(signatureHex), toBuf(messageHex), toBuf(publicKeyHex));
}

// --- AIMer (KpqC, MPCitH-based signature) ---
export type AimerVariant = '128f' | '128s' | '192f' | '192s' | '256f' | '256s';

function getAimer(variant: AimerVariant) {
  switch (variant) {
    case '128f': return aimer128f;
    case '128s': return aimer128s;
    case '192f': return aimer192f;
    case '192s': return aimer192s;
    case '256f': return aimer256f;
    case '256s': return aimer256s;
    default: throw new Error(`Unknown AIMer variant: ${variant}`);
  }
}

export async function aimerKeygen(variant: AimerVariant): Promise<{ publicKey: string; secretKey: string }> {
  const { publicKey, secretKey } = await getAimer(variant).keygen();
  return { publicKey: toHex(publicKey), secretKey: toHex(secretKey) };
}

export async function aimerSign(
  variant: AimerVariant, secretKeyHex: string, messageHex: string, contextHex?: string,
): Promise<string> {
  const opts = contextHex ? { context: toBuf(contextHex) } : undefined;
  const sig = await getAimer(variant).sign(toBuf(messageHex), toBuf(secretKeyHex), opts);
  return toHex(sig);
}

export async function aimerVerify(
  variant: AimerVariant, publicKeyHex: string, messageHex: string, signatureHex: string, contextHex?: string,
): Promise<boolean> {
  const opts = contextHex ? { context: toBuf(contextHex) } : undefined;
  try {
    return await getAimer(variant).verify(toBuf(messageHex), toBuf(signatureHex), toBuf(publicKeyHex), opts);
  } catch {
    return false;
  }
}

// --- HAETAE (KpqC, lattice-based signature) ---
export type HaetaeVariant = '2' | '3' | '5';

function getHaetae(variant: HaetaeVariant) {
  switch (variant) {
    case '2': return haetae2;
    case '3': return haetae3;
    case '5': return haetae5;
    default: throw new Error(`Unknown HAETAE variant: ${variant}`);
  }
}

export async function haetaeKeygen(variant: HaetaeVariant): Promise<{ publicKey: string; secretKey: string }> {
  const { publicKey, secretKey } = await getHaetae(variant).keygen();
  return { publicKey: toHex(publicKey), secretKey: toHex(secretKey) };
}

export async function haetaeSign(
  variant: HaetaeVariant, secretKeyHex: string, messageHex: string, contextHex?: string,
): Promise<string> {
  const opts = contextHex ? { context: toBuf(contextHex) } : undefined;
  const sig = await getHaetae(variant).sign(toBuf(messageHex), toBuf(secretKeyHex), opts);
  return toHex(sig);
}

export async function haetaeVerify(
  variant: HaetaeVariant, publicKeyHex: string, messageHex: string, signatureHex: string, contextHex?: string,
): Promise<boolean> {
  const opts = contextHex ? { context: toBuf(contextHex) } : undefined;
  try {
    return await getHaetae(variant).verify(toBuf(messageHex), toBuf(signatureHex), toBuf(publicKeyHex), opts);
  } catch {
    return false;
  }
}

// --- NTRU+ (KpqC, lattice-based KEM) ---
export type NtruPlusVariant = '768' | '864' | '1152';

function getNtruPlus(variant: NtruPlusVariant) {
  switch (variant) {
    case '768': return ntruplus768;
    case '864': return ntruplus864;
    case '1152': return ntruplus1152;
    default: throw new Error(`Unknown NTRU+ variant: ${variant}`);
  }
}

export async function ntruplusKeygen(variant: NtruPlusVariant): Promise<{ publicKey: string; secretKey: string }> {
  const { publicKey, secretKey } = await getNtruPlus(variant).keygen();
  return { publicKey: toHex(publicKey), secretKey: toHex(secretKey) };
}

export async function ntruplusEncapsulate(
  variant: NtruPlusVariant, publicKeyHex: string,
): Promise<{ ciphertext: string; sharedSecret: string }> {
  const { ciphertext, sharedSecret } = await getNtruPlus(variant).encapsulate(toBuf(publicKeyHex));
  return { ciphertext: toHex(ciphertext), sharedSecret: toHex(sharedSecret) };
}

export async function ntruplusDecapsulate(
  variant: NtruPlusVariant, secretKeyHex: string, ciphertextHex: string,
): Promise<string> {
  const ss = await getNtruPlus(variant).decapsulate(toBuf(ciphertextHex), toBuf(secretKeyHex));
  return toHex(ss);
}

// --- SMAUG-T / TiMER (KpqC, lattice-based KEM) ---
export type SmaugtVariant = '128' | '192' | '256' | 'timer';

function getSmaugt(variant: SmaugtVariant) {
  switch (variant) {
    case '128': return smaugt128;
    case '192': return smaugt192;
    case '256': return smaugt256;
    case 'timer': return smaugtTimer;
    default: throw new Error(`Unknown SMAUG-T variant: ${variant}`);
  }
}

export async function smaugtKeygen(variant: SmaugtVariant): Promise<{ publicKey: string; secretKey: string }> {
  const { publicKey, secretKey } = await getSmaugt(variant).keygen();
  return { publicKey: toHex(publicKey), secretKey: toHex(secretKey) };
}

export async function smaugtEncapsulate(
  variant: SmaugtVariant, publicKeyHex: string,
): Promise<{ ciphertext: string; sharedSecret: string }> {
  const { ciphertext, sharedSecret } = await getSmaugt(variant).encapsulate(toBuf(publicKeyHex));
  return { ciphertext: toHex(ciphertext), sharedSecret: toHex(sharedSecret) };
}

export async function smaugtDecapsulate(
  variant: SmaugtVariant, secretKeyHex: string, ciphertextHex: string,
): Promise<string> {
  const ss = await getSmaugt(variant).decapsulate(toBuf(ciphertextHex), toBuf(secretKeyHex));
  return toHex(ss);
}
