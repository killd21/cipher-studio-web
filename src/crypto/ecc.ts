import { toBuf, toHex } from './hex-utils.ts';
import { p256, p384 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { ed448, x448 } from '@noble/curves/ed448.js';

type EdCurve = 'ed25519' | 'ed448';
type XCurve = 'x25519' | 'x448';

const BYTE_LEN = 32;
const n = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
const pMod = BigInt('0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff');
const aCurve = BigInt('0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc');
const Gx = BigInt('0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296');
const Gy = BigInt('0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5');

type Point = [bigint, bigint] | null;
const INFINITY: Point = null;
const G: Point = [Gx, Gy];

function hexToBig(hex: string): bigint {
  const h = hex.replace(/\s+/g, '');
  if (!h) throw new Error('Empty hex');
  return BigInt('0x' + h.toUpperCase());
}

function bigToHex(val: bigint, byteLen = BYTE_LEN): string {
  let h = val.toString(16).toUpperCase();
  if (h.length % 2 !== 0) h = '0' + h;
  return h.padStart(byteLen * 2, '0');
}

function modp(x: bigint): bigint { return ((x % pMod) + pMod) % pMod; }
function modn(x: bigint): bigint { return ((x % n) + n) % n; }

function modInv(a: bigint, m: bigint): bigint {
  let [old_r, r] = [((a % m) + m) % m, m];
  let [old_s, s] = [1n, 0n];
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s];
  }
  if (old_r !== 1n) throw new Error('Modular inverse does not exist');
  return ((old_s % m) + m) % m;
}

function pointAdd(P1: Point, P2: Point): Point {
  if (P1 === null) return P2;
  if (P2 === null) return P1;
  const [x1, y1] = P1;
  const [x2, y2] = P2;
  if (x1 === x2) {
    if (y1 !== y2) return INFINITY;
    return pointDouble(P1);
  }
  const lam = modp((y2 - y1) * modInv(x2 - x1, pMod));
  const x3 = modp(lam * lam - x1 - x2);
  const y3 = modp(lam * (x1 - x3) - y1);
  return [x3, y3];
}

function pointDouble(P: Point): Point {
  if (P === null) return null;
  const [x1, y1] = P;
  if (y1 === 0n) return INFINITY;
  const lam = modp((3n * x1 * x1 + aCurve) * modInv(2n * y1, pMod));
  const x3 = modp(lam * lam - 2n * x1);
  const y3 = modp(lam * (x1 - x3) - y1);
  return [x3, y3];
}

function scalarMul(k: bigint, P: Point): Point {
  let result: Point = INFINITY;
  let addend: Point = P;
  let scalar = ((k % n) + n) % n;
  while (scalar > 0n) {
    if (scalar & 1n) result = pointAdd(result, addend);
    addend = pointDouble(addend);
    scalar >>= 1n;
  }
  return result;
}

function parsePubKey(pubHex: string): [bigint, bigint] {
  const h = pubHex.replace(/\s+/g, '').toUpperCase();
  if (h.length !== 130 || h.slice(0, 2) !== '04')
    throw new Error('Public key must be uncompressed 04||X||Y (65 bytes hex)');
  return [hexToBig(h.slice(2, 66)), hexToBig(h.slice(66, 130))];
}

function concat(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrays) { out.set(a, off); off += a.length; }
  return out;
}

function getCurve(name?: string) {
  switch (name?.toLowerCase()) {
    case 'p-384':
    case 'p384':
      return { curve: p384, keyLen: 48 };
    case 'secp256k1':
      return { curve: secp256k1, keyLen: 32 };
    default:
      return { curve: p256, keyLen: 32 };
  }
}

// --- ECDH ---
export function ecdhComputeSecret(privateKeyHex: string, peerPublicKeyHex: string, curveName?: string): string {
  const { curve, keyLen } = getCurve(curveName);
  const shared = curve.getSharedSecret(toBuf(privateKeyHex), toBuf(peerPublicKeyHex));
  return toHex(shared.subarray(1, 1 + keyLen));
}

// --- ECDSA ---
function encodeEcdsaDer(r: bigint, s: bigint): Uint8Array {
  function encodeInt(val: bigint): Uint8Array {
    let h = bigToHex(val);
    if (parseInt(h.slice(0, 2), 16) & 0x80) h = '00' + h;
    const bytes = toBuf(h);
    const out = new Uint8Array(2 + bytes.length);
    out[0] = 0x02;
    out[1] = bytes.length;
    out.set(bytes, 2);
    return out;
  }
  const rBuf = encodeInt(r);
  const sBuf = encodeInt(s);
  const seq = new Uint8Array(2 + rBuf.length + sBuf.length);
  seq[0] = 0x30;
  seq[1] = rBuf.length + sBuf.length;
  seq.set(rBuf, 2);
  seq.set(sBuf, 2 + rBuf.length);
  return seq;
}

export function ecdsaSign(privateKeyHex: string, messageHex: string, curveName?: string): { r: string; s: string; der: string } {
  const { curve, keyLen } = getCurve(curveName);
  const msgHash = sha256(toBuf(messageHex));
  const sig = curve.sign(msgHash, toBuf(privateKeyHex));
  const rBytes = sig.subarray(0, keyLen);
  const sBytes = sig.subarray(keyLen, keyLen * 2);
  const r = BigInt('0x' + toHex(rBytes));
  const s = BigInt('0x' + toHex(sBytes));
  const der = encodeEcdsaDer(r, s);
  return { r: bigToHex(r, keyLen), s: bigToHex(s, keyLen), der: toHex(der) };
}

export function ecdsaVerify(publicKeyHex: string, messageHex: string, rHex: string, sHex: string, curveName?: string): boolean {
  const { curve } = getCurve(curveName);
  const msgHash = sha256(toBuf(messageHex));
  const sigBytes = concat(toBuf(rHex), toBuf(sHex));
  try {
    return curve.verify(sigBytes, msgHash, toBuf(publicKeyHex));
  } catch {
    return false;
  }
}

// --- EC-SDSA (ISO 14888-3) ---
function sha256Big(data: Uint8Array): bigint {
  const hash = sha256(data);
  return BigInt('0x' + toHex(hash));
}

export function ecSdsaSign(privateKeyHex: string, messageHex: string): { e: string; s: string } {
  const d = hexToBig(privateKeyHex);
  const msgBuf = toBuf(messageHex);

  let e: bigint, s: bigint, R: Point;
  do {
    const kBuf = new Uint8Array(BYTE_LEN);
    crypto.getRandomValues(kBuf);
    const k = BigInt('0x' + toHex(kBuf));
    if (k === 0n || k >= n) continue;

    R = scalarMul(k, G);
    if (R === null) continue;

    const rxBuf = toBuf(bigToHex(R[0]));
    e = modn(sha256Big(concat(rxBuf, msgBuf)));
    if (e === 0n) continue;

    s = modn(k + e * d);
  } while (s! === 0n);

  return { e: bigToHex(e!), s: bigToHex(s!) };
}

export function ecSdsaVerify(publicKeyHex: string, messageHex: string, eHex: string, sHex: string): boolean {
  const Q = parsePubKey(publicKeyHex);
  const e = hexToBig(eHex);
  const s = hexToBig(sHex);
  const msgBuf = toBuf(messageHex);

  if (e === 0n || e >= n) return false;
  if (s === 0n || s >= n) return false;

  const sG = scalarMul(s, G);
  const neQ = scalarMul(n - e, Q);
  const Rprime = pointAdd(sG, neQ);

  if (Rprime === null) return false;

  const rxBuf = toBuf(bigToHex(Rprime[0]));
  const ePrime = modn(sha256Big(concat(rxBuf, msgBuf)));

  return ePrime === e;
}

export function derivePublicKey(privateKeyHex: string, curveName?: string): string {
  const { curve } = getCurve(curveName);
  const pub = curve.getPublicKey(toBuf(privateKeyHex), false);
  return toHex(pub);
}

// --- EdDSA (Ed25519 / Ed448) ---
function getEd(curve: EdCurve = 'ed25519') {
  return curve === 'ed448' ? { lib: ed448, keyLen: 57 } : { lib: ed25519, keyLen: 32 };
}

export function eddsaKeygen(curve: EdCurve = 'ed25519'): { secretKey: string; publicKey: string } {
  const { lib, keyLen } = getEd(curve);
  const sk = new Uint8Array(keyLen);
  crypto.getRandomValues(sk);
  return { secretKey: toHex(sk), publicKey: toHex(lib.getPublicKey(sk)) };
}

export function eddsaSign(secretKeyHex: string, messageHex: string, curve: EdCurve = 'ed25519'): string {
  const { lib } = getEd(curve);
  return toHex(lib.sign(toBuf(messageHex), toBuf(secretKeyHex)));
}

export function eddsaVerify(publicKeyHex: string, messageHex: string, signatureHex: string, curve: EdCurve = 'ed25519'): boolean {
  const { lib } = getEd(curve);
  try {
    return lib.verify(toBuf(signatureHex), toBuf(messageHex), toBuf(publicKeyHex));
  } catch {
    return false;
  }
}

export function eddsaDerivePublicKey(secretKeyHex: string, curve: EdCurve = 'ed25519'): string {
  const { lib } = getEd(curve);
  return toHex(lib.getPublicKey(toBuf(secretKeyHex)));
}

// --- XDH (X25519 / X448) ---
function getX(curve: XCurve = 'x25519') {
  return curve === 'x448' ? { lib: x448, keyLen: 56 } : { lib: x25519, keyLen: 32 };
}

export function xdhKeygen(curve: XCurve = 'x25519'): { privateKey: string; publicKey: string } {
  const { lib, keyLen } = getX(curve);
  const priv = new Uint8Array(keyLen);
  crypto.getRandomValues(priv);
  return { privateKey: toHex(priv), publicKey: toHex(lib.getPublicKey(priv)) };
}

export function xdhComputeSecret(privateKeyHex: string, peerPublicKeyHex: string, curve: XCurve = 'x25519'): string {
  const { lib } = getX(curve);
  return toHex(lib.getSharedSecret(toBuf(privateKeyHex), toBuf(peerPublicKeyHex)));
}

export function xdhDerivePublicKey(privateKeyHex: string, curve: XCurve = 'x25519'): string {
  const { lib } = getX(curve);
  return toHex(lib.getPublicKey(toBuf(privateKeyHex)));
}
