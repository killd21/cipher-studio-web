function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
  if (mod === 1n) return 0n;
  let result = 1n;
  base = base % mod;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % mod;
    exp >>= 1n;
    base = (base * base) % mod;
  }
  return result;
}

function hexToBig(hex: string): bigint {
  const h = hex.replace(/\s+/g, '');
  if (!h) throw new Error('Empty hex value');
  return BigInt('0x' + h.toUpperCase());
}

function bigToHex(n: bigint, byteLen: number): string {
  let h = n.toString(16).toUpperCase();
  if (h.length % 2 !== 0) h = '0' + h;
  return h.padStart(byteLen * 2, '0');
}

function nBytes(N: bigint): number {
  return Math.ceil(N.toString(16).length / 2);
}

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

export function encrypt(n: string, e: string, data: string): string {
  const N = hexToBig(n);
  const E = hexToBig(e);
  const M = hexToBig(data);
  if (M >= N) throw new Error('RSA: plaintext must be smaller than modulus N');
  return bigToHex(modPow(M, E, N), nBytes(N));
}

export function decrypt(n: string, d: string, data: string): string {
  const N = hexToBig(n);
  const D = hexToBig(d);
  const C = hexToBig(data);
  if (C >= N) throw new Error('RSA: ciphertext must be smaller than modulus N');
  return bigToHex(modPow(C, D, N), nBytes(N));
}

export function crtDecrypt(
  p: string, q: string, dP: string, dQ: string, qInv: string, data: string,
): string {
  const P  = hexToBig(p);
  const Q  = hexToBig(q);
  const DP = hexToBig(dP);
  const DQ = hexToBig(dQ);
  const QI = hexToBig(qInv);
  const C  = hexToBig(data);
  const N  = P * Q;

  const m1 = modPow(C % P, DP, P);
  const m2 = modPow(C % Q, DQ, Q);
  const h  = (QI * ((m1 - m2 + P) % P)) % P;
  const M  = m2 + h * Q;

  return bigToHex(M, nBytes(N));
}

export function crtToStandard(
  p: string, q: string, e: string,
): { n: string; d: string } {
  const P   = hexToBig(p);
  const Q   = hexToBig(q);
  const E   = hexToBig(e);
  const N   = P * Q;
  const phi = (P - 1n) * (Q - 1n);
  const d   = modInv(E, phi);
  const nb  = nBytes(N);
  return { n: bigToHex(N, nb), d: bigToHex(d, nb) };
}
