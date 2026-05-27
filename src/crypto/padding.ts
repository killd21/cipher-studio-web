import { toBuf, toHex } from './hex-utils.ts';

function concat(a: Uint8Array, b: Uint8Array): Uint8Array {
  const c = new Uint8Array(a.length + b.length);
  c.set(a);
  c.set(b, a.length);
  return c;
}

export function iso9797m1(dataHex: string, blockSize = 8): string {
  const buf = toBuf(dataHex);
  const padLen = blockSize - (buf.length % blockSize);
  if (padLen === blockSize) return toHex(buf);
  return toHex(concat(buf, new Uint8Array(padLen)));
}

export function iso9797m2(dataHex: string, blockSize = 8): string {
  const buf = toBuf(dataHex);
  const padLen = blockSize - (buf.length % blockSize);
  const pad = new Uint8Array(padLen);
  pad[0] = 0x80;
  return toHex(concat(buf, pad));
}

export function iso9797m3(dataHex: string, blockSize = 8): string {
  const buf = toBuf(dataHex);
  const Ld = buf.length * 8;

  const rem = buf.length % blockSize;
  const zeroPad = rem === 0 ? 0 : blockSize - rem;
  const dPadded = concat(buf, new Uint8Array(zeroPad));

  const L = new Uint8Array(blockSize);
  let ld = Ld;
  for (let i = blockSize - 1; i >= 0; i--) {
    L[i] = ld & 0xff;
    ld >>>= 8;
  }

  return toHex(concat(L, dPadded));
}

export function pkcs7(dataHex: string, blockSize = 8): string {
  const buf = toBuf(dataHex);
  const padLen = blockSize - (buf.length % blockSize);
  const pad = new Uint8Array(padLen).fill(padLen);
  return toHex(concat(buf, pad));
}

export function pkcs5(dataHex: string): string {
  return pkcs7(dataHex, 8);
}

export function desPad(dataHex: string): string {
  return iso9797m2(dataHex, 8);
}

export function aesPad(dataHex: string): string {
  return iso9797m2(dataHex, 16);
}
