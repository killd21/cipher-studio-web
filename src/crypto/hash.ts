import { toBuf, toHex } from './hex-utils.ts';
import { md5 as md5Hash } from 'js-md5';

export async function digest(algorithm: string, dataHex: string): Promise<string> {
  const alg = algorithm.toLowerCase();

  if (alg === 'md5') {
    const hash = md5Hash.arrayBuffer(toBuf(dataHex));
    return toHex(new Uint8Array(hash));
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

  const buf = toBuf(dataHex);
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
