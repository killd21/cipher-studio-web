// ============================================================================
// electronAPI adapter — browser shim for the Cipher Studio HTML.
//
// The original cipher-studio.html was written for an Electron renderer and
// calls window.electronAPI.* directly. This module replicates that surface in
// the browser by routing each call to a local implementation. During Phase 0
// every method throws "not-implemented"; subsequent phases wire real modules
// in one by one.
// ============================================================================

export type Hex = string;

type CryptoBridge = {
  des:     (op: string, ...args: unknown[]) => Promise<Hex>;
  aes:     (op: string, ...args: unknown[]) => Promise<Hex>;
  aria:    (op: string, ...args: unknown[]) => Promise<Hex>;
  seed:    (op: string, ...args: unknown[]) => Promise<Hex>;
  mac:     (op: string, ...args: unknown[]) => Promise<Hex>;
  hash:    (alg: string, data: Hex, outputLen?: number) => Promise<Hex>;
  padding: (op: string, data: Hex, blockSize: number) => Promise<Hex>;
  random:  (length: number) => Promise<Hex>;
  bitwise: (op: string, a: Hex, b: Hex) => Promise<Hex>;
  rsa:     (op: string, ...args: unknown[]) => Promise<Hex | { n: Hex; d: Hex }>;
  ecc:     (op: string, ...args: unknown[]) => Promise<unknown>;
  pqc:     (op: string, ...args: unknown[]) => Promise<unknown>;
  chacha:  (op: string, ...args: unknown[]) => Promise<Hex>;
};

export type ElectronAPI = {
  loadSettings: () => Promise<Record<string, unknown>>;
  saveSettings: (s: Record<string, unknown>) => Promise<void>;
  minimize?: () => void;
  close?: () => void;
  crypto: CryptoBridge;
};

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}


import * as bitwise from './crypto/bitwise.ts';
import * as padding from './crypto/padding.ts';
import * as random from './crypto/random.ts';
import * as rsa from './crypto/rsa.ts';
import * as hash from './crypto/hash.ts';
import * as aes from './crypto/aes.ts';
import * as des from './crypto/des.ts';
import * as mac from './crypto/mac.ts';
import * as settingsStore from './settings-store.ts';
import * as aria from './crypto/aria.ts';
import * as seed from './crypto/seed.ts';
import * as ecc from './crypto/ecc.ts';
import * as pqc from './crypto/pqc.ts';
import * as chacha from './crypto/chacha.ts';

type PaddingOp = keyof typeof padding;

export function installElectronAPI(): void {
  const api: ElectronAPI = {
    loadSettings: async () => settingsStore.loadSettings(),
    saveSettings: async (s: Record<string, unknown>) => settingsStore.saveSettings(s),
    crypto: {
      des: async (op: string, ...args: unknown[]): Promise<Hex> => {
        const key = args[0] as string;
        const data = args[1] as string;
        const iv = args[2] as string | undefined;
        switch (op) {
          case 'ecbEncrypt': return des.ecbEncrypt(key, data);
          case 'ecbDecrypt': return des.ecbDecrypt(key, data);
          case 'cbcEncrypt': return des.cbcEncrypt(key, data, iv);
          case 'cbcDecrypt': return des.cbcDecrypt(key, data, iv);
          default: throw new Error(`Unknown DES op: ${op}`);
        }
      },
      aes: async (op: string, ...args: unknown[]): Promise<Hex> => {
        const key = args[0] as string;
        const data = args[1] as string;
        const iv = args[2] as string | undefined;
        const aad = args[3] as string | undefined;
        switch (op) {
          case 'ecbEncrypt': return aes.ecbEncrypt(key, data);
          case 'ecbDecrypt': return aes.ecbDecrypt(key, data);
          case 'cbcEncrypt': return aes.cbcEncrypt(key, data, iv);
          case 'cbcDecrypt': return aes.cbcDecrypt(key, data, iv);
          case 'ctrEncrypt': return aes.ctrEncrypt(key, data, iv);
          case 'ctrDecrypt': return aes.ctrDecrypt(key, data, iv);
          case 'gcmEncrypt': return aes.gcmEncrypt(key, data, iv!, aad);
          case 'gcmDecrypt': return aes.gcmDecrypt(key, data, iv!, aad);
          case 'cfbEncrypt': return aes.cfbEncrypt(key, data, iv);
          case 'cfbDecrypt': return aes.cfbDecrypt(key, data, iv);
          default: throw new Error(`Unknown AES op: ${op}`);
        }
      },
      aria: async (op: string, ...args: unknown[]): Promise<Hex> => {
        const key = args[0] as string;
        const data = args[1] as string;
        const iv = args[2] as string | undefined;
        switch (op) {
          case 'ecbEncrypt': return aria.ecbEncrypt(key, data);
          case 'ecbDecrypt': return aria.ecbDecrypt(key, data);
          case 'cbcEncrypt': return aria.cbcEncrypt(key, data, iv);
          case 'cbcDecrypt': return aria.cbcDecrypt(key, data, iv);
          default: throw new Error(`Unknown ARIA op: ${op}`);
        }
      },
      seed: async (op: string, ...args: unknown[]): Promise<Hex> => {
        const key = args[0] as string;
        const data = args[1] as string;
        const iv = args[2] as string | undefined;
        switch (op) {
          case 'ecbEncrypt': return seed.ecbEncrypt(key, data);
          case 'ecbDecrypt': return seed.ecbDecrypt(key, data);
          case 'cbcEncrypt': return seed.cbcEncrypt(key, data, iv);
          case 'cbcDecrypt': return seed.cbcDecrypt(key, data, iv);
          case 'cbcMac':     return seed.cbcMac(key, data);
          default: throw new Error(`Unknown SEED op: ${op}`);
        }
      },
      mac: async (op: string, ...args: unknown[]): Promise<Hex> => {
        switch (op) {
          case 'hmac':
            return mac.hmac(args[0] as string, args[1] as string, args[2] as string);
          case 'desMac':
            return mac.desMac(
              args[0] as string, args[1] as string,
              args[2] as string | undefined ?? '0000000000000000',
              (args[3] as number | undefined) ?? 8,
              (args[4] as string | undefined) ?? 'iso9797m2',
            );
          case 'retailMac':
            return mac.retailMac(
              args[0] as string, args[1] as string,
              args[2] as string | undefined ?? '0000000000000000',
              (args[3] as string | undefined) ?? 'iso9797m2',
            );
          case 'desTdesMac':
            return mac.desTdesMac(
              args[0] as string, args[1] as string,
              args[2] as string | undefined ?? '0000000000000000',
              (args[3] as string | undefined) ?? 'iso9797m2',
            );
          case 'desFullMac':
            return mac.desFullMac(
              args[0] as string, args[1] as string,
              (args[2] as string | undefined) ?? 'iso9797m2',
            );
          case 'cmacAes':
            return mac.cmacAes(args[0] as string, args[1] as string);
          default:
            throw new Error(`Unknown MAC op: ${op}`);
        }
      },
      hash: async (alg: string, data: Hex, outputLen?: number): Promise<Hex> => {
        return hash.digest(alg, data, outputLen);
      },

      padding: async (op: string, data: Hex, blockSize: number): Promise<Hex> => {
        const fn = padding[op as PaddingOp];
        if (typeof fn !== 'function') throw new Error(`Unknown padding op: ${op}`);
        return (fn as (d: string, bs?: number) => string)(data, blockSize);
      },

      random: async (length: number): Promise<Hex> => {
        return random.bytes(length);
      },

      bitwise: async (op: string, a: Hex, b: Hex): Promise<Hex> => {
        switch (op) {
          case 'xor': return bitwise.xor(a, b);
          case 'and': return bitwise.and(a, b);
          case 'or':  return bitwise.or(a, b);
          case 'not': return bitwise.not(a);
          case 'shl': return bitwise.shiftLeft(a, parseInt(b, 10));
          case 'shr': return bitwise.shiftRight(a, parseInt(b, 10));
          default: throw new Error(`Unknown bitwise op: ${op}`);
        }
      },

      rsa: async (op: string, ...args: unknown[]): Promise<Hex | { n: Hex; d: Hex }> => {
        switch (op) {
          case 'encrypt':
            return rsa.encrypt(args[0] as string, args[1] as string, args[2] as string);
          case 'decrypt':
            return rsa.decrypt(args[0] as string, args[1] as string, args[2] as string);
          case 'crtDecrypt':
            return rsa.crtDecrypt(
              args[0] as string, args[1] as string,
              args[2] as string, args[3] as string,
              args[4] as string, args[5] as string,
            );
          case 'crtToStandard':
            return rsa.crtToStandard(args[0] as string, args[1] as string, args[2] as string);
          default:
            throw new Error(`Unknown RSA op: ${op}`);
        }
      },

      ecc: async (op: string, ...args: unknown[]): Promise<unknown> => {
        switch (op) {
          case 'ecdhComputeSecret':
            return ecc.ecdhComputeSecret(args[0] as string, args[1] as string, args[2] as string | undefined);
          case 'ecdsaSign':
            return ecc.ecdsaSign(args[0] as string, args[1] as string, args[2] as string | undefined);
          case 'ecdsaVerify':
            return ecc.ecdsaVerify(
              args[0] as string, args[1] as string, args[2] as string, args[3] as string, args[4] as string | undefined,
            );
          case 'ecSdsaSign':
            return ecc.ecSdsaSign(args[0] as string, args[1] as string);
          case 'ecSdsaVerify':
            return ecc.ecSdsaVerify(
              args[0] as string, args[1] as string, args[2] as string, args[3] as string,
            );
          case 'derivePublicKey':
            return ecc.derivePublicKey(args[0] as string, args[1] as string | undefined);
          case 'ed25519Keygen':
            return ecc.ed25519Keygen();
          case 'ed25519Sign':
            return ecc.ed25519Sign(args[0] as string, args[1] as string);
          case 'ed25519Verify':
            return ecc.ed25519Verify(args[0] as string, args[1] as string, args[2] as string);
          case 'ed25519DerivePublicKey':
            return ecc.ed25519DerivePublicKey(args[0] as string);
          case 'x25519Keygen':
            return ecc.x25519Keygen();
          case 'x25519ComputeSecret':
            return ecc.x25519ComputeSecret(args[0] as string, args[1] as string);
          case 'x25519DerivePublicKey':
            return ecc.x25519DerivePublicKey(args[0] as string);
          default:
            throw new Error(`Unknown ECC op: ${op}`);
        }
      },
      chacha: async (op: string, ...args: unknown[]): Promise<Hex> => {
        const key = args[0] as string;
        const data = args[1] as string;
        const nonce = args[2] as string;
        const aad = args[3] as string | undefined;
        switch (op) {
          case 'encrypt': return chacha.encrypt(key, data, nonce, aad);
          case 'decrypt': return chacha.decrypt(key, data, nonce, aad);
          default: throw new Error(`Unknown ChaCha op: ${op}`);
        }
      },
      pqc: async (op: string, ...args: unknown[]): Promise<unknown> => {
        switch (op) {
          case 'kemKeygen':
            return pqc.kemKeygen(args[0] as number | string);
          case 'kemEncapsulate':
            return pqc.kemEncapsulate(
              args[0] as number | string, args[1] as string, args[2] as string | undefined,
            );
          case 'kemDecapsulate':
            return pqc.kemDecapsulate(args[0] as number | string, args[1] as string, args[2] as string);
          case 'dsaKeygen':
            return pqc.dsaKeygen(args[0] as number | string);
          case 'dsaSign':
            return pqc.dsaSign(args[0] as number | string, args[1] as string, args[2] as string);
          case 'dsaVerify':
            return pqc.dsaVerify(
              args[0] as number | string, args[1] as string, args[2] as string, args[3] as string,
            );
          default:
            throw new Error(`Unknown PQC op: ${op}`);
        }
      },
    },
  };
  window.electronAPI = api;
}
