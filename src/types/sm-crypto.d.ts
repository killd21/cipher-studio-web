declare module 'sm-crypto' {
  export interface KeyPair {
    publicKey: string;
    privateKey: string;
  }

  export interface SM2Options {
    hash?: boolean;
    der?: boolean;
    userId?: string;
  }

  export const sm2: {
    generateKeyPairHex(): KeyPair;
    compressPublicKeyHex(s: string): string;
    comparePublicKeyHex(a: string, b: string): boolean;
    doEncrypt(msg: string | number[] | Uint8Array, publicKey: string, cipherMode?: 0 | 1): string;
    doDecrypt(
      ciphertext: string,
      privateKey: string,
      cipherMode?: 0 | 1,
      options?: { output?: 'string' | 'array' }
    ): string | number[];
    doSignature(msg: string | number[] | Uint8Array, privateKey: string, options?: SM2Options): string;
    doVerifySignature(
      msg: string | number[] | Uint8Array,
      sig: string,
      publicKey: string,
      options?: SM2Options
    ): boolean;
    getPublicKeyFromPrivateKey(privateKey: string): string;
    verifyPublicKey(publicKey: string): boolean;
  };

  export function sm3(
    input: string | number[] | Uint8Array,
    options?: { mode?: 'hmac'; key?: string | number[] | Uint8Array }
  ): string;

  export interface SM4Options {
    mode?: 'ecb' | 'cbc';
    iv?: string | number[] | Uint8Array;
    padding?: 'pkcs#5' | 'pkcs#7' | 'none';
    output?: 'string' | 'array';
  }

  export const sm4: {
    encrypt(data: string | number[] | Uint8Array, key: string | number[] | Uint8Array, options?: SM4Options): string | number[];
    decrypt(data: string | number[] | Uint8Array, key: string | number[] | Uint8Array, options?: SM4Options): string | number[];
  };
}
