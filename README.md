# Cipher Studio - Web Edition

A browser-based cryptography toolkit. All operations run client-side with no server communication.

## Supported Algorithms

### Symmetric Cipher

| Algorithm | Standard | Block Size | Key Length | Modes |
|---------|------|----------|--------|----------|
| DES / 3DES | FIPS 46-3, NIST SP 800-67 | 64-bit | 8 / 16 / 24 bytes | ECB, CBC |
| AES | FIPS 197 | 128-bit | 128 / 192 / 256-bit | ECB, CBC, CTR, CFB, GCM (AEAD), CCM (AEAD) |
| ARIA | RFC 5794, KS X 1213 | 128-bit | 128 / 192 / 256-bit | ECB, CBC |
| SEED | RFC 4269, TTAS.KO-12.0004 | 128-bit | 128-bit | ECB, CBC |
| ChaCha20-Poly1305 | RFC 8439 | Stream | 256-bit | AEAD (96-bit nonce) |

- Padding: ISO 9797-1 M1 (0x00), ISO 9797-1 M2 (0x80), No Padding
- AES-GCM / AES-CCM / ChaCha20-Poly1305 support AAD (Associated Authenticated Data) input
- AES-CCM: NIST SP 800-38C / RFC 3610, 7-13B nonce, 4/6/8/10/12/14/16B tag

### Asymmetric Cipher

| Algorithm | Standard | Description |
|---------|------|------|
| RSA | PKCS #1, RFC 8017 | Raw Modular Exponentiation with CRT support |

- Operations: Encrypt, Decrypt, CRT Decrypt, CRT → Standard conversion

### Elliptic Curve Cryptography (ECC)

| Algorithm | Standard | Curve | Features |
|---------|------|------|------|
| ECDSA | FIPS 186-5, ANSI X9.62 | P-256, P-384, secp256k1 | Sign / Verify |
| ECDH | NIST SP 800-56A, RFC 5903 | P-256, P-384, secp256k1 | Key Agreement (Shared Secret) |
| EC-SDSA | ISO/IEC 14888-3 | secp256r1 (P-256) | EC-Schnorr Sign / Verify |
| Ed25519 | RFC 8032 | Curve25519 (Edwards) | Keygen / Sign / Verify |
| X25519 | RFC 7748 | Curve25519 (Montgomery) | Key Agreement (Shared Secret) |

### Post-Quantum Cryptography (PQC)

| Algorithm | Standard | Variants | Features |
|---------|------|------|------|
| ML-KEM | FIPS 203 | ML-KEM-512 / 768 / 1024 | Keygen / Encapsulate / Decapsulate |
| ML-DSA | FIPS 204 | ML-DSA-44 / 65 / 87 | Keygen / Sign / Verify |
| SLH-DSA | FIPS 205 | SHAKE / SHA2 × 128 / 192 / 256 (fast) | Keygen / Sign / Verify |

### Utilities

| Feature | Standard | Description |
|------|------|------|
| Hash | FIPS 180-4, FIPS 202, RFC 1321, RFC 7693 | SHA-1, SHA-256/384/512, SHA3-256/384/512, SHAKE128/256, BLAKE2b/s, BLAKE3, RIPEMD-160, MD5 |
| MAC | RFC 2104 (HMAC), ISO/IEC 9797-1 (DES MAC), RFC 4493 (AES-CMAC) | HMAC supports SHA-1/2/3 families |
| KDF | RFC 5869 (HKDF), RFC 8018 (PBKDF2) | Key derivation functions; supports 7 HMAC-compatible hashes |
| Padding | ISO 9797-1 M1/M2/M3, PKCS #5/#7 | Apply / remove block cipher padding |
| Bitwise | — | XOR, AND, OR, NOT, Shift Left/Right operations |
| Random | — | CSPRNG (Web Crypto getRandomValues) |
| Encoding | RFC 4648 | ASCII ↔ Hex, Hex ↔ Base64 / Base64url conversion |

## Tech Stack

### Build & Test
[![TypeScript](https://img.shields.io/github/package-json/dependency-version/killd21/cipher-studio-web/dev/typescript?logo=typescript&logoColor=white&label=TypeScript&color=3178C6)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/github/package-json/dependency-version/killd21/cipher-studio-web/dev/vite?logo=vite&logoColor=white&label=Vite&color=646CFF)](https://vitejs.dev/)
[![Vitest](https://img.shields.io/github/package-json/dependency-version/killd21/cipher-studio-web/dev/vitest?logo=vitest&logoColor=white&label=Vitest&color=6E9F18)](https://vitest.dev/)

### Crypto Libraries
[![@noble/ciphers](https://img.shields.io/github/package-json/dependency-version/killd21/cipher-studio-web/@noble/ciphers?logo=npm&logoColor=white&label=%40noble%2Fciphers&color=8B5CF6)](https://www.npmjs.com/package/@noble/ciphers)
[![@noble/curves](https://img.shields.io/github/package-json/dependency-version/killd21/cipher-studio-web/@noble/curves?logo=npm&logoColor=white&label=%40noble%2Fcurves&color=8B5CF6)](https://www.npmjs.com/package/@noble/curves)
[![@noble/hashes](https://img.shields.io/github/package-json/dependency-version/killd21/cipher-studio-web/@noble/hashes?logo=npm&logoColor=white&label=%40noble%2Fhashes&color=8B5CF6)](https://www.npmjs.com/package/@noble/hashes)
[![@noble/post-quantum](https://img.shields.io/github/package-json/dependency-version/killd21/cipher-studio-web/@noble/post-quantum?logo=npm&logoColor=white&label=%40noble%2Fpost-quantum&color=8B5CF6)](https://www.npmjs.com/package/@noble/post-quantum)

### Repository
[![CI](https://github.com/killd21/cipher-studio-web/actions/workflows/ci.yml/badge.svg)](https://github.com/killd21/cipher-studio-web/actions/workflows/ci.yml)
[![Last Commit](https://img.shields.io/github/last-commit/killd21/cipher-studio-web?logo=github)](https://github.com/killd21/cipher-studio-web/commits/master)
[![Tests](https://img.shields.io/badge/tests-245%20passed-success?logo=vitest&logoColor=white)](./test)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)

## I/O Format

All cryptographic operations use **hex (hexadecimal) strings** for input and output.
The Base64 encoding utility supports conversion to and from standard / URL-safe Base64.

## License

This project is distributed under the [MIT License](./LICENSE).

Copyright (c) 2026 killd21
