# Cipher Studio - Web Edition

브라우저 기반 암호화 도구 모음. 서버 통신 없이 모든 연산이 클라이언트에서 수행됩니다.

## 지원 알고리즘

### 대칭키 암호 (Symmetric Cipher)

| 알고리즘 | 표준 | 블록 크기 | 키 길이 | 운용 모드 |
|---------|------|----------|--------|----------|
| DES / 3DES | FIPS 46-3, NIST SP 800-67 | 64-bit | 8 / 16 / 24 bytes | ECB, CBC |
| AES | FIPS 197 | 128-bit | 128 / 192 / 256-bit | ECB, CBC, CTR, CFB, GCM (AEAD), CCM (AEAD) |
| ARIA | RFC 5794, KS X 1213 | 128-bit | 128 / 192 / 256-bit | ECB, CBC |
| SEED | RFC 4269, TTAS.KO-12.0004 | 128-bit | 128-bit | ECB, CBC |
| ChaCha20-Poly1305 | RFC 8439 | Stream | 256-bit | AEAD (96-bit nonce) |

- 패딩: ISO 9797-1 M1 (0x00), ISO 9797-1 M2 (0x80), No Padding
- AES-GCM / AES-CCM / ChaCha20-Poly1305는 AAD(Associated Authenticated Data) 입력 지원
- AES-CCM: NIST SP 800-38C / RFC 3610, 7-13B nonce, 4/6/8/10/12/14/16B tag

### 비대칭키 암호 (Asymmetric Cipher)

| 알고리즘 | 표준 | 설명 |
|---------|------|------|
| RSA | PKCS #1, RFC 8017 | Raw Modular Exponentiation, CRT 지원 |

- 연산 모드: Encrypt, Decrypt, CRT Decrypt, CRT → Standard 변환

### 타원곡선 암호 (ECC)

| 알고리즘 | 표준 | 커브 | 기능 |
|---------|------|------|------|
| ECDSA | FIPS 186-5, ANSI X9.62 | P-256, P-384, secp256k1 | 서명 / 검증 |
| ECDH | NIST SP 800-56A, RFC 5903 | P-256, P-384, secp256k1 | 키 합의 (Shared Secret) |
| EC-SDSA | ISO/IEC 14888-3 | secp256r1 (P-256) | EC-Schnorr 서명 / 검증 |
| Ed25519 | RFC 8032 | Curve25519 (Edwards) | 키 생성 / 서명 / 검증 |
| X25519 | RFC 7748 | Curve25519 (Montgomery) | 키 합의 (Shared Secret) |

### 양자내성 암호 (PQC)

| 알고리즘 | 표준 | 변형 | 기능 |
|---------|------|------|------|
| ML-KEM | FIPS 203 | ML-KEM-512 / 768 / 1024 | 키 생성 / 캡슐화 / 역캡슐화 |
| ML-DSA | FIPS 204 | ML-DSA-44 / 65 / 87 | 키 생성 / 서명 / 검증 |
| SLH-DSA | FIPS 205 | SHAKE / SHA2 × 128 / 192 / 256 (fast) | 키 생성 / 서명 / 검증 |

### 유틸리티

| 기능 | 표준 | 설명 |
|------|------|------|
| Hash | FIPS 180-4, FIPS 202, RFC 1321, RFC 7693 | SHA-1, SHA-256/384/512, SHA3-256/384/512, SHAKE128/256, BLAKE2b/s, BLAKE3, RIPEMD-160, MD5 |
| MAC | RFC 2104 (HMAC), ISO/IEC 9797-1 (DES MAC), RFC 4493 (AES-CMAC) | HMAC은 SHA-1/2/3 모두 지원 |
| KDF | RFC 5869 (HKDF), RFC 8018 (PBKDF2) | 키 유도 함수, HMAC 호환 7개 해시 지원 |
| Padding | ISO 9797-1 M1/M2/M3, PKCS #5/#7 | 블록 암호 패딩 적용/제거 |
| Bitwise | — | XOR, AND, OR, NOT, Shift Left/Right 연산 |
| Random | — | CSPRNG (Web Crypto getRandomValues) |
| Encoding | RFC 4648 | ASCII ↔ Hex, Hex ↔ Base64 / Base64url 변환 |

## 기술 스택

- **Crypto**: `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`
- **Build**: Vite + TypeScript
- **Test**: Vitest (13개 테스트 파일, 245개 테스트 통과)

## 입출력 형식

모든 암호 연산의 입출력은 **Hex(16진수) 문자열** 형식입니다.
Base64 인코딩 유틸리티를 통해 표준 / URL-safe Base64로 상호 변환할 수 있습니다.
