# Cipher Studio - Web Edition

브라우저 기반 암호화 도구 모음. 서버 통신 없이 모든 연산이 클라이언트에서 수행됩니다.

## 지원 알고리즘

### 대칭키 암호 (Symmetric Cipher)

| 알고리즘 | 표준 | 블록 크기 | 키 길이 | 운용 모드 |
|---------|------|----------|--------|----------|
| DES / 3DES | FIPS 46-3, NIST SP 800-67 | 64-bit | 8 / 16 / 24 bytes | ECB, CBC |
| AES | FIPS 197 | 128-bit | 128 / 192 / 256-bit | ECB, CBC, CTR, GCM (AEAD) |
| ARIA | RFC 5794, KS X 1213 | 128-bit | 128 / 192 / 256-bit | ECB, CBC |
| SEED | RFC 4269, TTAS.KO-12.0004 | 128-bit | 128-bit | ECB, CBC |

- 패딩: ISO 9797-1 M1 (0x00), ISO 9797-1 M2 (0x80), No Padding
- AES-GCM은 AAD(Associated Authenticated Data) 입력 지원

### 비대칭키 암호 (Asymmetric Cipher)

| 알고리즘 | 표준 | 설명 |
|---------|------|------|
| RSA | PKCS #1, RFC 8017 | Raw Modular Exponentiation, CRT 지원 |

- 연산 모드: Encrypt, Decrypt, CRT Decrypt, CRT → Standard 변환

### 타원곡선 암호 (ECC)

| 알고리즘 | 표준 | 커브 | 기능 |
|---------|------|------|------|
| ECDSA | FIPS 186-5, ANSI X9.62 | secp256r1 (P-256) | 서명 / 검증 |
| ECDH | NIST SP 800-56A, RFC 5903 | secp256r1 (P-256) | 키 합의 (Shared Secret) |
| EC-SDSA | ISO/IEC 14888-3 | secp256r1 (P-256) | EC-Schnorr 서명 / 검증 |

### 양자내성 암호 (PQC)

| 알고리즘 | 표준 | 변형 | 기능 |
|---------|------|------|------|
| ML-KEM | FIPS 203 | ML-KEM-512, ML-KEM-768 | 키 생성 / 캡슐화 / 역캡슐화 |
| ML-DSA | FIPS 204 | ML-DSA-44, ML-DSA-65, ML-DSA-87 | 키 생성 / 서명 / 검증 |

### 유틸리티

| 기능 | 표준 | 설명 |
|------|------|------|
| MAC | ISO 9797-1 (DES MAC), RFC 2104 (HMAC) | 메시지 인증 코드 생성 |
| Hash | FIPS 180-4 (SHA-1/256/384/512), RFC 1321 (MD5) | 해시 다이제스트 |
| Padding | ISO 9797-1 M1/M2/M3, PKCS #5/#7 | 블록 암호 패딩 적용/제거 |
| Bitwise | — | XOR, AND, OR, NOT, Shift 연산 |
| Random | — | 난수 생성 |
| ASCII ↔ Hex | — | ASCII 문자열 ↔ 16진수 변환 |

## 기술 스택

- **Crypto**: `@noble/ciphers`, `@noble/curves`, `@noble/hashes`, `@noble/post-quantum`
- **Build**: Vite + TypeScript
- **Test**: Vitest

## 입출력 형식

모든 암호 연산의 입출력은 **Hex(16진수) 문자열** 형식입니다.
