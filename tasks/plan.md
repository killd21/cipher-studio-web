# Cipher Studio 암호화 기능 확장 계획

## Context

Cipher Studio는 브라우저 기반 암호화 도구 모음으로, 현재 대칭키(AES, DES, ARIA, SEED), 비대칭키(RSA, ECC), PQC(ML-KEM, ML-DSA), 유틸리티(Hash, MAC, Padding, Bitwise, Random, ASCII↔Hex)를 지원한다. @noble 라이브러리가 제공하는 기능 중 아직 노출되지 않은 알고리즘과 모드가 많고, 현대 암호화 표준(TLS 1.3, FIPS 205 등)에서 필요한 알고리즘이 빠져 있다.

이 계획은 기존 모듈 확장 → 신규 모던 알고리즘 → 고급 기능 순서로 12개 태스크를 3단계에 걸쳐 구현한다.

## 아키텍처 패턴 (모든 태스크 공통)

각 기능은 3개 레이어를 수직으로 관통:
1. **Crypto 모듈** (`src/crypto/<name>.ts`) — 순수 함수, hex string 입출력
2. **Adapter** (`src/electronAPI-adapter.ts`) — `window.electronAPI.crypto.*`에 매핑
3. **UI 패널** (`index.html`) — dock item + panel HTML + inline JS handler

---

## Phase 1: 기존 모듈 확장 (모두 독립, 병렬 가능)

### Task 1.1: SHA-3 Family 추가 [S]
- `src/crypto/hash.ts`: `@noble/hashes/sha3`에서 sha3_256/384/512, shake128/256 import, digest() 확장
- SHAKE는 출력 길이 파라미터 필요 → digest 시그니처에 optional `outputLen` 추가
- `index.html`: `#hash-alg` select에 옵션 추가, SHAKE 선택 시 출력 길이 input 표시
- **검증**: NIST 테스트 벡터 (empty, "abc"), SHAKE 가변 길이 출력

### Task 1.2: ML-KEM-1024 변형 추가 [S]
- `src/crypto/pqc.ts`: `ml_kem1024` import, getKem()에 1024 케이스 추가
- `index.html`: `#mlkem-variant` select에 `<option value="1024">` 추가
- Adapter 변경 불필요 (variant가 이미 passthrough)
- **검증**: keygen → encap → decap 라운드트립, shared secret 일치

### Task 1.3: Bitwise 연산 완성 (AND/OR/NOT/Shift) [S]
- `src/crypto/bitwise.ts`: and, or, not, shiftLeft, shiftRight 함수 추가
- `src/electronAPI-adapter.ts`: bitwise switch에 케이스 추가
- `index.html`: 연산 선택 드롭다운, NOT 시 Hex B 숨김, Shift 시 비트 수 입력 표시
- **검증**: `and('FF','0F')='0F'`, `not('FF')='00'`, `shl('01',4)='10'`

### Task 1.4: AES-CFB 모드 추가 [S]
- `src/crypto/aes.ts`: `@noble/ciphers/aes`에서 cfb import, cfbEncrypt/cfbDecrypt 추가
- `index.html`: `#aes-mode`에 CFB 옵션, updateAesMode()에서 CFB 처리 (IV 필요, 패딩 불필요)
- **검증**: NIST SP 800-38A AES-CFB128 테스트 벡터

### Phase 1 체크포인트
- `vitest run` 전체 통과
- 각 확장 패널 수동 스모크 테스트

---

## Phase 2: 신규 모던 알고리즘 (새 패널 추가)

### Task 2.1: ChaCha20-Poly1305 (AEAD) [M]
- **신규** `src/crypto/chacha.ts`: `@noble/ciphers/chacha`에서 chacha20poly1305 import
- Key=32B, Nonce=12B, 선택적 AAD, 암호문에 16B Poly1305 태그 포함
- Adapter에 `chacha` 네임스페이스 추가
- `index.html`: Symmetric 그룹에 dock item "CC", panel-chacha 추가
- **검증**: RFC 8439 Section 2.8.2 벡터, 변조된 암호문 복호화 실패 확인

### Task 2.2: Ed25519 서명 [M]
- `src/crypto/ecc.ts`: `@noble/curves/ed25519`에서 ed25519 import
- ed25519Keygen, ed25519Sign, ed25519Verify, ed25519DerivePublicKey 추가
- `index.html`: ECC 그룹에 dock item "ED", panel-ed25519 추가
- **검증**: RFC 8032 Section 7.1 벡터, 변조 메시지 검증 실패

### Task 2.3: X25519 키 교환 [S]
- `src/crypto/ecc.ts`: `@noble/curves/ed25519`에서 x25519 import (2.2와 같은 경로)
- x25519Keygen, x25519ComputeSecret, x25519DerivePublicKey 추가
- `index.html`: ECC 그룹에 dock item "X2", panel-x25519 추가
- **검증**: RFC 7748 Section 6.1 벡터, 양측 shared secret 일치
- **순서**: Task 2.2 이후 (같은 파일 수정)

### Task 2.4: 다중 ECC 커브 (P-384, secp256k1) [M]
- `src/crypto/ecc.ts`: p384, secp256k1 import, getCurve(name) 헬퍼 추가
- 기존 ECDSA/ECDH 함수를 curve 파라미터 수용하도록 리팩토링 (기본값 P-256 유지)
- `index.html`: ECDSA, ECDH 패널에 커브 선택 드롭다운 추가
- **검증**: P-384/secp256k1 ECDSA sign/verify, ECDH 라운드트립, P-256 호환성 유지
- **순서**: Task 2.2/2.3 이후 (ecc.ts 충돌 방지)

### Phase 2 체크포인트
- 전체 테스트 통과
- 새 4개 패널 UI 스모크 테스트
- Phase 1 기능 리그레션 확인

---

## Phase 3: 고급 기능

### Task 3.1: HKDF / PBKDF2 키 유도 함수 [M]
- **신규** `src/crypto/kdf.ts`: `@noble/hashes/hkdf`, `@noble/hashes/pbkdf2` import
- HKDF: derive, extract, expand / PBKDF2: derive (async로 UI 블로킹 방지)
- `index.html`: Utility 그룹에 dock item "KD", panel-kdf 추가
- HKDF 선택 시 info 필드, PBKDF2 선택 시 iterations 필드 조건부 표시
- **검증**: RFC 5869 Appendix A (HKDF), RFC 6070 (PBKDF2) 벡터

### Task 3.2: SLH-DSA (FIPS 205 해시기반 PQC 서명) [M]
- `src/crypto/pqc.ts`: `@noble/post-quantum/slh-dsa` import
- 변형: slh_dsa_shake_128f, slh_dsa_shake_256f (fast 변형 우선)
- 서명이 크므로 (최대 ~50KB) UI에 스크롤 가능한 textarea 사용
- `index.html`: PQC 그룹에 dock item "SL", panel-slhdsa 추가
- **검증**: keygen/sign/verify 라운드트립, 변조 서명 거부, 수 초 내 완료

### Task 3.3: Base64 인코딩/디코딩 [S]
- **신규** `src/crypto/base64.ts`: hexToBase64, base64ToHex, Base64url 변형 지원
- 기존 ASCII↔Hex 패널을 "Encoding" 패널로 확장하거나 별도 패널 추가
- **검증**: `hexToBase64('48656C6C6F')='SGVsbG8='`, Base64url (`-_` 치환, `=` 제거)

### Task 3.4: BLAKE2b/s, BLAKE3, RIPEMD-160 해시 [S]
- `src/crypto/hash.ts`: `@noble/hashes/blake2`, `blake3`, `ripemd160` import, digest() 확장
- BLAKE2/3는 가변 출력 길이 지원 (Task 1.1의 SHAKE 패턴 재사용)
- `index.html`: `#hash-alg` select에 옵션 추가
- **검증**: 각 알고리즘 레퍼런스 벡터 대조

### Phase 3 체크포인트
- 전체 테스트 통과
- SLH-DSA, PBKDF2 성능 확인 (브라우저에서 수 초 이내)
- 전체 dock 항목 레이아웃 리뷰 (모바일 하단 탭바 포함)

---

## 의존성 그래프

```
Phase 1 (모두 독립):
  1.1 SHA-3 ──────────┐
  1.2 ML-KEM-1024 ────┤── Phase 1 체크포인트
  1.3 Bitwise ────────┤
  1.4 AES-CFB ────────┘

Phase 2 (2.2→2.3→2.4 순차, 2.1 독립):
  2.1 ChaCha20 ───────┐
  2.2 Ed25519 → 2.3 X25519 → 2.4 Multi-curve ──┤── Phase 2 체크포인트

Phase 3 (모두 독립, 3.4는 1.1 패턴 참조):
  3.1 KDF ────────────┐
  3.2 SLH-DSA ────────┤── Phase 3 체크포인트
  3.3 Base64 ──────────┤
  3.4 BLAKE2/3 ────────┘
```

## 핵심 수정 파일

- `src/crypto/hash.ts` — Task 1.1, 3.4
- `src/crypto/pqc.ts` — Task 1.2, 3.2
- `src/crypto/bitwise.ts` — Task 1.3
- `src/crypto/aes.ts` — Task 1.4
- `src/crypto/ecc.ts` — Task 2.2, 2.3, 2.4
- `src/electronAPI-adapter.ts` — 거의 모든 태스크
- `index.html` — 모든 태스크 (UI 패널)

## 신규 생성 파일

- `src/crypto/chacha.ts` — Task 2.1
- `src/crypto/kdf.ts` — Task 3.1
- `src/crypto/base64.ts` — Task 3.3
- `test/crypto/` 하위 테스트 파일들 (각 태스크별)

## 검증 방법

1. `npm run build` — TypeScript 컴파일 에러 없음
2. `vitest run` — 전체 테스트 통과
3. `npm run dev` → 브라우저에서 각 패널 수동 테스트
4. 모바일 뷰 (768px 이하) 에서 하단 탭바에 새 항목 표시 확인
