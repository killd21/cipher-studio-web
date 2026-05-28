# Cipher Studio 기능 확장 태스크 목록

## Phase 1: 기존 모듈 확장

- [ ] **1.1** SHA-3 Family (SHA3-256/384/512, SHAKE128/256) — hash.ts, index.html
- [ ] **1.2** ML-KEM-1024 변형 추가 — pqc.ts, index.html
- [ ] **1.3** Bitwise 연산 완성 (AND/OR/NOT/Shift) — bitwise.ts, adapter, index.html
- [ ] **1.4** AES-CFB 모드 — aes.ts, adapter, index.html
- [ ] **Phase 1 체크포인트**: 빌드 + 테스트 + 스모크 테스트

## Phase 2: 신규 모던 알고리즘

- [ ] **2.1** ChaCha20-Poly1305 AEAD — 신규 chacha.ts, adapter, index.html
- [ ] **2.2** Ed25519 서명 — ecc.ts, adapter, index.html
- [ ] **2.3** X25519 키 교환 (2.2 이후) — ecc.ts, adapter, index.html
- [ ] **2.4** 다중 ECC 커브 P-384/secp256k1 (2.3 이후) — ecc.ts, adapter, index.html
- [ ] **Phase 2 체크포인트**: 빌드 + 테스트 + 리그레션 확인

## Phase 3: 고급 기능

- [ ] **3.1** HKDF / PBKDF2 키 유도 함수 — 신규 kdf.ts, adapter, index.html
- [ ] **3.2** SLH-DSA (FIPS 205) PQC 서명 — pqc.ts, adapter, index.html
- [ ] **3.3** Base64 인코딩/디코딩 — 신규 base64.ts, adapter, index.html
- [ ] **3.4** BLAKE2b/s, BLAKE3, RIPEMD-160 해시 — hash.ts, index.html
- [ ] **Phase 3 체크포인트**: 빌드 + 테스트 + 성능 + 레이아웃 리뷰
