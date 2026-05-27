# Cipher Studio 웹 마이그레이션 — Todo

작업 단위는 모두 **한 패널이 완전히 동작**하는 수직 슬라이스. 각 체크박스 = 하나의 acceptance test.

대상 경로: `c:/Users/UBIVELOX/Documents/Antigravity/cipher-studio-web/`

---

## Phase 0 — Bootstrap

### Task 0.1 — 프로젝트 scaffold (Vite + TS)
- [ ] `cipher-studio-web/` 폴더 생성 + `npm create vite@latest . -- --template vanilla-ts`
- [ ] 의존성 설치: `@noble/ciphers @noble/hashes @noble/curves @noble/post-quantum js-md5 buffer`
- [ ] `tsconfig.json`: strict / noUncheckedIndexedAccess / target ES2022 / lib ES2022+DOM
- [ ] `npm run dev` → 빈 Vite 페이지가 localhost에서 뜸 / `npx tsc --noEmit` 통과

### Task 0.2 — HTML/CSS/폰트 이식 + 어댑터 스텁
- [ ] `cipher-studio.html` → `index.html`로 복사 (인라인 `<script>` 그대로)
- [ ] `cryptoIDE/fonts/` → `public/fonts/` 통째로 복사
- [ ] `<head>`에 `<script type="module" src="/src/main.ts">` 추가
- [ ] `src/electronAPI-adapter.ts`: window.electronAPI 타입 정의 + 모든 메서드 throw stub
- [ ] `src/main.ts`: 어댑터를 `window.electronAPI`에 부착
- [ ] **검증**: 사이드바 13개 패널 토글 OK / 다크-라이트 테마 토글 OK / 임의 패널 실행 시 "not-implemented" 에러만 표시 (UI 흐름 정상) / `tsc --noEmit` 통과

🛑 **Checkpoint A** — 사용자 확인: Electron판과 시각적으로 동일

---

## Phase 1 — 의존성 0 패널

### Task 1.1 — XOR 패널
- [ ] `src/crypto/hex-utils.ts` 이식
- [ ] `src/crypto/bitwise.ts` 이식
- [ ] 어댑터 `crypto.bitwise` wiring
- [ ] **검증**: `AA BB` ⊕ `12 34` = `B8 8F`

### Task 1.2 — Padding 패널
- [ ] `src/crypto/padding.ts` 이식 (Buffer polyfill 동작 확인)
- [ ] 어댑터 `crypto.padding` wiring
- [ ] **검증**: 5종 알고리즘 (M1/M2/PKCS5/PKCS7/desPad/aesPad) 모두 Electron판과 동일

### Task 1.3 — Random 패널
- [ ] `src/crypto/random.ts`: `getRandomValues` 기반 재작성
- [ ] 어댑터 `crypto.random` wiring
- [ ] **검증**: 32 B 요청 → 64 hex 출력 / 두 번 호출 결과 상이

### Task 1.4 — RSA 패널
- [ ] `src/crypto/rsa.ts` 이식 (BigInt only)
- [ ] 어댑터 `crypto.rsa` wiring
- [ ] **검증**: Encrypt/Decrypt 라운드트립 / CRT Decrypt == Standard Decrypt / CRT→Standard 결과로 다시 암호화 OK

🛑 **Checkpoint B** — Phase 1 네 패널 일치 확인

---

## Phase 2 — Hash & AES (WebCrypto)

### Task 2.1 — Hash 패널
- [ ] `src/crypto/hash.ts`: SHA1/256 → WebCrypto, MD5 → `js-md5`
- [ ] **검증**: SHA-256("") = `e3b0c442...`, SHA-1("616263") = `a9993e36...`, MD5("") = `d41d8cd9...`

### Task 2.2 — AES 패널
- [ ] `src/crypto/aes.ts`: `@noble/ciphers/aes` (ecb/cbc/ctr) — autoPad off
- [ ] **검증**: NIST AES-128 ECB 테스트 벡터 / CBC 128·192·256 라운드트립 / CTR 라운드트립

🛑 **Checkpoint C**

---

## Phase 3 — DES/3DES

### Task 3.1 — DES 패널
- [ ] `src/crypto/des.ts`: `@noble/ciphers/legacy` des / tdes_ede
- [ ] **검증**: DES ECB FIPS PUB 81 벡터 / 3DES CBC 라운드트립 / 8·16·24 B 키 모두 동작

🛑 **Checkpoint D**

---

## Phase 4 — MAC

### Task 4.1 — MAC 패널
- [ ] `src/crypto/mac.ts`: HMAC (noble/hashes), AES-CMAC, DES Retail/TDES/FullMAC (Phase 3 des 재사용)
- [ ] **검증**: HMAC-SHA256 ("key"/quick fox) / AES-CMAC RFC 4493 4종 벡터 / DES Retail MAC = Electron판 결과

🛑 **Checkpoint E**

---

## Phase 5 — ARIA / SEED

### Task 5.1 — ARIA & SEED 패널
- [ ] `vite.config.ts`에 buffer alias / `main.ts` 최상단 `window.Buffer = Buffer`
- [ ] `src/crypto/aria.ts`, `src/crypto/seed.ts` 원본 이식
- [ ] **검증**: ARIA RFC 5794 벡터 (key 16/24/32) / SEED TTAS.KO-12.0004 벡터 + CBC-MAC

🛑 **Checkpoint F**

---

## Phase 6 — ECC

### Task 6.1 — ECDSA/ECDH/EC-SDSA 패널
- [ ] `src/crypto/ecc.ts`: `@noble/curves/p256` 기반 + EC-SDSA BigInt 유지
- [ ] DER 코덱 재사용 (기존 `_encodeEcdsaDer/_decodeEcdsaDer`)
- [ ] `crypto.randomBytes` → `getRandomValues` 교체
- [ ] **검증**: ECDSA Sign→Verify 라운드트립 / ECDH 양쪽 어댑터 일치 / EC-SDSA 라운드트립 / Electron판이 서명한 EC-SDSA를 브라우저판이 검증 OK

🛑 **Checkpoint G**

---

## Phase 7 — PQC

### Task 7.1 — ML-KEM / ML-DSA 패널
- [ ] `src/crypto/pqc.ts`: `@noble/post-quantum` 그대로 + Buffer → Uint8Array
- [ ] **검증**: ML-KEM-768 keygen→encap→decap shared secret 일치 / ML-DSA-65 sign→verify true / 1바이트 손상 → verify false

🛑 **Checkpoint H**

---

## Phase 8 — Settings & 정리

### Task 8.1 — Settings + 잔여 정리
- [ ] `src/settings-store.ts` (localStorage 래퍼)
- [ ] 어댑터 `loadSettings/saveSettings` 연결
- [ ] `btn-min`/`btn-close` 숨김
- [ ] grep: `electronAPI.` 호출이 모두 어댑터 경유하는지 확인
- [ ] **검증**: 테마 토글 → 새로고침 → 직전 테마 유지

🛑 **Checkpoint I** — 13개 패널 1회씩 손으로 돌려보기

---

## Phase 9 — Build & Deploy

### Task 9.1 — 정적 빌드 + 배포 문서
- [ ] `npm run build` → `dist/` 생성
- [ ] `npx vite preview` 로컬 검증
- [ ] `README.md`: dev/build 명령 + 호스팅 옵션 3종 가이드
- [ ] `npx tsc --noEmit` 통과 (전체 TS 빌드 검증)
- [ ] (옵션) 호스팅 선택 후 `vite.config.ts` `base` 설정

🛑 **Final Checkpoint** — 배포 URL에서 외부 브라우저로 13개 패널 전부 OK
