# Cipher Studio — 정적 웹 마이그레이션 계획 (A안)

**목표**: `cryptoIDE/cipher-studio.html`을 Electron 의존성에서 분리해, 순수 정적 웹앱으로 배포 가능한 신규 프로젝트 `../cipher-studio-web/`을 만든다.

**대상 경로**: `c:/Users/UBIVELOX/Documents/Antigravity/cipher-studio-web/`

**원본**: `c:/Users/UBIVELOX/Documents/Antigravity/ScriptIDE/cryptoIDE/cipher-studio.html` (3310줄, fonts/ 포함)

---

## 1. 의존성 매트릭스

`cipher-studio.html`이 호출하는 외부 API 13종 + 각 API가 기대는 Node 측 모듈:

| 사용 API | 호출 부 | 원본 구현 | 브라우저 대체 전략 | 난이도 |
|---|---|---|---|---|
| `loadSettings/saveSettings` | initTheme/toggleTheme | electron userData JSON | `localStorage` 어댑터 | ⭐ |
| `minimize/close` | btn-min/btn-close | BrowserWindow API | 버튼 숨김 | ⭐ |
| `crypto.bitwise` | XOR 패널 | `crypto/bitwise.js` (순수 JS) | 그대로 이식 | ⭐ |
| `crypto.padding` | Padding 패널 + DES/AES Enc | `crypto/padding.js` (순수 JS, Buffer) | 그대로 이식 + Buffer polyfill | ⭐ |
| `crypto.random` | Random 패널 + ML-KEM 입력 채움 | `crypto.randomBytes` | `crypto.getRandomValues` | ⭐ |
| `crypto.rsa` | RSA 패널 | `crypto/rsa.js` (BigInt only) | 그대로 이식 | ⭐ |
| `crypto.hash` | Hash 패널 | Node `crypto` (SHA1/256/MD5) | WebCrypto `subtle.digest` + MD5는 `js-md5` | ⭐⭐ |
| `crypto.aes` | AES 패널 + MAC AES-CMAC | Node `crypto` (ECB/CBC/CTR) | `@noble/ciphers/aes` (ECB 직접/CBC/CTR) | ⭐⭐ |
| `crypto.des` | DES 패널 + MAC 일부 | Node `crypto` (des-ede/des-ede3) | `@noble/ciphers/legacy` (DES/3DES) | ⭐⭐ |
| `crypto.aria` | ARIA 패널 | `crypto/aria.js` (순수 JS S-box, Buffer) | 그대로 이식 + Buffer polyfill | ⭐ |
| `crypto.seed` | SEED 패널 | `crypto/seed.js` (순수 JS S-box, Buffer) | 그대로 이식 + Buffer polyfill | ⭐ |
| `crypto.mac` | MAC 패널 | hmac/desMac/desTdesMac/desFullMac/cmacAes | `@noble/hashes` (HMAC) + 자체 CMAC + des(위) | ⭐⭐⭐ |
| `crypto.ecc` | ECDSA/ECDH/EC-SDSA | Node `createECDH/sign/verify` + P-256 BigInt | `@noble/curves/p256` (ECDSA/ECDH) + 기존 BigInt EC-SDSA | ⭐⭐⭐ |
| `crypto.pqc` | ML-KEM/ML-DSA 패널 | `@noble/post-quantum` (이미 ESM!) | 그대로 import + Buffer 제거 | ⭐⭐ |

---

## 2. 기술 선택

- **번들러**: **Vite** (ESM 네이티브, 정적 빌드, GH Pages 호환, TS 무설정 지원)
- **언어**: **TypeScript** (strict mode). Vite가 `.ts`를 무빌드로 처리. 기존 `crypto/*.js`는 이식 시 타입 추가하며 재작성
- **암호 라이브러리**:
  - `@noble/ciphers` — AES, DES/3DES (Cure53 audited, 순수 JS, ESM)
  - `@noble/hashes` — SHA1/SHA256/SHA384/SHA512, HMAC, CMAC
  - `js-md5` — MD5 (WebCrypto/noble 양쪽 미지원)
  - `@noble/curves` — P-256 (secp256r1, ECDSA, ECDH)
  - `@noble/post-quantum` — ML-KEM, ML-DSA (기존과 동일 라이브러리)
  - `buffer` — ARIA/SEED/기존 padding 코드를 그대로 쓰기 위한 polyfill
- **호스팅 후보**: GitHub Pages / Cloudflare Pages / Netlify / Vercel (어느 쪽이든 정적)

---

## 3. 어댑터 계약 (`src/electronAPI-adapter.ts`)

`cipher-studio.html`의 HTML/UI 코드는 **거의 손대지 않는다**. 대신 `window.electronAPI`를 흉내내는 어댑터를 만들어 한 곳에서 라우팅한다:

```ts
type Hex = string;
type CryptoBridge = {
  des:     (op: string, ...args: unknown[]) => Promise<Hex>;
  aes:     (op: string, ...args: unknown[]) => Promise<Hex>;
  aria:    (op: string, ...args: unknown[]) => Promise<Hex>;
  seed:    (op: string, ...args: unknown[]) => Promise<Hex>;
  mac:     (op: string, ...args: unknown[]) => Promise<Hex>;
  hash:    (alg: string, data: Hex) => Promise<Hex>;
  padding: (op: string, data: Hex, bs: number) => Promise<Hex>;
  random:  (len: number) => Promise<Hex>;
  bitwise: (op: string, a: Hex, b: Hex) => Promise<Hex>;
  rsa:     (op: string, ...args: unknown[]) => Promise<Hex | { n: Hex; d: Hex }>;
  ecc:     (op: string, ...args: unknown[]) => Promise<unknown>;
  pqc:     (op: string, ...args: unknown[]) => Promise<unknown>;
};

declare global {
  interface Window {
    electronAPI: {
      loadSettings: () => Promise<Record<string, unknown>>;
      saveSettings: (s: Record<string, unknown>) => Promise<void>;
      minimize?: () => void;
      close?: () => void;
      crypto: CryptoBridge;
    };
  }
}
```

이 어댑터는 `<script type="module">` 첫 줄에서 로드되며, 기존 HTML 코드의 `window.electronAPI.crypto.xxx` 호출은 변경 불필요 (런타임 모양이 동일).

---

## 4. 디렉토리 구조 (목표)

```
cipher-studio-web/
├─ package.json
├─ tsconfig.json             ← strict: true, target ES2022, lib DOM+ES2022
├─ vite.config.ts
├─ index.html                ← cipher-studio.html을 이식 + <script src> 끝에 module 1줄 추가
├─ public/
│   └─ fonts/                ← cryptoIDE/fonts/ 통째로 복사
├─ src/
│   ├─ main.ts               ← 어댑터 wiring + DOMContentLoaded 부트
│   ├─ electronAPI-adapter.ts
│   ├─ settings-store.ts     ← localStorage 래퍼
│   ├─ types.ts              ← Hex 타입 alias, 공통 타입
│   └─ crypto/
│       ├─ hex-utils.ts      ← 원본 → TS, Uint8Array 기반으로 정리
│       ├─ bitwise.ts        ← 원본 → TS
│       ├─ padding.ts        ← 원본 → TS (Uint8Array)
│       ├─ random.ts         ← getRandomValues 기반 재작성
│       ├─ rsa.ts            ← 원본 → TS (BigInt only)
│       ├─ hash.ts           ← WebCrypto + js-md5
│       ├─ aes.ts            ← @noble/ciphers/aes 기반 재작성
│       ├─ des.ts            ← @noble/ciphers/legacy 기반 재작성
│       ├─ aria.ts           ← 원본 → TS (+ Buffer polyfill)
│       ├─ seed.ts           ← 원본 → TS (+ Buffer polyfill)
│       ├─ mac.ts            ← HMAC/CMAC/DES-MAC 조합
│       ├─ ecc.ts            ← @noble/curves 재작성 + EC-SDSA BigInt 유지
│       └─ pqc.ts            ← @noble/post-quantum 그대로 (Buffer→Uint8Array)
└─ README.md                 ← 빌드/배포 방법
```

**tsconfig 핵심 설정**:
- `"strict": true` — null/undefined 명시 강제
- `"noUncheckedIndexedAccess": true` — 배열 인덱싱 시 undefined 자동 추가 (암호 코드 안전성↑)
- `"target": "ES2022"`, `"module": "ESNext"` — BigInt/Uint8Array 네이티브
- `"lib": ["ES2022", "DOM"]`

---

## 5. 작업 분해 — 수직 슬라이스

각 Task는 **한 UI 패널이 끝까지(입력→연산→결과 표시→로그) 동작**하는 단위로 자른다.
의존성이 0인 패널부터, 외부 라이브러리가 필요한 패널 순으로 진행.

### Phase 0 — 부트스트랩 (UI만 살아 있는 빈 껍데기)

#### Task 0.1 — 신규 프로젝트 scaffold
- 산출물: `cipher-studio-web/` 생성, `npm create vite@latest . -- --template vanilla-ts`, `tsconfig.json`/`vite.config.ts`
- 의존성 설치: `@noble/ciphers @noble/hashes @noble/curves @noble/post-quantum js-md5 buffer`
- tsconfig에 strict + noUncheckedIndexedAccess 활성화
- 검증: `npm run dev` → localhost 띄움, 빈 Vite 페이지 OK / `npx tsc --noEmit` 통과

#### Task 0.2 — HTML/CSS/폰트 이식 + Throw 스텁
- `cryptoIDE/cipher-studio.html`을 `index.html`로 복사 (CDN 폰트 제외, `<link href="fonts/fonts.css">` 경로 유지)
- `cryptoIDE/fonts/` → `public/fonts/`
- `<script type="module" src="/src/main.ts">` 추가
- `src/electronAPI-adapter.ts`: 타입 정의 + 모든 메서드가 `throw new Error('not-implemented')`인 스텁
- `src/main.ts`: 어댑터를 `window.electronAPI`에 부착
- 인라인 `<script>`의 `'use strict'`부터 닫는 `</script>`까지 그대로 유지 (변경 X)
- 검증:
  - 사이드바 탭 클릭 → 13개 패널 토글 OK
  - byte counter 증가 OK
  - 임의 패널 실행 → "not-implemented" 에러 표시 (UI 흐름은 정상)
  - `npx tsc --noEmit` 통과

🛑 **Checkpoint A — 사용자 확인**: 폰트, 다크/라이트 테마 토글, 레이아웃이 Electron판과 시각적으로 동일한지 확인.

---

### Phase 1 — 의존성 0짜리 패널 (Padding · XOR · Random · RSA)

#### Task 1.1 — hex-utils + bitwise → XOR 패널 동작
- `src/crypto/hex-utils.js` 이식 (브라우저 `Buffer` polyfill로 그대로 동작)
- `src/crypto/bitwise.js` 이식
- 어댑터에서 `crypto.bitwise` 라우팅 활성
- 검증: XOR 패널 — 두 hex 입력 XOR 결과가 Electron판과 일치 (테스트 벡터: `AA BB ^ 12 34 = B8 8F`)

#### Task 1.2 — padding 모듈 → Padding 패널 동작
- `src/crypto/padding.js` 이식
- 검증: Padding 패널 — ISO9797 M1/M2, PKCS#5/7, DES/AES pad 모두 Electron판과 동일 출력

#### Task 1.3 — random 모듈 (브라우저 재작성) → Random 패널 동작
- `src/crypto/random.js`: `crypto.getRandomValues(new Uint8Array(len))` → hex
- 검증: Random 패널 — 32 B 출력 길이/16진수 검증, 두 번 호출 결과가 서로 다름

#### Task 1.4 — rsa 모듈 → RSA 패널 동작
- `src/crypto/rsa.js` 이식 (BigInt only — Buffer 미사용)
- 검증: RSA 패널 4가지 모드
  - Encrypt/Decrypt: 알려진 N/E/D로 라운드트립 (M → C → M)
  - CRT Decrypt: p/q/dP/dQ/qInv 입력 → Standard Decrypt 결과와 일치
  - CRT→Standard: p/q/e 입력 → N, D 출력이 RSA Encrypt에 그대로 동작

🛑 **Checkpoint B**: 위 4개 패널이 모두 Electron판과 비트 단위 동일 결과를 내는지 사용자 확인.

---

### Phase 2 — Hash & AES (WebCrypto)

#### Task 2.1 — hash 모듈 → Hash 패널 동작
- `src/crypto/hash.js`: SHA1/SHA256은 `crypto.subtle.digest`, MD5는 `js-md5`
- 검증: Hash 패널
  - SHA-256("") = `e3b0c442...`
  - SHA-1("616263") = `a9993e36...`
  - MD5("") = `d41d8cd9...`

#### Task 2.2 — aes 모듈 → AES 패널 동작
- `src/crypto/aes.js`: `@noble/ciphers/aes`
  - ECB: noble의 `ecb`
  - CBC: noble의 `cbc` (autoPadding 비활성화 — 패딩은 호출부에서 처리)
  - CTR: noble의 `ctr`
- 검증: AES 패널
  - NIST 테스트 벡터 (AES-128 ECB): key `2b7e1516...`, pt `6bc1bee2...` → ct `3ad77bb4...`
  - CBC 128/192/256 라운드트립
  - CTR 라운드트립

🛑 **Checkpoint C**: Hash 패널 3 알고리즘 + AES 패널 ECB/CBC/CTR × Enc/Dec 모두 일치.

---

### Phase 3 — DES/3DES

#### Task 3.1 — des 모듈 → DES 패널 동작
- `src/crypto/des.js`: `@noble/ciphers/legacy`의 `des`, `tdes_ede` 사용
  - 8B 키 → DES, 16B → 3DES 2-key (EDE), 24B → 3DES 3-key
- 검증: DES 패널
  - DES ECB 테스트 벡터 (FIPS PUB 81)
  - 3DES CBC 라운드트립
  - 8/16/24 B 키 모두 동작

🛑 **Checkpoint D**: DES 패널 ECB/CBC × 8/16/24 B 키 모두 일치.

---

### Phase 4 — MAC

#### Task 4.1 — mac 모듈 → MAC 패널 동작
- `src/crypto/mac.js`:
  - `hmac`: `@noble/hashes/hmac`
  - `desMac` (Retail MAC, SCP02): 기존 알고리즘 그대로 + Phase 3의 des
  - `desTdesMac`, `desFullMac`: 동일하게 des 조합
  - `cmacAes`: `@noble/hashes/_cmac` 또는 직접 (NIST SP 800-38B)
- 검증: MAC 패널
  - HMAC-SHA256(key="key", data="The quick brown fox...") = `f7bc83f4...`
  - AES-CMAC RFC 4493 테스트 벡터 (key `2b7e1516...`, M=빈/16B/40B/64B)
  - DES Retail MAC: 기존 Electron판 결과와 비트 동일

🛑 **Checkpoint E**: MAC 5종 모두 일치.

---

### Phase 5 — ARIA / SEED (Buffer polyfill)

#### Task 5.1 — Buffer 글로벌 polyfill + aria/seed 이식
- `vite.config.js`에 `buffer` alias 추가, `src/main.js` 최상단에 `import { Buffer } from 'buffer'; window.Buffer = Buffer;`
- `src/crypto/aria.js`, `src/crypto/seed.js` 원본 그대로 복사
- 검증:
  - ARIA 패널: ECB/CBC × Enc/Dec, key 16/24/32 B (RFC 5794 테스트 벡터)
  - SEED 패널: ECB/CBC × Enc/Dec + CBC-MAC (TTAS.KO-12.0004 테스트 벡터)

🛑 **Checkpoint F**: ARIA + SEED 모두 일치.

---

### Phase 6 — ECC

#### Task 6.1 — ecc 모듈 → ECDSA/ECDH/EC-SDSA 패널 동작
- `src/crypto/ecc.js`:
  - `ecdhComputeSecret`: `@noble/curves/p256` `getSharedSecret`
  - `ecdsaSign/Verify`: `p256.sign(msgHash, priv)`, `p256.verify(sig, msgHash, pub)`. 메시지는 SHA-256 후 입력. r/s/DER 모두 추출.
  - `ecSdsaSign/Verify`: 기존 BigInt 코드 유지, `crypto.randomBytes` → `getRandomValues`, `crypto.createHash` → `@noble/hashes/sha256`
  - `derivePublicKey`: `p256.getPublicKey(priv, false)` (uncompressed)
- 검증:
  - ECDSA Sign → Verify 라운드트립
  - ECDH: A의 priv + B의 pub == B의 priv + A의 pub (양쪽 어댑터 일치)
  - EC-SDSA Sign → Verify 라운드트립 + Electron판 서명을 브라우저판이 검증 OK (상호운용)

🛑 **Checkpoint G**: ECC 3종 라운드트립 + Electron판과 상호 검증.

---

### Phase 7 — PQC

#### Task 7.1 — pqc 모듈 → ML-KEM / ML-DSA 패널 동작
- `src/crypto/pqc.js`: 기존 코드 거의 그대로, `Buffer` → `Uint8Array` + hex 유틸로 교체
- `@noble/post-quantum`는 이미 ESM/브라우저 호환 → 추가 작업 거의 없음
- 검증:
  - ML-KEM-768: keygen → encap(ek) → decap(dk, ct) ⇒ 두 sharedSecret 일치
  - ML-DSA-65: keygen → sign(sk, msg) → verify(pk, msg, sig) == true; sig 1바이트 손상 → verify false

🛑 **Checkpoint H**: PQC 두 알고리즘 라운드트립.

---

### Phase 8 — 설정 영속화 & 정리

#### Task 8.1 — Settings + 잔여 정리
- `src/settings-store.js`: localStorage 래퍼
- 어댑터에서 `loadSettings/saveSettings` 연결
- `btn-min`/`btn-close` 요소를 CSS로 숨김 또는 DOM 제거 (어댑터의 optional chain은 이미 안전)
- grep 검증: `electronAPI.` 호출이 전부 어댑터를 거치는지 확인 (어댑터 내부 외부에서 `window.electronAPI`를 직접 set하는 곳 없음)
- 검증: 테마 토글 → 새로고침 → 직전 테마 유지

🛑 **Checkpoint I**: 전체 통합 — 13개 패널 1회씩 손으로 돌려보기.

---

### Phase 9 — 빌드 & 배포

#### Task 9.1 — 정적 빌드 + 호스팅
- `npm run build` → `dist/` 검증
- `npx vite preview` 로컬에서 `dist/` 직접 서빙 → 모든 패널 동작 재확인
- README.md 작성:
  - 개발: `npm install && npm run dev`
  - 빌드: `npm run build`
  - 배포 옵션 3가지 (GitHub Pages / Cloudflare Pages / Vercel) 각 5줄 가이드
- (옵션) GitHub Pages용 `vite.config.js`의 `base` 설정 — 사용자가 호스팅 선택 후 추가

🛑 **Final Checkpoint**: 배포 URL에서 외부 브라우저로 13개 패널 전부 한 번씩 돌려 OK.

---

## 6. 위험 요소 & 대응

| 위험 | 영향 | 대응 |
|---|---|---|
| WebCrypto가 AES-ECB 미지원 | AES 패널 ECB 모드 깨짐 | noble/ciphers의 `ecb` 사용 (Phase 2.2 이미 반영) |
| DES는 WebCrypto 미지원 | DES 패널 전체 + DES MAC | noble/ciphers/legacy (Phase 3 핵심) |
| Buffer.alloc 등 Node API가 ARIA/SEED에 산재 | 이식 시 미세 버그 가능 | `buffer` npm polyfill + 글로벌 주입 (Phase 5.1) |
| `@noble/curves`의 ECDSA가 raw 키 형식 (Node와 DER 처리 다름) | r/s 추출/조합 미스 | 기존 DER 코덱(`_encodeEcdsaDer/_decodeEcdsaDer`) 유지, noble은 raw r,s만 받게 어댑팅 |
| MD5는 WebCrypto/noble 미지원 | Hash 패널 MD5 | `js-md5` 1개 추가 (~5KB) |
| 키/평문이 브라우저 메모리에만 있어야 (네트워크 송신 금지) | 보안 회귀 위험 | 어떤 fetch/XHR도 추가하지 않음 — 정적 호스팅 + 모든 연산 클라이언트. README에 명시 |
| EC-SDSA가 BigInt + `crypto.randomBytes`에 의존 | 이식 시 깨짐 | `getRandomValues`로 교체 (Phase 6.1) |

---

## 7. 비목표 (이번 작업에 포함하지 않는 것)

- 단위 테스트 자동화 — 검증은 각 Phase의 수동 테스트 벡터로 대체. (요청 시 Phase 10으로 추가 가능)
- PWA / 오프라인 캐싱
- 다국어
- Cipher Studio UI 자체의 리디자인/리팩토링 — 원본 HTML/CSS 유지

---

## 8. 진행 방식

- 각 Phase 끝 🛑 Checkpoint에서 사용자가 동작 확인 후 다음 Phase 진행
- 모든 코드 변경은 신규 `cipher-studio-web/` 안에서만 발생. **`ScriptIDE/cryptoIDE/`는 손대지 않는다** (Electron 앱 정상 동작 유지)
- 커밋은 사용자가 직접 관리 (자동 커밋 금지 — 메모리 확인 완료)
