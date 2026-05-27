# Cipher Studio - Web Edition

Cipher Studio의 정적 웹 마이그레이션 버전입니다. Vite와 TypeScript를 기반으로 하며, 모든 암호화 연산은 클라이언트 측 브라우저에서 실행됩니다.

## 주요 특징

- **순수 정적 웹**: 서버 사이드 연산 없이 브라우저 내에서 모든 암호화 수행.
- **Modern Crypto**: `@noble` 라이브러리 및 WebCrypto API 사용.
- **다양한 알고리즘 지원**: AES, DES/3DES, ARIA, SEED, RSA, ECC, PQC (ML-KEM, ML-DSA), Hash, MAC 등.
- **Zero-Dependency UI**: 기존 Electron 버전의 HTML/CSS/JS 로직을 그대로 유지하면서 어댑터를 통해 브라우저 환경에 맞게 라우팅.

## 개발 및 빌드

### 의존성 설치
```bash
npm install
```

### 개발 서버 실행
```bash
npm run dev
```

### 프로덕션 빌드
```bash
npm run build
```
빌드 결과물은 `dist/` 폴더에 생성됩니다.

### 테스트 실행
```bash
npm test
```

## 배포 가이드

`dist/` 폴더의 내용을 정적 호스팅 서비스에 업로드하여 배포할 수 있습니다.

### 1. GitHub Pages
1. `vite.config.ts`에서 `base` 경로를 설정합니다 (예: `base: '/repo-name/'`).
2. GitHub Actions를 사용하여 자동으로 배포하거나, 빌드 후 `gh-pages` 브랜치에 푸시합니다.

### 2. Cloudflare Pages / Vercel
1. 프로젝트를 연결합니다.
2. 빌드 명령을 `npm run build`로, 결과 디렉토리를 `dist`로 설정합니다.
3. 자동으로 배포됩니다.

### 3. 직접 호스팅 (Nginx, S3 등)
`dist/` 폴더 내의 모든 파일을 서버의 웹 루트에 업로드합니다.
