# 우리집 가계부 (PWA)

뱅크샐러드 엑셀을 올리면 Today / Month / Year / Asset 대시보드를 보여주는 부부용 가계부.

- 금융 데이터는 서버에 올라가지 않음. 각 기기의 IndexedDB에 AES-GCM(256)으로 암호화 저장.
- 잠금: 6자리 비밀번호(PBKDF2-SHA256 60만 회) + Face ID/Touch ID(WebAuthn PRF, iOS 18·macOS 15 이상 Safari).
- 5회 이상 틀리면 대기시간이 점점 늘어남. 앱을 1분 이상 벗어나면 자동 잠금.
- 엑셀 파싱은 동봉된 SheetJS(xlsx.mini.min.js 0.18.5)로 기기 안에서 처리. 외부 CDN·분석도구 없음(CSP로 차단).

## 아이폰에 설치
Safari로 주소 열기 → 공유 버튼 → "홈 화면에 추가".
