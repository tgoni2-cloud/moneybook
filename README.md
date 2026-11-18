# 우리집 가계부 (PWA)

뱅크샐러드 엑셀을 올리면 Today / Month / Year / Asset 대시보드를 보여주는 부부용 가계부.

- 금융 데이터는 서버에 올라가지 않음. 각 기기의 IndexedDB에 AES-GCM(256)으로 암호화 저장.
- 잠금: 6자리 비밀번호(PBKDF2-SHA256 60만 회) + Face ID/Touch ID(WebAuthn PRF, iOS 18·macOS 15 이상 Safari).
- 5회 이상 틀리면 대기시간이 점점 늘어남. 앱을 1분 이상 벗어나면 자동 잠금.
- 엑셀 파싱은 동봉된 SheetJS(xlsx.mini.min.js 0.18.5)로 기기 안에서 처리. 외부 CDN·분석도구 없음(CSP로 차단).

## 아이폰에 설치
Safari로 주소 열기 → 공유 버튼 → "홈 화면에 추가".

## 불러오기
- 수동: Setting에서 뱅크샐러드 .zip(비밀번호) 또는 .xlsx 선택. 압축 비밀번호는 매번 입력하며 저장하지 않음.
- Gmail: Setting → "Gmail에서 최신 파일 불러오기". Google OAuth(gmail.readonly) 리디렉트 방식, 토큰은 메모리에만 두고 끝나면 즉시 revoke.
  Google Cloud에서 "웹 애플리케이션" OAuth 클라이언트를 만들고 승인된 리디렉션 URI에 `https://tgoni2-cloud.github.io/moneybook/` 를 등록한 뒤, 클라이언트 ID를 Setting에 입력.
