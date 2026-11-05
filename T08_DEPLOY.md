# T08 Render 무료 배포 연결 — 마지막 설정

> **상태(2026-11-05):** 소스 `assignment-8` 브랜치, CI PASS, 무료 Render PostgreSQL 생성 완료. Render Web Service도 생성했으나 `DATABASE_URL` 비밀값을 아직 입력하지 않아 시작을 **의도적으로 거부**하고 있다. 로그인/실서비스 WebAuthn 시험까지 완료했다고 주장하지 않는다.

## 만들어진 과제8 자원

| 항목 | 정보 |
|---|---|
| 원본 과제1 저장소 | https://github.com/ecde4499/SKT-ALEPH-AI/tree/main (변경 없음) |
| 과제8 소스 | https://github.com/ecde4499/SKT-ALEPH-AI/tree/assignment-8 |
| Render T08 웹 서비스 | https://dashboard.render.com/web/srv-dblu0po8v5cc73cu3os0 |
| 공개 서비스 주소(현재 설정 미완료) | https://t08-skt-aleph-passkey-ecde4499.onrender.com |
| Render T08 PostgreSQL | https://dashboard.render.com/d/dpg-dbltv58ae00c73fnqik0-a |
| 데이터베이스 이름 | `t08_passkey_aleph` |
| 리전/과금 | Singapore / Free, DB 생성 후 약 30일 만료 |
| 무료 DB 만료 예정 | 2026-12-05 (Render 제공 만료 타임스탬프: 2026-12-05T01:44:53Z) |
| GitHub 자동검증 | https://github.com/ecde4499/SKT-ALEPH-AI/actions/runs/41950370489 |

기존 T01 GitHub Pages와 T06·T07 Render/Supabase 서비스는 변경하지 않는다.

## 필요한 비밀 환경변수 설정 1회

Render는 생성된 PostgreSQL 내부 연결 문자열의 비밀번호를 이 자동화 도구에 노출하지 않는다. **사용자가 관리 페이지에서 직접 복사하여 Render 환경변수에 넣어야 한다.** 채팅/GitHub/스크린샷에 붙여 넣지 않는다.

1. [Render PostgreSQL 관리 페이지](https://dashboard.render.com/d/dpg-dbltv58ae00c73fnqik0-a) → **Info/Connect** → **Internal Database URL** 전체를 **복사**한다. 복사한 URL의 경로가 `/t08_passkey_aleph`로 끝나는지 확인한다.
2. [과제8 Render Web Service](https://dashboard.render.com/web/srv-dblu0po8v5cc73cu3os0) → **Environment** → **Add Environment Variable**.
3. KEY = `DATABASE_URL`, VALUE = **위에서 복사한 Internal Database URL 전체(비밀번호 포함)**. 저장한 뒤 **Save, rebuild and deploy**로 과제8 서비스만 배포한다.

**T08 환경변수 중 이미 설정된 값:** `NODE_ENV=production`, `ORIGIN=https://t08-skt-aleph-passkey-ecde4499.onrender.com`, `RP_ID=t08-skt-aleph-passkey-ecde4499.onrender.com`, `DATABASE_SSL=false`, `T08_DB_ACK=I_VERIFIED_T08_ONLY`. 수정하지 않아도 된다.

서버는 시작 전에 별도 T08 DB임을 검증하며 DB명이 `t08_...`가 아니면 실행을 거부한다. 시작에 성공하면 **과제8 DB에만** `server/schema.sql`의 테이블 5개를 만든다.

## 배포 후 실제 검증

- [ ] 비로그인 `/`에서 과제1 공개 소개 및 잠긴 영역 표시
- [ ] 비로그인 `/api/t08/notes`와 `/private`가 HTTP 401
- [ ] T08 공개 URL에서 새 가상 계정 등록, 실제 휴대폰/Windows Hello로 패스키 생성
- [ ] 패스키 저장 위치(구글 비밀번호 관리자·Windows Hello·기기·보안 키)를 제출문에 실제 사용한 것으로 기록
- [ ] 두 번째 **실제** 패스키 등록 후 한 개 삭제, 남은 키로 로그인
- [ ] 서로 다른 두 계정의 비공개 항목 상호 접근 403/404, 질문 재사용 401 확인
- [ ] 등록·로그인·로그아웃·비공개 조회의 실제 HTTP 기록과 화면 캡처 생성

**주의:** 가상 인증기 CI는 코드의 검증 결과이며, 사용자의 물리적 기기에서 패스키가 저장되었다는 증거가 아니다.

## 그 외 참고

- 공개 웹 주소가 열리지 않을 때: DB 연결 설정 후 최신 수동 배포 상태가 `live`인지 확인한다.
- 패스키 창이 뜨지 않을 때: HTTPS 주소와 RP_ID, 브라우저 WebAuthn 및 기기 지원 확인.
- 패스키를 모두 잃었을 때: 패스키 하나도 없는 상태로 만들지 않도록 **마지막 키 삭제를 HTTP 409로 차단**한다. 물리적 분실 시 자동 계정 복구는 구현되지 않았다.
- Render 무료 DB는 30일 후 만료되며 백업도 제공하지 않는다. 계속 사용할 서비스라면 별도 지속성 있는 DB로 이전해야 한다.
