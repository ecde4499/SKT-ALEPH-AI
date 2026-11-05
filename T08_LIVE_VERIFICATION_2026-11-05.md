# T08 실제 HTTPS WebAuthn 검증 기록 — 2026-11-05

> **범위 구분:** 아래 결과는 실제 Render 프로덕션 URL과 실제 T08 PostgreSQL에 **Chrome 가상 WebAuthn 인증기**로 요청을 보내 얻은 결과다. 실제 휴대폰/Windows Hello/보안 키에 패스키를 등록한 사실은 증명하지 않는다.

## 대상 / 증거

- 실제 공개 페이지: https://t08-skt-aleph-passkey-ecde4499.onrender.com
- GitHub T08 전용 소스: https://github.com/ecde4499/SKT-ALEPH-AI/tree/assignment-8
- 실제 브라우저 자동 검증 실행: https://github.com/ecde4499/SKT-ALEPH-AI/actions/runs/41954420906
- 화면 캡처 + JSON 증거(총 5장, GitHub Actions 보존 기간 14일): https://github.com/ecde4499/SKT-ALEPH-AI/actions/runs/41954420906/artifacts/13382103640
- 브라우저 시험 코드: `tests/t08-live-browser.cjs`. 실제 연결 DB 비밀번호를 조회하거나 출력하지 않음.
- 시연 계정: **완전히 새로운 가상 별명 계정 A와 B를 하나씩 생성**하고, 각각 **만들어 넣은 메모 3건** 보유. 실제 개인정보·토큰·패스키 개인키·원본 challenge·계정 별명은 증거에서 생략.
- **T01 원본 `main`과 T06/T07 서비스·DB는 변경하지 않음.** 테스트 계정과 가상 메모는 T08 DB에 남는다.

## 실제 HTTPS 요청·응답 확인

| 확인 | 성공/허용 요청 및 응답 | 거절 요청 및 응답 | 검증 |
|---|---|---|---|
| 공개 / 비공개 경계 | `GET /` → **200**, `GET /api/t08/health` → **200** | 비로그인 `GET /api/t08/notes` 및 `GET /private` → **401** | PASS |
| 최초 패스키 등록 | WebAuthn 등록 검증 `POST /api/t08/register/verify` → **201**; 로그인 세션 후 개인 메모 3건 조회 **200** | 등록 옵션만 받고 종료한 가상 별명의 로그인 옵션 조회 → **404**(미등록) | PASS |
| 공개키만 보관 | 인증된 `GET /api/t08/passkeys/public-key` → **200**, 공개 COSE 키 hex 형태와 설명 확인 | 개인키 저장·비밀번호 필드는 DB 스키마에 없고 클라이언트는 WebAuthn 자격 증명 응답만 전송 | PASS(소스/서버 API 근거) |
| 일회용 질문 | 서로 다른 등록 옵션의 `challenge`가 다름을 assert / 서로 다른 로그인 옵션도 상이함을 assert | 이미 사용된 `transaction_id` + 서명 재전송 `POST /api/t08/login/verify` → **401** | PASS |
| 패스키 2개 관리 | A 계정에 가상 인증기로 발급한 서로 다른 패스키 2개가 이름·등록일과 함께 표시 | 마지막 남은 패스키까지 삭제 시도 → **409** | PASS |
| 계정 격리 | A와 B가 각자의 비공개 메모 3건을 `GET /api/t08/notes` → **200** | A→B 타인 메모 ID 직접 조회 → **404**, B→A → **404** | PASS |
| 계정 바꿔치기 | A·B 각자 자기 메모 건수 **3건 유지** | `?user_id=<상대>` 임의 전달해도 **자기 자료만** 반환 | PASS |
| 다른 계정의 서명 | B 개인키로 B가 정상 서명 생성 | 그 서명을 A 로그인 transaction에 제출 `POST /api/t08/login/verify` → **403** | PASS |
| 삭제·로그아웃·재로그인 | 첫 번째 패스키 제거 후 남은 패스키로 로그인 성공 → **200** | 제거된 패스키 ID 인증 시도 → **403**, 로그아웃 후 `GET /api/t08/notes` → **401** | PASS |

**결과: 실제 HTTPS 가상 인증기 E2E 9/9 PASS.** 위 9개 그룹별 PASS는 [CI의 실제 실행 로그](https://github.com/ecde4499/SKT-ALEPH-AI/actions/runs/41954420906)와 첨부 `verification.json`에 대응한다.

### 민감값을 가린 요청 구조 예시

> 아래 JSON은 **실제 원문 트래픽 덤프가 아닌**, 실제 앱의 WebAuthn 요청 구조를 설명하기 위한 비식별화 예시다.

```json
{
  "transaction_id": "[가림]",
  "credential": {
    "id": "[가림]",
    "type": "public-key",
    "response": {
      "clientDataJSON": "[가림]",
      "attestationObject": "[가림]"
    }
  }
}
```

서버로 패스키의 **개인키/비밀번호 원문이 전송되지 않는다.** 등록에는 기기가 만든 attestation·공개키 자료가 전달되고, 로그인에는 서버의 매번 새 challenge에 서명한 WebAuthn authentication 자료를 전달한다. `public_key`는 `server/schema.sql`의 `t08_passkeys.public_key BYTEA`에 저장되고 `server/t08-app.cjs`의 `verifyAuthenticationResponse()`가 인증에 사용한다. 서버 내부 세션은 SHA-256 해시로 DB에 저장한다.

## 실제 브라우저 화면 캡처 5장

- `01-live-public-locked.png`: 원래 소개 내용이 공개이고 비공개 구역은 잠긴 상태
- `02-live-account-a.png`: A 계정의 패스키 인증 후 만들어 넣은 비공개 메모 3건
- `03-live-two-passkeys.png`: A 계정에 두 개의 가상 패스키와 이름/등록 날짜
- `04-live-account-b.png`: B 계정 고유의 가상 메모 3건
- `05-live-remaining-key-relogin.png`: A 패스키 하나 삭제 및 로그아웃 뒤 남은 키로 로그인

모든 캡처는 배포된 실제 사이트의 Chrome 화면이며, 오른쪽 하단에 **“테스트용 가상 패스키 · 실제 기기 인증 아님”**이라는 표시를 넣었다. 이 표시는 캡처할 때만 추가한 주석이며 사이트 코드에 배포한 UI는 아니다.

## 아직 반드시 직접 확인할 것

1. 본인 컴퓨터나 휴대폰에서 실제 플랫폼 패스키 1개를 생성하고 **저장 위치**(Windows Hello·Google 비밀번호 관리자·기기·보안 키 중 실제로 사용한 방식)를 기록.
2. **다른 기기 또는 별도 보안 키**로 두 번째 패스키를 등록하고, 하나를 삭제한 후 남은 것으로 실제 재로그인.
3. 삭제된 실제 패스키가 더 이상 로그인할 수 없는지, 비로그인 접근이 차단되는지 실제 기기로 확인.
4. 제출 최종 설명서에서 **본인이 직접 판단한 일과 AI 제안을 거절한 사례**가 실제로 했던 판단인지 확인.
5. **모든 기기 분실 시 복구 미구현**을 제한사항으로 적는다. 마지막 패스키의 정상 삭제는 409로 제한한다.

### 한계와 데이터 분리

- 가상 인증기는 프로토콜/서버 검증용이며, 실제 장치의 생체인증·동기화·분실 대응을 대신하지 못한다.
- 시연용 계정 2개와 메모 6건은 **T08 DB**에만 남아 있고, 기존 과제 데이터는 건드리지 않았다.
- 무료 Render DB는 2026-12-05 만료 예정이며 시험 이력을 영구 보관하려면 별도 백업/이전이 필요하다.
- CI에 실비밀번호·토큰·개인키를 포함한 로그는 남기지 않았다.
