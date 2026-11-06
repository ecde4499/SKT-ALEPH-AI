# 로그 한눈에 — 보안 이상징후 분석기

**한 줄 소개:** 보안 로그를 분석해 이상징후의 발생 이유와 위험도를 쉽게 확인하는 교육용 웹앱.

보안관제 입문자가 예시 로그 또는 본인 CSV를 분석해 (1) 반복 로그인 실패 (2) 심야 로그인 (3) 트래픽 급증 결과를 확인하고 CSV 리포트로 내려받을 수 있습니다.

## 실행 방법 (Python 3.10+)

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

브라우저에서 `http://127.0.0.1:5000` 열기. 공개 배포에는 `gunicorn --chdir star-log-analyzer app:app --bind 0.0.0.0:$PORT`를 사용합니다.

## 첫 실행 3단계

1. `예시 로그 사용` → `이상징후 분석 실행` 클릭: 입력 11건, 탐지 사건 3건(높음 1·보통 2) 확인
2. `내 CSV 분석` → UTF-8 CSV 파일 선택 → 분석: 표에서 발생 시간, 규칙, 위험도, 근거 확인
3. `리포트 CSV 다운로드` 클릭: 표의 탐지 3건과 같은 내용이 다운로드되는지 확인

예시 CSV 파일은 `/sample.csv`에서 다운로드할 수 있습니다. 시간대 없는 ISO 날짜는 KST로 해석됩니다.

## CSV 규격

`timestamp,event_type,user,src_ip,bytes`

- `timestamp`: ISO 8601 (예: `2026-11-06T02:01:00+09:00`)
- `event_type`: `LOGIN_FAILURE`, `LOGIN_SUCCESS`, `TRAFFIC`
- `user`: 식별용 계정 문자열(64자 이하, 실명 사용하지 않음)
- `src_ip`: IPv4/IPv6
- `bytes`: TRAFFIC일 때 반드시 0 이상의 정수, 다른 이벤트는 공란 가능
- UTF-8/UTF-8-BOM CSV, 최대 256KB, 최대 2,000행

## 탐지 기준

| 코드 | 정책 | 위험도 |
| --- | --- | --- |
| `BRUTE_FORCE` | 동일 계정/IP의 5분 내 실패 5회 이상 | 높음 |
| `OFFHOUR_LOGIN` | 00:00~05:59 KST 성공 로그인 | 보통 |
| `TRAFFIC_SPIKE` | 5분 트래픽 바이트 합계 > 직전 데이터가 있는 3개 5분 구간 평균 × 2. 평균 0일 때 탐지 유보 | 보통 |

실제 공격 확정 또는 차단을 수행하지 않으며, 외부 SIEM·상용 API에 연결되지 않습니다.

## 테스트

```bash
python -m unittest discover -s tests -v
```

원하는 경우 `curl -X POST -F sample=true http://127.0.0.1:5000/api/analyze`로 API를 확인할 수 있습니다.

## 개인정보·보안

- 샘플에는 가상 계정과 문서용 IP 주소(`192.0.2.x`, `198.51.100.x`, `203.0.113.x`)만 있습니다.
- 서버는 CSV를 메모리에서 분석하고 파일 또는 DB로 보관하지 않습니다.
- 업로드 파일은 서버에 전송되므로 민감한 운영 로그는 사용하지 마세요.
- 브라우저는 텍스트를 `textContent`로 렌더링하여 사용자 값이 HTML로 실행되지 않도록 합니다.
- CSV 다운로드는 수식 주입 문자열을 이스케이프합니다.
- 로그인·외부 API·비밀키가 필요 없습니다.

## 프로젝트 범위

`plan.md`에 정의된 기본 탐지 기능을 구현합니다. 실시간 수집, 차단, 자동 SOAR 조치, 고급 SIEM 연동은 포함하지 않습니다.

## 폴더 구조

```text
app.py
 detectors.py
 templates/index.html
 static/style.css / static/app.js
 samples/sample_logs.csv
 tests/test_detectors.py / tests/test_app.py
 plan.md / README.md
```

## 중간 점검 2차 개선

- **새 입력 선택 시 결과 초기화**: 예시/CSV 모드 전환 또는 업로드 파일 변경 시 직전 탐지 목록과 다운로드 버튼을 초기화하여 이전 결과를 현재 파일의 결과로 오인하지 않도록 개선했습니다.
- **오류 후 재시도**: 잘못된 CSV로 분석을 시도하면 서버 오류 안내를 보여주고 이전 리포트를 비활성화합니다. 정상 CSV를 다시 선택하면 분석할 수 있습니다.
- **실제 브라우저 E2E 자동화**: `tests/e2e_public.py`는 공개 Render URL에서 샘플 분석 → 리포트 CSV 파일 저장·표와 대조 → 샘플 다운로드·재업로드 → 날짜 오류 CSV → 재시도 → 모바일 분석·가로 넘침 여부를 Chrome으로 확인합니다. GitHub Actions `.github/workflows/logscope-second-check.yml` 실행 근거를 별도 보관합니다.

실제 민감 로그 업로드 없이 예시 데이터만으로 검증합니다. GitHub Actions 환경에서는 Chromium이 공개 URL에 접속하며, 로컬 실행에서는 `pip install playwright` 및 Chrome/Chromium이 필요합니다.
