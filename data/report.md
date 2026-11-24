# API 보안 점검 리포트 — http://127.0.0.1:8888

> 생성 2026-11-23 18:02 UTC · 대상: 로컬 OWASP crAPI(의도적 취약 실습 앱) · 외부/운영 시스템 비대상

## 요약

| 지표 | 값 |
| --- | --- |
| 전체 엔드포인트 | 73 |
| Shadow (문서에 없는 노출) | 24 |
| 의도치 않은 무인증 | 12 |
| 개인정보 노출 (관측) | 13 |
| **M3 실제 확정 취약점** | **3** |

정적 분석·설정·트래픽으로 후보를 찾고(M1·M2), 로컬 대상에 한해 실제 요청으로 확정했다(M3). 모든 공격성 요청은 가드레일(스코프·행위·레이트 제한)을 통과했고 전 시도가 감사 로그에 남는다.

## 확정 취약점

### 1. GET `/identity/api/v2/vehicle/{carId}/location` — BOLA (객체 소유권 미검증)

- **코드 근거**: `sources/crAPI/services/identity/src/main/java/com/crapi/controller/VehicleController.java:121` · `getLocationBOLA`
- **인증(코드)**: anyRequest().authenticated()
- **분류/위험도**: active / high

**재현 (차분 테스트)**

| 주체 | 응답 | 의미 |
| --- | --- | --- |
| 소유자 | ✅ 200 | 정상 기준선 |
| 다른 사용자 | ✅ 200 | 타인 객체 접근됨 |
| 비로그인 | 🔒 401 | 차단 |

**유출된 소유자 식별값** (마스킹): `latitude=37.***69`, `longitude=-94***28`, `fullName=u***`, `email=use***al`

**조치방안**

- 핸들러에서 객체를 조회한 뒤 `객체.owner == 현재사용자`를 명시적으로 검사하거나,
- `currentUser.resources().findById(id)`처럼 소유자 범위 쿼리로 조회해 구조적으로 차단.
- 중앙 정책 엔진(OPA/Cedar) 사용 시 객체 단위(resource-level) 규칙을 추가.
- 식별자를 UUID로 바꾸는 것만으로는 해결되지 않음 — 인가 검사가 본질.

### 2. GET `/workshop/api/mechanic/service_request/{service_request_id}` — 인증 누락

- **코드 근거**: `sources/crAPI/services/workshop/crapi/mechanic/views.py:347` · `ServiceRequestView.get`
- **인증(코드)**: 인증 데코레이터 없음
- **분류/위험도**: shadow / none

**재현 (차분 테스트)**

| 주체 | 응답 | 의미 |
| --- | --- | --- |
| 소유자 | ✅ 200 | 정상 기준선 |
| 다른 사용자 | ✅ 200 | 타인 객체 접근됨 |
| 비로그인 | ✅ 200 | 무인증 접근됨 |

**유출된 소유자 식별값** (마스킹): `email=jho***om`, `vin=8VA***11`, `number=987***06`

**조치방안**

- 기본 거부(deny by default): 라우트별 인증을 opt-in이 아니라 기본값으로.
- 누락된 핸들러에 인증 미들웨어/데코레이터(`@jwt_auth_required` 등) 추가.
- 게이트웨이·서비스 양쪽에서 인증을 강제(내부 직접 접근 경로 차단).

### 3. GET `/workshop/api/shop/orders/{order_id}` — 인증 누락

- **코드 근거**: `sources/crAPI/services/workshop/crapi/shop/views.py:109` · `OrderControlView.get`
- **인증(코드)**: 인증 데코레이터 없음
- **분류/위험도**: active / critical

**재현 (차분 테스트)**

| 주체 | 응답 | 의미 |
| --- | --- | --- |
| 소유자 | ✅ 200 | 정상 기준선 |
| 다른 사용자 | ✅ 200 | 타인 객체 접근됨 |
| 비로그인 | ✅ 200 | 무인증 접근됨 |

**유출된 소유자 식별값** (마스킹): `email=use***al`, `number=010***01`

**조치방안**

- 기본 거부(deny by default): 라우트별 인증을 opt-in이 아니라 기본값으로.
- 누락된 핸들러에 인증 미들웨어/데코레이터(`@jwt_auth_required` 등) 추가.
- 게이트웨이·서비스 양쪽에서 인증을 강제(내부 직접 접근 경로 차단).

## 서비스별 현황

| 서비스 | 엔드포인트 | 무인증 | BOLA후보 | PII | 확정 | 최고위험 |
| --- | --- | --- | --- | --- | --- | --- |
| workshop | 28 | 7 | 8 | 5 | 2 | critical |
| identity | 32 | 2 | 5 | 4 | 1 | critical |
| community | 9 | 0 | 2 | 4 | 0 | high |
| chatbot | 1 | 1 | 0 | 0 | 0 | none |
| gateway | 2 | 1 | 0 | 0 | 0 | none |
| mailhog | 1 | 1 | 0 | 0 | 0 | none |

## 서비스 간 신뢰 관계 주의점

- `community` → `identity` (토큰 검증 (POST /identity/api/auth/verify)): **TLS 검증 비활성화** — `InsecureSkipVerify: true` 제거, 내부 CA로 인증서 검증. (근거: `community/api/auth/token.go:72`)

## 가드레일 동작 (M3)

- 스코프: 허용 호스트 ['127.0.0.1', 'localhost'] 밖 요청 차단
- 행위: 허용 메서드 ['GET'] 외 차단 (파괴적 행위 기본 차단)
- 레이트: 초당 3.0건 상한
- 요청 집계: 전송 27 / **차단 2** / 드라이런 0
- 모든 시도(차단 포함)는 `data/audit.log`(JSONL)에 기록 — 재현·책임추적 가능

## 범위·윤리 고지

- 모든 테스트는 로컬 docker의 OWASP crAPI 대상에 한정.
- 가드레일의 스코프 화이트리스트가 외부 대상 요청을 기술적으로 차단.
- 공격성 행위는 읽기 계열(GET) 검증으로 제한, 파괴적 행위는 기본 차단.
