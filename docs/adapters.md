# 다른 대상에 적용하기 (어댑터 가이드)

이 툴킷은 **범용 엔진 + 대상별 어댑터** 구조다. crAPI에 종속된 부분은 아래 4곳뿐이고,
나머지(병합·분류, 스펙/HAR 파싱, PII 탐지, 가드레일·감사로그)는 대상과 무관하게 재사용된다.

## 대상을 바꿀 때 손대는 곳

| # | 바꾸는 것 | 파일 | 난이도 |
| --- | --- | --- | --- |
| 1 | 대상 주소·소스 경로·스코프·테스트 계정 | `config.yaml` | 설정만 |
| 2 | 코드 스캔 규칙(프레임워크) | `rules/routes.yml` | 프레임워크별 규칙 추가 |
| 3 | 게이트웨이 파서 | `apisec/m1/gateway.py` | nginx 외엔 파서 추가 |
| 4 | BOLA 검증 케이스(객체 ID를 어디서 얻나) | `apisec/m3/__main__.py` TEMPLATES/_collect_objects | 대상별 매핑 |

### 1. config.yaml (대부분 여기서 끝)
- `target`, `scope`, `sources.code`(서비스별 framework/path), `sources.spec`, `sources.gateway_nginx`
- `expected_public`(의도된 공개 경로), `m3.test_users`, `service_deps`(코드 근거로 선언)

### 2. 프레임워크 규칙
현재 지원: Spring(`@*Mapping`+Security), gorilla/mux, Django(urls+view+`@jwt_auth_required`).
추가하려면 `rules/routes.yml`에 라우트/인증 추출 규칙을 넣고, `message`에 `KEY=$VAR` 형식으로
메타변수를 실어 `apisec/m1/code.py`의 프레임워크 핸들러에서 조합한다.
- 예: FastAPI `@app.get("/x")` + `Depends(auth)`, Express `router.get`, NestJS 데코레이터, gRPC proto.

### 3. 게이트웨이
현재 nginx `location` 파서만 있다. Kong/Spring Cloud Gateway/k8s Ingress/Envoy는
`gateway.collect()`와 동일한 출력(prefix, kind, upstream)을 내는 파서를 추가하면 M1 병합은 그대로 동작.

### 4. BOLA 케이스
`TEMPLATES`(검증할 경로)와 `_collect_objects`(소유자 토큰으로 자기 객체 ID 수집)를 대상에 맞게.
판정 로직(`apisec/m3/bola.py`)과 가드레일은 그대로.

## 재사용되는 범용 부분 (손 안 댐)
- `apisec/m1/merge.py` — 네 출처 병합·분류(lifecycle/flag)
- `apisec/m1/spec.py`, `apisec/m1/traffic.py` — OpenAPI/HAR 표준 파싱
- `apisec/m2/detect.py` — PII 정규식(국내 전화·주민번호 포함), base64 중첩
- `apisec/m3/guardrails.py`, `runner.py` — 스코프·행위·레이트·드라이런·감사로그
- `apisec/m4/*`, `apisec/report.py` — 리포트·서비스맵

## 범위·안전
M3(실제 요청)는 반드시 **본인이 통제하는 테스트 대상**에만. 가드레일의 스코프 화이트리스트가
config의 허용 호스트 밖 요청을 전송 전에 차단하므로, 대상을 바꿀 때 `scope.allowed_hosts`를 먼저 설정.
