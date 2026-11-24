# API 보안 가시화 툴킷 (apisec)

금융권 API의 **인가 취약점(BOLA)·무인증 노출·개인정보 유출**을 정적 분석으로 발견하고,
가드레일 아래에서 **실제 요청으로 확정**하는 파이프라인. OWASP crAPI(의도적 취약 실습 앱)로 검증.

> ⚠️ 대상은 로컬 docker의 OWASP crAPI로 한정. 외부·운영 시스템 대상 사용 금지.

## 핵심 결과 (crAPI 기준)

- 엔드포인트 **73개**를 네 출처로 교차 분석 → Shadow API **24개**, 무인증 **12개** 식별
- **CodeQL taint**로 `@PathVariable → DB 조회 → PII 응답` 코드 흐름 확정 (Java·Python)
- **M3 가드레일 검증**으로 BOLA/무인증 **4건을 실제 요청으로 확정** (차분 테스트 + 감사 로그)
- 결과는 단일 대시보드(`data/report.html`)로 — 목록 탭 + 확정 취약점 흐름 탭(시퀀스 다이어그램)

> 패턴 매칭(Semgrep) → 데이터 흐름(CodeQL) → 런타임 실증(M3)의 **3단계 깊이**를 교차해 오탐을 줄이는 게 설계 핵심.

## 한눈에

네 출처(코드·스펙·게이트웨이·트래픽)로 API를 탐지·분류(M1)하고, 개인정보 노출을 탐지(M2)한 뒤,
가드레일 아래에서 실제 요청으로 BOLA/무인증을 확정(M3)하고, 리포트·서비스맵으로 산출(M4)한다.

```bash
apisec all          # 전체 파이프라인 (scan → verify → report)
apisec all --dry-run  # M3는 전송 없이 계획만
apisec scan         # M1+M2 (+report.html)
apisec verify       # M3 (findings.json, audit.log)
apisec report       # M4 (report.md, service_graph.json, report.html)
```

설치: `pip install -e .` (또는 아래 venv의 `python -m apisec.cli ...`).
**다른 대상에 적용**: `docs/adapters.md` — config 하나로 대부분 교체, 프레임워크/게이트웨이만 어댑터 추가.

## M1: API 탐지와 공격면 지도

네 출처에서 각각 엔드포인트 목록을 뽑아 겹친다.

| 출처 | 방법 | 코드 |
| --- | --- | --- |
| 소스코드(패턴) | Semgrep 규칙으로 라우트·인증 표시 추출 (Spring, gorilla/mux, Django) | `apisec/m1/code.py`, `rules/routes.yml` |
| 소스코드(taint) | CodeQL 데이터 흐름으로 BOLA 확정: 식별자가 소유권 검사 없이 DB 조회까지 흐르는 코드 경로 | `codeql/queries/BolaPathToRepo.ql`, `apisec/m1/codeql.py` |
| 스펙 | OpenAPI 파싱 | `apisec/m1/spec.py` |
| 게이트웨이 | nginx location 접두사 파싱 → 노출 범위 계산 | `apisec/m1/gateway.py` |
| 트래픽 | mitmproxy 리버스 프록시 HAR → 템플릿 매칭 | `apisec/m1/traffic.py` |

분류와 플래그 규칙은 `apisec/m1/merge.py` 상단 주석 참고.

### CodeQL taint (선택, Java identity 서비스)

Semgrep이 "인증 표시 유무"를 본다면 CodeQL은 "식별자가 소유권 검사 없이 리포지토리
조회까지 흐르는 코드 경로"를 데이터 흐름으로 확정한다(`@PathVariable` → `findByUuid`).
결과는 M1에 `TAINT_BOLA` 플래그 + 흐름 경로로 합쳐지고, 시퀀스 다이어그램 하단에 표시된다.

```bash
# 사전: JDK17 (~/.jdks), CodeQL CLI (~/.codeql/codeql)
export JAVA_HOME=~/.jdks/jdk-17*/Contents/Home
SRC="$PWD/../sources/crAPI/services/identity"
# 1) 빌드를 추적해 코드 DB 생성
~/.codeql/codeql/codeql database create codeql/identity-db --language=java \
  --overwrite --source-root="$SRC" --command="<빌드 스크립트: gradlew clean build -x test>"
# 2) taint 쿼리 실행 → SARIF
~/.codeql/codeql/codeql database analyze codeql/identity-db codeql/queries/BolaPathToRepo.ql \
  --format=sarifv2.1.0 --output=data/codeql-bola.sarif \
  --additional-packs=~/.codeql/codeql/qlpacks --rerun
# 3) M1이 data/codeql-bola.sarif를 자동으로 읽어 TAINT_BOLA 부여
apisec scan
```

crAPI identity는 Gradle 8.1 + JDK17. DB(`codeql/identity-db`)는 용량이 커서 `.gitignore` 처리.
쿼리는 핸들러 메서드명으로 정확 매칭해 같은 컨트롤러의 정상 엔드포인트엔 오탐이 붙지 않는다.

### 실행

```bash
# 0) crAPI 실행 (127.0.0.1에만 바인딩)
cd ../testbed/crapi && docker compose --compatibility up -d && cd -

# 1) 정상 사용자 트래픽 캡처 → data/traffic.har
./scripts/capture.sh

# 2) M1 실행 → data/endpoints.json, data/attack_surface.html
~/.venvs/apisec/bin/python -m apisec.m1

# 3) M2 개인정보 흐름 탐지 → data/enriched_endpoints.json
~/.venvs/apisec/bin/python -m apisec.m2          # 정규식만
~/.venvs/apisec/bin/python -m apisec.m2 --llm    # 애매한 필드는 LLM 2차 판정(키 있을 때)

# 4) M3 가드레일 BOLA 검증 (로컬 crAPI 전용) → data/findings.json, data/audit.log
~/.venvs/apisec/bin/python -m apisec.m3 --dry-run   # 먼저 계획만 확인(전송 없음)
~/.venvs/apisec/bin/python -m apisec.m3             # 실제 검증

# 5) 통합 리포트 (흐름 + M1 분류 + M2 PII + M3 확정) → data/report.html
~/.venvs/apisec/bin/python -m apisec.report
```

## M3: 가드레일 BOLA 검증

M1/M2가 "후보"로 지목한 BOLA 엔드포인트를 실제 요청으로 확정한다. 범위는 로컬 crAPI와 테스트 계정 A·B로 한정.

차분 테스트: A 소유 객체를 ① 소유자 A(기준선) ② 다른 사용자 B ③ 비로그인 으로 조회해, B/비로그인이 A의 식별값(이메일·좌표 등)을 받아내면 취약 확정. 판정은 결정론적 코드가 한다(LLM 아님).

가드레일 (`apisec/m3/guardrails.py`) — 모든 요청이 전송 전 통과:

| 가드 | 동작 |
| --- | --- |
| 스코프 화이트리스트 | config의 허용 호스트(127.0.0.1) 밖은 차단 |
| 행위 화이트리스트 | 허용 메서드(기본 GET)만. DELETE 등 파괴적 행위 차단 |
| 레이트 리밋 | 초당 요청 상한, 초과 시 대기 |
| 드라이런 | `--dry-run`이면 실제 전송 없이 계획만 |
| 감사 로그 | 모든 시도(차단 포함)를 `data/audit.log`(JSONL)에 기록, 토큰 마스킹 |

설정은 `config.yaml`의 `m3:` 섹션.

## M4: 리포트 · 서비스 맵

- **report.md**: 요약, 확정 취약점(재현 차분표·유출값·조치방안), 서비스별 현황, 가드레일 동작, 범위 고지.
- **service_graph.json + report.html의 "서비스 맵" 탭**: 서비스 간 신뢰 관계 그래프.
  리스트가 "무엇이 있나"라면 맵은 "누가 누구를 호출하고 어디서 인가·TLS가 약한가"를 본다.
  예: community→identity 토큰 검증 호출이 TLS 검증 꺼짐(빨간 점선) — 리스트로는 안 보이는 정보.
- 모든 엔드포인트 목록은 리스트가 더 낫다(노드 73개는 그래프로 털뭉치가 됨). 그래프는 서비스 단위 관계에만.

## 디렉터리

```
toolkit/
  apisec/
    common.py          공통(설정·경로정규화·매칭)
    m1/ {code,spec,gateway,traffic,merge,render}.py   탐지·병합·분류
    m2/ {detect,llm}.py                                PII 탐지(+LLM 어댑터)
    m3/ {guardrails,runner,bola}.py                    가드레일·감사로그·검증
    m4/ {build,markdown}.py                            집계·서비스맵·MD리포트
    report.py          통합 HTML(리스트+서비스맵 탭)
    cli.py             apisec 단일 CLI
  rules/routes.yml     Semgrep 라우트 추출 규칙
  config.yaml          대상·스코프·출처·가드레일·서비스의존성
  docs/adapters.md     다른 대상 적용 가이드
  data/                산출물(endpoints/enriched/findings/report*.{html,md}/audit.log)
```

## M2: PII(개인정보) 흐름 탐지

캡처한 HAR의 응답 본문을 엔드포인트별로 모아 스캔한다. 새 요청은 보내지 않는다.

| 단계 | 방법 | 코드 |
| --- | --- | --- |
| 1차 정규식 | 이메일·전화(01x)·카드(Luhn)·좌표·VIN·JWT·주민번호 + 필드명 힌트 | `apisec/m2/detect.py` |
| base64 중첩 | crAPI 커뮤니티 응답처럼 base64(JSON)이면 디코딩 후 재귀 탐지 | 〃 |
| 2차 LLM(선택) | 필드명만으로 애매한 값을 LLM이 PII 여부·종류·근거 판정 | `apisec/m2/llm.py` |
| 점수·위험도 | 종류별 가중합 → 민감도, 무인증(NO_AUTH)+PII면 `critical` 승격 | `apisec/m2/__main__.py` |

LLM은 `LLM_PROVIDER`(claude/openai) + API 키가 있을 때만 동작하고, 없으면 자동으로 정규식만 쓴다.

### 환경

- `~/.venvs/apisec`: Python 3.11 + semgrep, httpx, pydantic, pyyaml, rich, jinja2
- `~/.venvs/mitm`: mitmproxy 11 (semgrep과 의존성 충돌이 있어 분리)
- venv는 iCloud 동기화를 피하려고 프로젝트 폴더 밖에 둔다.

### 알려진 한계

- Semgrep OSS는 비로그인 시 metavariable 값을 JSON에 넣지 않아, 규칙 `message`에 값을 넣고 파싱한다.
- 코드 기반 인증 판정은 "프레임워크 수준 표시(어노테이션·미들웨어·데코레이터)" 기준이다. 핸들러 안에서 직접 검사하는 경우는 `public`으로 보일 수 있으며, M3에서 실제 요청으로 검증한다.
- `unobserved`는 트래픽 시나리오의 커버리지에 따라 달라진다.
