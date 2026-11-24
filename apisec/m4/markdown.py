"""M4 Markdown 리포트: 요약 · 확정 취약점(재현·증거·조치) · 서비스 현황 · 가드레일."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

# 취약점 유형별 조치방안(시큐어 코딩). 공격만이 아니라 수정까지 보여주는 부분.
REMEDIATION = {
    "vulnerable_bola": (
        "BOLA (객체 소유권 미검증)",
        [
            "핸들러에서 객체를 조회한 뒤 `객체.owner == 현재사용자`를 명시적으로 검사하거나,",
            "`currentUser.resources().findById(id)`처럼 소유자 범위 쿼리로 조회해 구조적으로 차단.",
            "중앙 정책 엔진(OPA/Cedar) 사용 시 객체 단위(resource-level) 규칙을 추가.",
            "식별자를 UUID로 바꾸는 것만으로는 해결되지 않음 — 인가 검사가 본질.",
        ],
    ),
    "vulnerable_no_auth": (
        "인증 누락",
        [
            "기본 거부(deny by default): 라우트별 인증을 opt-in이 아니라 기본값으로.",
            "누락된 핸들러에 인증 미들웨어/데코레이터(`@jwt_auth_required` 등) 추가.",
            "게이트웨이·서비스 양쪽에서 인증을 강제(내부 직접 접근 경로 차단).",
        ],
    ),
    "NO_AUTH": (
        "의도치 않은 공개 엔드포인트",
        ["인증 정책을 화이트리스트가 아닌 '명시된 공개 경로만 허용'으로 뒤집기.",
         "스펙·게이트웨이·코드의 인증 요구를 CI에서 교차 검증."],
    ),
    "INTERNAL_TOOL": (
        "내부 도구 외부 노출",
        ["mailhog 등 내부 도구는 게이트웨이 라우팅에서 제외하거나 내부망으로 한정."],
    ),
    "DEBUG": (
        "디버그 경로 노출",
        ["nginx autoindex·디버그 로그·pprof를 운영 설정에서 비활성화.",
         "요청 바디를 access log에 남기지 않기(비밀번호 로깅 위험)."],
    ),
    "tls_insecure": (
        "서비스 간 TLS 검증 비활성화",
        ["`InsecureSkipVerify: true` 제거, 내부 CA로 인증서 검증.",
         "토큰 검증을 원격 호출에 의존한다면 그 채널의 무결성이 특히 중요."],
    ),
}


def _h(status) -> str:
    return "✅" if status and 200 <= status < 300 else ("🔒" if status in (401, 403) else str(status))


def generate(data: dict, graph: dict, summary: list[dict], findings_meta: dict | None) -> str:
    eps = data["endpoints"]
    meta = data["meta"]
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    confirmed = [e for e in eps if e.get("m3") and e["m3"]["verdict"].startswith("vulnerable")]
    no_auth = [e for e in eps if "NO_AUTH" in e["flags"]]
    shadow = [e for e in eps if e["lifecycle"] == "shadow"]
    pii = [e for e in eps if e.get("pii_findings")]

    L: list[str] = []
    w = L.append
    w(f"# API 보안 점검 리포트 — {meta['target']}")
    w("")
    w(f"> 생성 {now} · 대상: 로컬 OWASP crAPI(의도적 취약 실습 앱) · 외부/운영 시스템 비대상")
    w("")
    w("## 요약")
    w("")
    w("| 지표 | 값 |")
    w("| --- | --- |")
    w(f"| 전체 엔드포인트 | {len(eps)} |")
    w(f"| Shadow (문서에 없는 노출) | {len(shadow)} |")
    w(f"| 의도치 않은 무인증 | {len(no_auth)} |")
    w(f"| 개인정보 노출 (관측) | {len(pii)} |")
    w(f"| **M3 실제 확정 취약점** | **{len(confirmed)}** |")
    w("")
    w("정적 분석·설정·트래픽으로 후보를 찾고(M1·M2), 로컬 대상에 한해 실제 요청으로 확정했다(M3). "
      "모든 공격성 요청은 가드레일(스코프·행위·레이트 제한)을 통과했고 전 시도가 감사 로그에 남는다.")
    w("")

    if confirmed:
        w("## 확정 취약점")
        w("")
        for i, e in enumerate(confirmed, 1):
            m = e["m3"]
            vtype, (title, steps) = m["verdict"], REMEDIATION.get(m["verdict"], ("", []))
            w(f"### {i}. {e['method']} `{e['path']}` — {title}")
            w("")
            code = e["sources"].get("code")
            if code:
                w(f"- **코드 근거**: `{code['loc']}` · `{code['handler']}`")
                w(f"- **인증(코드)**: {code.get('auth_evidence','-')}")
            w(f"- **분류/위험도**: {e['lifecycle']} / {e.get('risk','-')}")
            leaked = {**m['evidence'].get('cross_leaked', {}), **m['evidence'].get('anon_leaked', {})}
            w("")
            w("**재현 (차분 테스트)**")
            w("")
            w("| 주체 | 응답 | 의미 |")
            w("| --- | --- | --- |")
            w(f"| 소유자 | {_h(m['baseline'])} {m['baseline']} | 정상 기준선 |")
            actor = "다른 사용자" if m["verdict"] == "vulnerable_bola" else "다른 사용자"
            w(f"| {actor} | {_h(m['cross'])} {m['cross']} | {'타인 객체 접근됨' if m['cross'] and m['cross']<300 else '차단'} |")
            w(f"| 비로그인 | {_h(m['anon'])} {m['anon']} | {'무인증 접근됨' if m['anon'] and m['anon']<300 else '차단'} |")
            w("")
            if leaked:
                w(f"**유출된 소유자 식별값** (마스킹): {', '.join(f'`{k}={v}`' for k,v in leaked.items())}")
                w("")
            w("**조치방안**")
            w("")
            for s in steps:
                w(f"- {s}")
            w("")

    w("## 서비스별 현황")
    w("")
    w("| 서비스 | 엔드포인트 | 무인증 | BOLA후보 | PII | 확정 | 최고위험 |")
    w("| --- | --- | --- | --- | --- | --- | --- |")
    for s in sorted(summary, key=lambda s: -s["confirmed"]):
        w(f"| {s['service']} | {s['endpoints']} | {s['no_auth']} | {s['bola']} | "
          f"{s['pii']} | {s['confirmed']} | {s['max_risk']} |")
    w("")

    insecure = [e for e in graph["edges"] if e.get("insecure")]
    if insecure:
        w("## 서비스 간 신뢰 관계 주의점")
        w("")
        for e in insecure:
            w(f"- `{e['from']}` → `{e['to']}` ({e['purpose']}): **TLS 검증 비활성화** "
              f"— {REMEDIATION['tls_insecure'][1][0]} (근거: `{e['evidence']}`)")
        w("")

    if findings_meta:
        gr = findings_meta.get("guardrails", {})
        rc = findings_meta.get("request_counts", {})
        w("## 가드레일 동작 (M3)")
        w("")
        w(f"- 스코프: 허용 호스트 {gr.get('allowed_hosts')} 밖 요청 차단")
        w(f"- 행위: 허용 메서드 {gr.get('allowed_methods')} 외 차단 (파괴적 행위 기본 차단)")
        w(f"- 레이트: 초당 {gr.get('rate_per_sec')}건 상한")
        w(f"- 요청 집계: 전송 {rc.get('sent',0)} / **차단 {rc.get('blocked',0)}** / 드라이런 {rc.get('dry',0)}")
        w("- 모든 시도(차단 포함)는 `data/audit.log`(JSONL)에 기록 — 재현·책임추적 가능")
        w("")

    w("## 범위·윤리 고지")
    w("")
    w("- 모든 테스트는 로컬 docker의 OWASP crAPI 대상에 한정.")
    w("- 가드레일의 스코프 화이트리스트가 외부 대상 요청을 기술적으로 차단.")
    w("- 공격성 행위는 읽기 계열(GET) 검증으로 제한, 파괴적 행위는 기본 차단.")
    return "\n".join(L) + "\n"
