"""확정 취약점별 호출 홉 시퀀스 빌더.

각 홉이 '무슨 검사를 하는가'를 표시해, 인가가 어느 홉에서 빠졌는지 보이게 한다.
홉 구성은 코드 근거(게이트웨이 라우팅 + 서비스 핸들러 + 인증 방식)로 결정한다.
실측 응답(M3 findings)의 상태코드를 각 시나리오(소유자/타인/비로그인)에 붙인다.
"""
from __future__ import annotations

from typing import Any

# 서비스별 아키텍처 사실 (코드에서 확인). 토큰 검증을 어디서/어떻게 하나.
SERVICE_FACTS = {
    "identity": {
        "auth_at": "service",
        "auth_note": "Spring Security JWT 필터",
        "store": "PostgreSQL",
    },
    "workshop": {
        "auth_at": "handler",
        "auth_note": "뷰 메서드의 @jwt_auth_required (누락 가능)",
        "store": "PostgreSQL",
    },
    "community": {
        "auth_at": "remote",
        "auth_note": "identity /verify 원격 호출 (TLS 검증 꺼짐)",
        "store": "MongoDB",
    },
}


def build_sequences(cfg, endpoints: list[dict]) -> list[dict[str, Any]]:
    """confirmed(m3 vulnerable) 엔드포인트마다 홉 시퀀스 1개."""
    seqs = []
    for e in endpoints:
        m = e.get("m3")
        if not m or not m["verdict"].startswith("vulnerable"):
            continue
        svc = e.get("service") or "service"
        facts = SERVICE_FACTS.get(svc, {"auth_at": "service", "auth_note": "인증 필터", "store": "DB"})
        code = e["sources"].get("code") or {}
        no_auth = m["verdict"] == "vulnerable_no_auth"

        # 공통 액터(열): 공격자 → 게이트웨이 → 서비스 → 저장소
        actors = [
            {"id": "attacker", "label": "공격자", "sub": "B 토큰 / 토큰 없음"},
            {"id": "gateway", "label": "gateway", "sub": "nginx 라우팅"},
            {"id": svc, "label": svc, "sub": facts["auth_note"]},
            {"id": "db", "label": facts["store"], "sub": "데이터 저장소"},
        ]

        # 홉(행): 각 단계에서 무슨 검사를 하는가
        hops = []
        hops.append({"from": "attacker", "to": "gateway", "kind": "request",
                     "label": f"{e['method']} {e['path']}",
                     "note": "소유자 아닌 토큰 / 토큰 없이"})
        hops.append({"from": "gateway", "to": svc, "kind": "forward",
                     "label": "프록시 전달",
                     "check": "ok", "check_label": "게이트웨이: 경로만 보고 통과(인가 안 함)"})

        if no_auth:
            hops.append({"from": svc, "to": "db", "kind": "query",
                         "label": "바로 조회",
                         "check": "fail", "check_label": "인증 검사 없음 — 토큰 없이도 진입",
                         "vuln": True})
        else:  # BOLA
            hops.append({"from": svc, "to": svc, "kind": "authcheck",
                         "label": "토큰 유효성 검사",
                         "check": "ok", "check_label": "인증 통과(로그인은 됨)"})
            # CodeQL taint 흐름이 있으면 그 경로를 근거로 표시
            ql = (e.get("codeql") or [{}])[0]
            qlabel = "carId로 조회"
            qnote = "소유권 검사 없음 — 남의 객체도 조회"
            if ql.get("source") and ql.get("sink"):
                qnote = f"CodeQL taint 확정: {ql['source']} → {ql['sink']} (소유권 검사 없음)"
            hops.append({"from": svc, "to": "db", "kind": "query",
                         "label": qlabel,
                         "check": "fail", "check_label": qnote,
                         "vuln": True, "taint": bool(ql.get("sink"))})

        hops.append({"from": "db", "to": svc, "kind": "return",
                     "label": "소유자 식별 데이터"})
        hops.append({"from": svc, "to": "attacker", "kind": "response",
                     "label": f"200 + {', '.join(m['leaked'])}",
                     "note": "공격자에게 타인 PII 반환", "vuln": True})

        qflow = e.get("codeql") or []
        seqs.append({
            "id": e["id"],
            "title": f"{e['method']} {e['path']}",
            "verdict": m["verdict"],
            "service": svc,
            "code_loc": code.get("loc"),
            "handler": code.get("handler"),
            "codeql": [{"source": q.get("source"), "sink": q.get("sink"),
                        "steps": q.get("steps", [])} for q in qflow],
            "leaked": m["leaked"],
            "scenarios": {"owner": m["baseline"], "cross": m["cross"], "anon": m["anon"]},
            "actors": actors,
            "hops": hops,
        })
    # 같은 취약 유형(경로 템플릿)이 A/B 중복이면 하나만
    seen, uniq = set(), []
    for s in seqs:
        key = (s["title"].split("}")[0], s["verdict"])
        import re
        k2 = (re.sub(r"[0-9a-f-]{8,}|/\d+$", "{id}", s["title"]), s["verdict"])
        if k2 in seen:
            continue
        seen.add(k2)
        uniq.append(s)
    return uniq
