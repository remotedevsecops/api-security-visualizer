"""M4 데이터 빌더: 서비스별 위험 집계 + 서비스 관계 그래프 노드/엣지.

그래프로 그릴 가치가 있는 것만 그래프로: 서비스 간 신뢰 관계(누가 누구를 호출, 인가/TLS).
엔드포인트 73개 전체는 리스트(report.html)가 더 낫다 — 여기선 서비스 단위로 요약.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Any

RISK_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "none": 0}


def service_summary(endpoints: list[dict]) -> list[dict[str, Any]]:
    svc: dict[str, dict] = defaultdict(lambda: {
        "endpoints": 0, "no_auth": 0, "bola": 0, "pii": 0,
        "confirmed": 0, "shadow": 0, "max_risk": "none",
    })
    for e in endpoints:
        s = svc[e.get("service") or "기타"]
        s["endpoints"] += 1
        if "NO_AUTH" in e["flags"]:
            s["no_auth"] += 1
        if "BOLA_CANDIDATE" in e["flags"]:
            s["bola"] += 1
        if e.get("pii_findings"):
            s["pii"] += 1
        if e.get("m3") and e["m3"]["verdict"].startswith("vulnerable"):
            s["confirmed"] += 1
        if e["lifecycle"] == "shadow":
            s["shadow"] += 1
        if RISK_RANK.get(e.get("risk", "none"), 0) > RISK_RANK.get(s["max_risk"], 0):
            s["max_risk"] = e.get("risk", "none")
    return [{"service": k, **v} for k, v in svc.items()]


def auth_matrix(endpoints: list[dict]) -> list[dict[str, Any]]:
    """확정 취약점의 차분 매트릭스(엔드포인트 × 주체 상태코드)."""
    import re
    rows, seen = [], set()
    for e in endpoints:
        m = e.get("m3")
        if not m or not m["verdict"].startswith("vulnerable"):
            continue
        tmpl = re.sub(r"[0-9a-f-]{8,}|/\d+$", "/{id}", e["path"])
        key = (e["method"], tmpl, m["verdict"])
        if key in seen:
            continue
        seen.add(key)
        rows.append({
            "method": e["method"], "path": tmpl, "service": e.get("service"),
            "verdict": m["verdict"], "leaked": m["leaked"],
            "owner": m["baseline"], "cross": m["cross"], "anon": m["anon"],
        })
    return rows


def service_graph(cfg, endpoints: list[dict]) -> dict[str, Any]:
    summary = {s["service"]: s for s in service_summary(endpoints)}
    nodes = []
    for name, s in summary.items():
        nodes.append({
            "id": name, "kind": "gateway" if name == "gateway" else "service",
            "endpoints": s["endpoints"], "confirmed": s["confirmed"],
            "no_auth": s["no_auth"], "pii": s["pii"], "max_risk": s["max_risk"],
        })
    # 게이트웨이 노드는 명시(엔드포인트 집계엔 거의 안 잡히므로)
    if "gateway" not in summary:
        nodes.insert(0, {"id": "gateway", "kind": "gateway", "endpoints": 0,
                         "confirmed": 0, "no_auth": 0, "pii": 0, "max_risk": "none"})
    known = {n["id"] for n in nodes}
    edges = []
    for d in cfg.get("service_deps", []):
        for end in (d["from"], d["to"]):
            if end not in known:
                nodes.append({"id": end, "kind": "service", "endpoints": 0,
                              "confirmed": 0, "no_auth": 0, "pii": 0, "max_risk": "none"})
                known.add(end)
        edges.append({
            "from": d["from"], "to": d["to"], "purpose": d.get("purpose", ""),
            "evidence": d.get("evidence", ""),
            "tls_verify": d.get("tls_verify", None),
            "insecure": d.get("tls_verify") is False,
        })
    return {"nodes": nodes, "edges": edges}
