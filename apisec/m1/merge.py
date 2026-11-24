"""네 출처(코드·스펙·게이트웨이·트래픽)를 겹쳐서 엔드포인트별로 분류한다.

분류(lifecycle) — 하나만 붙는다
  active        : 코드O 스펙O 노출O 트래픽O  (정상)
  unobserved    : 코드O 스펙O 노출O 트래픽X  (Zombie 후보. 트래픽 커버리지에 따라 달라짐)
  shadow        : 코드O 스펙X 노출O          (문서에 없는데 밖에서 접근 가능)
  internal-only : 코드O 노출X                (게이트웨이 접두사 밖. 내부 신뢰 점검 대상)
  stale-doc     : 스펙O 코드X                (문서만 남음)
  gateway-only  : 게이트웨이 location 자체가 엔드포인트 (디버그 목록, 내부 도구 프록시 등)
  traffic-only  : 트래픽에서만 보임

플래그(flags) — 여러 개 가능
  NO_AUTH, AUTH_MISMATCH, BOLA_CANDIDATE, BODY_ID, ADMIN, DEBUG, OLD_VERSION, INTERNAL_TOOL
"""
from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from apisec.common import ant_match, canon, key, param_names
from apisec.m1 import gateway as gw

VERSION_SEG = re.compile(r"/v(\d+(?:\.\d+)?)(?=/)")


def _expected_public(cfg, path: str) -> bool:
    return any(ant_match(p, path) for p in cfg.get("expected_public", []))


def _version_groups(eps: list[dict[str, Any]]) -> None:
    """같은 기능의 구버전이 함께 살아 있으면 낮은 버전에 OLD_VERSION."""
    groups: dict[tuple[str, str], list[tuple[float, dict]]] = defaultdict(list)
    for e in eps:
        m = VERSION_SEG.search(e["path"])
        if m:
            base = VERSION_SEG.sub("/v*", e["path"], count=1)
            groups[(e["method"], base)].append((float(m.group(1)), e))
    for items in groups.values():
        if len(items) > 1:
            top = max(v for v, _ in items)
            for v, e in items:
                if v < top:
                    e["flags"].append("OLD_VERSION")
                    e["notes"].append(f"상위 버전 v{top:g} 과 병존")


def merge(cfg, code: list, spec: list, locs: list, traffic: list) -> list[dict[str, Any]]:
    eps: dict[tuple[str, str], dict[str, Any]] = {}

    def get(method: str, path: str, service: str | None = None) -> dict[str, Any]:
        k = key(method, path)
        if k not in eps:
            eps[k] = {"method": method, "path": canon(path), "service": service,
                      "sources": {"code": None, "spec": None, "gateway": None, "traffic": None},
                      "flags": [], "notes": []}
        if service and not eps[k]["service"]:
            eps[k]["service"] = service
        return eps[k]

    for r in code:
        get(r["method"], r["path"], r["service"])["sources"]["code"] = r
    for s in spec:
        get(s["method"], s["path"])["sources"]["spec"] = s
    for t in traffic:
        e = get(t["method"], t["path"])
        e["sources"]["traffic"] = t

    # 게이트웨이 노출 판정
    for e in eps.values():
        loc = gw.match(locs, e["path"])
        exposed = bool(loc and loc["kind"] == "proxy" and e["path"] != "/")
        e["sources"]["gateway"] = {"exposed": exposed, "location": loc["prefix"] if loc else None,
                                   "upstream": loc["upstream"] if loc else None}
        if not e["service"] and loc and loc["upstream"]:
            e["service"] = loc["upstream"]

    # 서비스로 프록시하지 않는 location = 게이트웨이 자체 엔드포인트
    for loc in locs:
        if loc["kind"] == "proxy" and loc["upstream"] in {s["service"] for s in cfg["sources"]["code"]}:
            continue
        if loc["prefix"] in ("/", "/static", "/images"):
            continue
        path = canon(loc["prefix"]) + ("/{*}" if loc["prefix"].endswith("/") else "")
        e = get("ANY" if loc["prefix"].endswith("/") else "GET", path, loc["upstream"] or "gateway")
        e["sources"]["gateway"] = {"exposed": True, "location": loc["prefix"], "upstream": loc["upstream"],
                                   "kind": loc["kind"], "line": loc["line"]}

    out = list(eps.values())
    for e in out:
        src = e["sources"]
        c, s, g, t = src["code"], src["spec"], src["gateway"], src["traffic"]
        exposed = bool(g and g["exposed"])

        if g and g.get("kind"):
            e["lifecycle"] = "gateway-only"
        elif c and not exposed:
            e["lifecycle"] = "internal-only"
        elif c and not s:
            e["lifecycle"] = "shadow"
        elif c and s and t:
            e["lifecycle"] = "active"
        elif c and s:
            e["lifecycle"] = "unobserved"
        elif s and not c:
            e["lifecycle"] = "stale-doc"
        else:
            e["lifecycle"] = "traffic-only"

        # 인증: 코드가 1순위 근거, 없으면 스펙
        auth = (c or {}).get("auth") or (s or {}).get("auth") or "unknown"
        if g and g.get("kind") in ("directory-listing", "proxy", "static-response"):
            auth = "public"
        e["auth"] = auth
        if c and s and c["auth"] in ("public", "token") and c["auth"] != s["auth"]:
            e["flags"].append("AUTH_MISMATCH")
            e["notes"].append(f"코드={c['auth']} / 스펙={s['auth']}")
        if auth == "public" and exposed is not False and not _expected_public(cfg, e["path"]):
            if e["lifecycle"] != "internal-only":
                e["flags"].append("NO_AUTH")
        if t and t["unauth_2xx"] and not _expected_public(cfg, e["path"]):
            e["notes"].append(f"토큰 없는 요청이 2xx {t['unauth_2xx']}회")

        # 경로에 객체 식별자가 있으면 BOLA 후보 (무인증이면 더 위험 — NO_AUTH와 함께 표시됨)
        if param_names(e["path"]) and "{*}" not in e["path"]:
            e["flags"].append("BOLA_CANDIDATE")
        if s and s.get("body_id_fields"):
            e["flags"].append("BODY_ID")
            e["notes"].append("요청 바디 객체 참조: " + ", ".join(s["body_id_fields"]))
        low = e["path"].lower()
        if re.search(r"admin|management", low) or auth.startswith("role:"):
            e["flags"].append("ADMIN")
        if re.search(r"debug|pprof|test|internal", low):
            e["flags"].append("DEBUG")
        if g and g.get("kind") == "proxy" and g.get("upstream") not in {x["service"] for x in cfg["sources"]["code"]}:
            if g.get("upstream") in cfg["gateway"].get("internal_tools", []):
                e["flags"].append("INTERNAL_TOOL")
                e["notes"].append(f"게이트웨이가 내부 도구({g['upstream']})를 외부로 프록시")
            else:
                e["flags"].append("UNSCANNED")
                e["notes"].append(f"코드 미분석 서비스({g['upstream']}) — 접두사 전체가 노출")
        if g and g.get("kind") == "directory-listing":
            e["notes"].append("nginx autoindex: 디렉터리 목록 공개")
        if c and c.get("note"):
            e["notes"].append(c["note"])

    _version_groups(out)
    order = {"identity": 0, "community": 1, "workshop": 2}
    out.sort(key=lambda e: (order.get(e["service"] or "", 9), e["service"] or "", e["path"], e["method"]))
    for i, e in enumerate(out, 1):
        e["id"] = f"ep_{i:03d}"
        e["flags"] = sorted(set(e["flags"]))
    return out
