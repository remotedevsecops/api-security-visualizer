"""출처 1: 소스코드 (Semgrep으로 라우트·인증 표시 추출 → 프레임워크별로 조합).

Semgrep OSS는 비로그인 상태에서 metavariable 값을 JSON에 넣어주지 않으므로,
규칙의 message에 "KEY=$VAR|KEY=$VAR" 형태로 넣고 여기서 다시 파싱한다.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

from apisec.common import HTTP_METHODS, TOOLKIT_ROOT, ant_match, canon, rel, strip_literal

RULES = TOOLKIT_ROOT / "rules" / "routes.yml"


def _semgrep_bin() -> str:
    cand = Path(sys.executable).parent / "semgrep"
    return str(cand) if cand.exists() else (shutil.which("semgrep") or "semgrep")


def run_semgrep(target: Path) -> list[dict[str, Any]]:
    proc = subprocess.run(
        [_semgrep_bin(), "scan", "--metrics=off", "--quiet", "--json",
         "--config", str(RULES), str(target)],
        capture_output=True, text=True, check=False,
    )
    data = json.loads(proc.stdout or "{}")
    if data.get("errors"):
        print(f"[code] semgrep errors in {target}: {len(data['errors'])}", file=sys.stderr)
    out = []
    for r in data.get("results", []):
        fields = {}
        for part in r["extra"]["message"].split("|"):
            k, _, v = part.partition("=")
            fields[k] = v
        out.append({
            "rule": r["check_id"].split(".")[-1],
            "file": r["path"],
            "line": r["start"]["line"],
            **fields,
        })
    return out


def _loc(cfg, file: str, line: int) -> str:
    try:
        return f"{Path(file).resolve().relative_to(rel(cfg, '..'))}:{line}"
    except ValueError:
        return f"{file}:{line}"


# ----------------------------------------------------------------- Spring

def spring_routes(cfg, svc: dict[str, Any]) -> list[dict[str, Any]]:
    hits = run_semgrep(rel(cfg, svc["path"]))
    prefix_by_file = {h["file"]: strip_literal(h["PATH"])
                      for h in hits if h["rule"] == "spring-class-mapping"}
    # Spring Security 규칙: 파일 내 선언 순서대로 첫 매치가 이긴다
    rules = sorted(
        [h for h in hits if h["rule"] in ("spring-security-permitall", "spring-security-hasrole")],
        key=lambda h: (h["file"], h["line"]),
    )
    routes = []
    for h in hits:
        if h["rule"] != "spring-method-mapping":
            continue
        method = h["ANN"].replace("Mapping", "").upper()
        path = canon(prefix_by_file.get(h["file"], "") + "/" + strip_literal(h["PATH"]))
        auth, auth_src = "token", "anyRequest().authenticated()"
        for r in rules:
            if ant_match(strip_literal(r["PATH"]), path):
                if r["rule"] == "spring-security-permitall":
                    auth = "public"
                else:
                    auth = "role:" + strip_literal(r["ROLE"])
                auth_src = f"requestMatchers({strip_literal(r['PATH'])}) @ {_loc(cfg, r['file'], r['line'])}"
                break
        routes.append({
            "service": svc["service"], "method": method, "path": path,
            "handler": h["FUNC"], "loc": _loc(cfg, h["file"], h["line"]),
            "auth": auth, "auth_evidence": auth_src,
        })
    return routes


# ----------------------------------------------------------------- gorilla/mux

def mux_routes(cfg, svc: dict[str, Any]) -> list[dict[str, Any]]:
    routes = []
    for h in run_semgrep(rel(cfg, svc["path"])):
        if h["rule"] == "go-mux-route":
            methods = [m for m in re.findall(r'"(\w+)"', h["METHODS"]) if m in HTTP_METHODS]
            authed = "SetMiddlewareAuthentication" in h["HANDLER"]
            fn = re.findall(r"controller\.(\w+)", h["HANDLER"])
            for m in methods:
                routes.append({
                    "service": svc["service"], "method": m, "path": canon(strip_literal(h["PATH"])),
                    "handler": fn[0] if fn else h["HANDLER"], "loc": _loc(cfg, h["file"], h["line"]),
                    "auth": "token" if authed else "public",
                    "auth_evidence": "SetMiddlewareAuthentication 래핑" if authed else "인증 미들웨어 없음",
                })
        elif h["rule"] == "go-mux-prefix":
            routes.append({
                "service": svc["service"], "method": "ANY",
                "path": canon(strip_literal(h["PATH"])) + "/{*}",
                "handler": h["HANDLER"], "loc": _loc(cfg, h["file"], h["line"]),
                "auth": "public", "auth_evidence": "PathPrefix 핸들러, 인증 미들웨어 없음",
                "note": "와일드카드 라우트 (조건부 등록 여부는 코드 확인 필요)",
            })
    return routes


# ----------------------------------------------------------------- Django

def django_routes(cfg, svc: dict[str, Any]) -> list[dict[str, Any]]:
    base = rel(cfg, svc["path"])
    hits = run_semgrep(base)
    by_file = defaultdict(list)
    for h in hits:
        by_file[str(Path(h["file"]).resolve())].append(h)

    view_methods: dict[str, list[str]] = defaultdict(list)
    view_auth: dict[str, set[str]] = defaultdict(set)
    view_loc: dict[str, str] = {}
    for h in hits:
        if h["rule"] == "django-view-method":
            view_methods[h["VIEW"]].append(h["METHOD"].upper())
            view_loc.setdefault(h["VIEW"], _loc(cfg, h["file"], h["line"]))
        elif h["rule"] == "django-view-method-auth":
            view_auth[h["VIEW"]].add(h["METHOD"].upper())

    routes: list[dict[str, Any]] = []

    def walk(urls_file: Path, prefix: str, depth: int = 0) -> None:
        if depth > 10:
            return
        for h in sorted(by_file.get(str(urls_file.resolve()), []), key=lambda x: x["line"]):
            frag = prefix + strip_literal(h.get("PATH", ""))
            if h["rule"] == "django-include":
                module = strip_literal(h["MODULE"])
                target = base / (module.replace(".", "/") + ".py")
                if target.exists():
                    walk(target, frag, depth + 1)
                else:  # 서드파티 앱(소스 없음)
                    routes.append({
                        "service": svc["service"], "method": "ANY", "path": canon(frag) + "/{*}",
                        "handler": module, "loc": _loc(cfg, h["file"], h["line"]),
                        "auth": "unknown", "auth_evidence": "외부 패키지 include (소스 없음)",
                    })
            elif h["rule"] == "django-admin-site":
                routes.append({
                    "service": svc["service"], "method": "ANY", "path": canon(frag) + "/{*}",
                    "handler": "django.contrib.admin", "loc": _loc(cfg, h["file"], h["line"]),
                    "auth": "session-login", "auth_evidence": "Django admin 로그인 페이지",
                    "note": "관리자 콘솔",
                })
            elif h["rule"] == "django-view-route":
                view = h["VIEW"]
                for m in view_methods.get(view, []):
                    authed = m in view_auth.get(view, set())
                    routes.append({
                        "service": svc["service"], "method": m, "path": canon(frag),
                        "handler": f"{view}.{m.lower()}", "loc": view_loc.get(view, _loc(cfg, h["file"], h["line"])),
                        "route_loc": _loc(cfg, h["file"], h["line"]),
                        "auth": "token" if authed else "public",
                        "auth_evidence": "@jwt_auth_required" if authed else "인증 데코레이터 없음",
                    })

    walk(base / svc["root_urlconf"], "")
    return routes


FRAMEWORKS = {"spring": spring_routes, "gorilla-mux": mux_routes, "django": django_routes}


def collect(cfg) -> list[dict[str, Any]]:
    out = []
    for svc in cfg["sources"]["code"]:
        found = FRAMEWORKS[svc["framework"]](cfg, svc)
        print(f"[code] {svc['service']:<10} {svc['framework']:<12} routes={len(found)}")
        out.extend(found)
    return out
