"""출처 3: 게이트웨이 설정 (nginx) — 외부에 무엇이 노출되는가.

nginx는 location 접두사 단위로 라우팅하므로, 접두사 아래의 모든 코드 라우트가 노출된다.
서비스로 프록시하지 않는 location(디버그, 내부 도구 등)은 그 자체로 엔드포인트로 기록한다.
"""
from __future__ import annotations

import re
from typing import Any

from apisec.common import rel

LOC_RX = re.compile(r"location\s+(?:[=~^]+\s+)?(\S+)\s*\{")


def _blocks(text: str) -> list[str]:
    """첫 번째 'listen 80' server 블록만 사용 (443 블록은 동일 구성)."""
    servers, depth, start = [], 0, None
    for i, ch in enumerate(text):
        if text.startswith("server", i) and depth == 0 and start is None:
            start = i
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0 and start is not None:
                servers.append(text[start:i + 1])
                start = None
    return [s for s in servers if re.search(r"listen\s+80\b", s)] or servers


def collect(cfg) -> list[dict[str, Any]]:
    path = rel(cfg, cfg["sources"]["gateway_nginx"])
    text = path.read_text(encoding="utf-8")
    server = _blocks(text)[0]
    upstream_map = cfg["gateway"]["upstream_map"]
    locs = []
    for m in LOC_RX.finditer(server):
        # location 블록 본문 추출 (중괄호 균형)
        depth, i = 0, m.end() - 1
        for j in range(i, len(server)):
            depth += {"{": 1, "}": -1}.get(server[j], 0)
            if depth == 0:
                body = server[i + 1:j]
                break
        prefix = m.group(1)
        proxy = re.search(r"proxy_pass\s+([^;]+);", body)
        upstream_var = None
        if proxy:  # ${HTTP_PROTOCOL}://${IDENTITY_SERVICE} → 서비스 변수만 고른다
            upstream_var = next((v for v in re.findall(r"\$\{(\w+)\}", proxy.group(1)) if v in upstream_map), None)
        if proxy:
            kind = "proxy"
        elif re.search(r"\bautoindex\s+on", body):
            kind = "directory-listing"
        elif re.search(r"\breturn\s+\d+", body):
            kind = "static-response"
        else:
            kind = "static-files"
        locs.append({
            "prefix": prefix,
            "kind": kind,
            "upstream": upstream_map.get(upstream_var, upstream_var) if upstream_var else None,
            "proxy_target": proxy.group(1).strip() if proxy else None,
            "line": text[:text.find(server)].count("\n") + server[:m.start()].count("\n") + 1,
        })
    print(f"[gateway] {path.name}: locations={len(locs)}")
    return locs


def match(locs: list[dict[str, Any]], path: str) -> dict[str, Any] | None:
    """nginx 접두사 location 규칙: 가장 긴 접두사가 이긴다."""
    best = None
    for loc in locs:
        p = loc["prefix"]
        if path == p.rstrip("/") or path.startswith(p if p.endswith("/") else p) and p != "/":
            if best is None or len(p) > len(best["prefix"]):
                best = loc
    if best is None:
        best = next((l for l in locs if l["prefix"] == "/"), None)
    return best
