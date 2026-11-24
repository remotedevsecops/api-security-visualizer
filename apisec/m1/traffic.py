"""출처 4: 트래픽 (mitmproxy HAR) — 실제로 무엇이 호출되고 있는가.

실제 경로(/orders/7)를 알려진 템플릿(/orders/{order_id})에 맞추고,
어떤 템플릿에도 맞지 않으면 숫자·UUID 등을 {}로 바꿔 '트래픽에서만 보인 경로'로 남긴다.
"""
from __future__ import annotations

import base64
import json
import re
from collections import defaultdict
from typing import Any
from urllib.parse import urlsplit

from apisec.common import canon, rel, template_regex

DYNAMIC_SEG = re.compile(
    r"^(\d+|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}|[0-9a-f]{16,}|[A-Z0-9]{10,})$",
    re.I,
)
SKIP_PREFIXES = ("/static/", "/images/", "/favicon", "/manifest", "/logo")


def _jwt_sub(auth_header: str | None) -> str | None:
    """서명 검증 없이 sub만 읽는다 (누가 보낸 요청인지 표시용)."""
    if not auth_header or not auth_header.lower().startswith("bearer "):
        return None
    try:
        payload = auth_header.split()[1].split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("sub")
    except Exception:
        return "unparseable-token"


def normalize_unknown(path: str) -> str:
    segs = [("{id}" if DYNAMIC_SEG.match(s) else s) for s in path.split("/")]
    return canon("/".join(segs))


def collect(cfg, templates: list[tuple[str, str]]) -> list[dict[str, Any]]:
    """templates: (METHOD, template_path) — 코드·스펙에서 모은 알려진 경로."""
    har_path = rel(cfg, cfg["sources"]["traffic_har"])
    if not har_path.exists():
        print(f"[traffic] {har_path} 없음 — 트래픽 출처 생략")
        return []
    entries = json.loads(har_path.read_text(encoding="utf-8"))["log"]["entries"]

    # 리터럴이 많은(=더 구체적인) 템플릿을 먼저 시도: posts/recent 가 posts/{id} 보다 우선
    compiled = sorted(
        ((m, t, template_regex(t)) for m, t in set(templates)),
        key=lambda x: (x[1].count("{"), -len(x[1])),
    )
    agg: dict[tuple[str, str], dict[str, Any]] = defaultdict(
        lambda: {"count": 0, "statuses": defaultdict(int), "actors": set(), "unauth_2xx": 0, "samples": []}
    )
    for e in entries:
        req, res = e["request"], e["response"]
        url = urlsplit(req["url"])
        path = canon(url.path or "/")
        if path.startswith(SKIP_PREFIXES) or path == "/":
            continue
        method = req["method"].upper()
        if method == "OPTIONS":
            continue
        headers = {h["name"].lower(): h["value"] for h in req.get("headers", [])}
        tmpl, matched = None, False
        for m, t, rx in compiled:
            if (m == method or m == "ANY") and rx.match(path):
                tmpl, matched = t, True
                break
        if not matched:
            tmpl = normalize_unknown(path)
        a = agg[(method, tmpl)]
        a["count"] += 1
        a["statuses"][res["status"]] += 1
        a["actors"].add(_jwt_sub(headers.get("authorization")) or "anonymous")
        if not headers.get("authorization") and 200 <= res["status"] < 300:
            a["unauth_2xx"] += 1
        a["matched_template"] = matched
        if len(a["samples"]) < 3 and path not in a["samples"]:
            a["samples"].append(path)

    out = []
    for (m, t), a in agg.items():
        out.append({
            "method": m, "path": t, "count": a["count"],
            "statuses": dict(sorted(a["statuses"].items())),
            "actors": sorted(a["actors"]), "unauth_2xx": a["unauth_2xx"],
            "matched_template": a["matched_template"], "samples": a["samples"],
        })
    print(f"[traffic] {har_path.name}: requests={len(entries)} endpoints={len(out)}")
    return out
