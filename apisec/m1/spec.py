"""출처 2: API 스펙 (OpenAPI 3) — 회사가 '있다'고 문서화한 목록."""
from __future__ import annotations

import json
import re
from typing import Any

import yaml

from apisec.common import HTTP_METHODS, canon, rel

ID_FIELD = re.compile(r"(^id$|_id$|Id$|^vin$|^uuid$|account)", re.I)


def _resolve(doc: dict, node: Any) -> Any:
    if isinstance(node, dict) and "$ref" in node:
        cur: Any = doc
        for part in node["$ref"].lstrip("#/").split("/"):
            cur = cur.get(part, {})
        return _resolve(doc, cur)
    return node


def _body_id_fields(doc: dict, op: dict) -> list[str]:
    content = (_resolve(doc, op.get("requestBody", {})) or {}).get("content", {})
    found: list[str] = []
    for media in content.values():
        schema = _resolve(doc, media.get("schema", {})) or {}
        for name in (schema.get("properties") or {}):
            if ID_FIELD.search(name):
                found.append(name)
    return sorted(set(found))


def collect(cfg) -> list[dict[str, Any]]:
    path = rel(cfg, cfg["sources"]["spec"])
    text = path.read_text(encoding="utf-8")
    doc = json.loads(text) if path.suffix == ".json" else yaml.safe_load(text)
    global_sec = doc.get("security")
    out = []
    for raw_path, item in doc.get("paths", {}).items():
        for m, op in item.items():
            if m.upper() not in HTTP_METHODS:
                continue
            sec = op.get("security", global_sec)
            out.append({
                "method": m.upper(),
                "path": canon(raw_path),
                "auth": "public" if not sec else "token",
                "operation_id": op.get("operationId"),
                "summary": op.get("summary"),
                "tags": op.get("tags", []),
                "body_id_fields": _body_id_fields(doc, op),
            })
    print(f"[spec] {path.name}: operations={len(out)}")
    return out
