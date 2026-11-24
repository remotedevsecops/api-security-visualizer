"""CodeQL taint 결과(SARIF)를 M1 엔드포인트에 합친다.

Semgrep(패턴)이 "인증 표시 유무"를 본다면, CodeQL(taint)은 "@PathVariable 값이
소유권 검사 없이 리포지토리 조회까지 흘러가는 코드 경로"를 데이터 흐름으로 확정한다.
결과를 엔드포인트의 code loc(파일:라인)과 매칭해 TAINT_BOLA 플래그와 흐름 경로를 붙인다.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from apisec.common import rel


def load_sarif(path: Path) -> list[dict[str, Any]]:
    """SARIF → finding 목록 (sink 위치 + 흐름 경로 단계)."""
    if not path.exists():
        return []
    doc = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for run in doc.get("runs", []):
        for r in run.get("results", []):
            locs = r.get("locations", [])
            if not locs:
                continue
            phys = locs[0].get("physicalLocation", {})
            sink_file = phys.get("artifactLocation", {}).get("uri", "")
            sink_line = phys.get("region", {}).get("startLine")
            # codeFlows → 소스에서 싱크까지의 단계
            steps = []
            for cf in r.get("codeFlows", []):
                for tf in cf.get("threadFlows", []):
                    for loc in tf.get("locations", []):
                        p = loc.get("location", {}).get("physicalLocation", {})
                        steps.append({
                            "file": p.get("artifactLocation", {}).get("uri", ""),
                            "line": p.get("region", {}).get("startLine"),
                            "msg": loc.get("location", {}).get("message", {}).get("text", ""),
                        })
                    break
                break
            import re
            msg = r.get("message", {}).get("text", "")
            hm = re.search(r"\\?\[handler=([\w.]+)\\?\]", msg)
            out.append({
                "rule": r.get("ruleId", ""),
                "message": re.sub(r"\s*\\?\[handler=[\w.]+\\?\]", "", msg),
                "handler": hm.group(1) if hm else None,
                "sink_file": sink_file, "sink_line": sink_line,
                "source_file": steps[0]["file"] if steps else sink_file,
                "source_line": steps[0]["line"] if steps else sink_line,
                "steps": steps,
            })
    return out


def attach(cfg, endpoints: list[dict], sarif_name: str = "codeql-bola.sarif") -> int:
    """SARIF finding을 엔드포인트의 handler 파일 기준으로 매칭.

    소스(핸들러 @PathVariable)의 파일·라인이 엔드포인트 code loc와 같은 컨트롤러면 연결.
    """
    sarif = rel(cfg, cfg["output_dir"] + "/" + sarif_name)
    findings = load_sarif(sarif)
    if not findings:
        return 0

    # 엔드포인트의 code loc: ".../controller/VehicleController.java:121"
    def ctrl_of(e):
        c = e.get("sources", {}).get("code") or {}
        loc = c.get("loc", "")
        return loc.rsplit(":", 1)[0] if ":" in loc else loc

    import re as _re

    def has_param(e):
        return "{" in e["path"]

    # handler별로 후보 엔드포인트를 모은다
    by_handler: dict[str, list] = {}
    for e in endpoints:
        h = (e.get("sources", {}).get("code") or {}).get("handler", "")
        if h:
            by_handler.setdefault(h, []).append(e)

    matched = 0
    for f in findings:
        h = f.get("handler")
        if not h or h not in by_handler:
            continue
        cands = by_handler[h]
        # 같은 핸들러가 여러 경로에 매핑되면: taint가 경로 식별자에서 시작하므로 {id} 있는 경로 우선
        targets = [e for e in cands if has_param(e)] or cands
        for e in targets:
            e.setdefault("codeql", []).append({
                "rule": f["rule"], "message": f["message"],
                "sink": f"{Path(f['sink_file']).name}:{f['sink_line']}",
                "source": f"{Path(f['source_file']).name}:{f['source_line']}",
                "steps": _readable_steps(cfg, f["steps"]),
            })
            if "TAINT_BOLA" not in e["flags"]:
                e["flags"].append("TAINT_BOLA")
                e["flags"].sort()
            matched += 1
    return matched


def _readable_steps(cfg, steps: list[dict]) -> list[str]:
    """흐름 단계를 '파일:라인  코드스니펫' 형태로. CFG 노드 설명 대신 실제 코드 한 줄."""
    out, seen = [], set()
    for s in steps:
        if not s.get("file") or not s.get("line"):
            continue
        key = (s["file"], s["line"])
        if key in seen:
            continue
        seen.add(key)
        snippet = _source_line(cfg, s["file"], s["line"])
        label = f"{Path(s['file']).name}:{s['line']}"
        out.append(f"{label}  {snippet}" if snippet else f"{label} {s.get('msg','')}")
    return out


def attach_pii_sink(cfg, endpoints: list[dict], sarif_name: str) -> int:
    """구조 쿼리(BolaRepoToPii) 결과를 기존 taint 흐름의 마지막 'PII 응답' 단계로 덧붙인다.

    이 쿼리는 @kind problem(경로 없음)이라 handler 매칭 후 흐름 steps 끝에
    '응답 DTO가 email/name을 담아 반환' 단계를 추가해 DB→PII 응답을 완성한다.
    """
    import re as _re
    sarif = rel(cfg, cfg["output_dir"] + "/" + sarif_name)
    if not sarif.exists():
        return 0
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    by_handler: dict[str, list] = {}
    for e in endpoints:
        h = (e.get("sources", {}).get("code") or {}).get("handler", "")
        if h:
            by_handler.setdefault(h, []).append(e)
    added = 0
    for run in doc.get("runs", []):
        for r in run.get("results", []):
            msg = r.get("message", {}).get("text", "")
            hm = _re.search(r"\\?\[handler=([\w.]+)\\?\]", msg)
            if not hm or hm.group(1) not in by_handler:
                continue
            loc = r.get("locations", [{}])[0].get("physicalLocation", {})
            uri = loc.get("artifactLocation", {}).get("uri", "")
            line = loc.get("region", {}).get("startLine")
            snippet = _source_line(cfg, uri, line)
            step = f"{Path(uri).name}:{line}  {snippet}" if snippet else f"{Path(uri).name}:{line}"
            clean = _re.sub(r"\s*\\?\[handler=[\w.]+\\?\]", "", msg)
            for e in by_handler[hm.group(1)]:
                for q in e.get("codeql", []):
                    if step not in q["steps"]:
                        q["steps"].append(step)
                        q["pii_response"] = clean
                        added += 1
    return added


def _source_line(cfg, uri: str, line: int) -> str:
    """소스 루트에서 해당 파일의 line을 읽어 공백 정리한 한 줄."""
    for base in ("../sources/crAPI/services/identity",
                 "../sources/crAPI/services/workshop",
                 "../sources/crAPI/services/community"):
        p = rel(cfg, base) / uri
        if p.exists():
            try:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
                if 1 <= line <= len(lines):
                    return " ".join(lines[line - 1].split())[:80]
            except OSError:
                return ""
    return ""
