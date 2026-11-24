"""가드레일을 통과한 요청만 내보내는 클라이언트 + 감사 로그.

모든 시도(차단 포함)를 audit.log(JSONL)에 append 한다.
증거 저장을 위해 요청/응답 요약을 남기되, 토큰·민감값은 마스킹한다.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from apisec.m3.guardrails import Decision, Guardrails


def _mask_headers(h: dict[str, str]) -> dict[str, str]:
    out = {}
    for k, v in h.items():
        if k.lower() == "authorization":
            out[k] = v[:14] + "…(masked)" if v else v
        else:
            out[k] = v
    return out


@dataclass
class Attempt:
    actor: str
    method: str
    url: str
    decision: Decision
    status: int | None = None
    resp_summary: str = ""
    elapsed_ms: int | None = None
    note: str = ""


class GuardedRunner:
    def __init__(self, guards: Guardrails, audit_path: Path, actor_tokens: dict[str, str]):
        self.g = guards
        self.audit_path = audit_path
        self.actor_tokens = actor_tokens  # actor 이름 -> bearer 토큰 ("anon"은 토큰 없음)
        self.audit_path.parent.mkdir(parents=True, exist_ok=True)
        self._fh = audit_path.open("a", encoding="utf-8")
        self._client = httpx.Client(timeout=15, follow_redirects=False)
        self.counts = {"sent": 0, "blocked": 0, "dry": 0}

    def _log(self, a: Attempt) -> None:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
            "actor": a.actor, "method": a.method, "url": a.url,
            "allowed": a.decision.allowed, "guard": a.decision.guard,
            "reason": a.decision.reason, "status": a.status,
            "resp": a.resp_summary, "elapsed_ms": a.elapsed_ms, "note": a.note,
        }
        self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")
        self._fh.flush()

    def request(self, actor: str, method: str, url: str, *, body: dict | None = None,
                note: str = "") -> Attempt:
        dec = self.g.check(method, url)
        att = Attempt(actor, method, url, dec, note=note)
        if not dec.allowed:
            self.counts["blocked"] += 1
            self._log(att)
            return att
        if self.g.dry_run:
            att.note = (note + " [dry-run: 전송 안 함]").strip()
            self.counts["dry"] += 1
            self._log(att)
            return att

        headers = {}
        tok = self.actor_tokens.get(actor)
        if tok:
            headers["Authorization"] = f"Bearer {tok}"
        self.g.throttle()
        t0 = time.monotonic()
        try:
            r = self._client.request(method, url, headers=headers,
                                     json=body if body is not None else None)
            att.status = r.status_code
            att.elapsed_ms = int((time.monotonic() - t0) * 1000)
            txt = r.text or ""
            att.resp_summary = txt[:500]
            att._body = txt  # 검증 로직이 참조(로그엔 요약만)
            att._headers = _mask_headers(dict(r.request.headers))
        except Exception as e:  # noqa
            att.status = -1
            att.resp_summary = f"error: {type(e).__name__}: {e}"
        self.counts["sent"] += 1
        self._log(att)
        return att

    def close(self) -> None:
        self._client.close()
        self._fh.close()
