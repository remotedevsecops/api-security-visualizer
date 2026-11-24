"""BOLA 검증 (읽기 전용 차분 테스트).

전제: 테스트 계정 A, B가 각자 소유한 객체가 있다.
방법: A 소유 객체를 대상으로 같은 요청을 세 주체로 보낸다.
  - owner A : 성공(200 + A의 식별 데이터)이 정상 기준선
  - other B : A의 객체에 접근 → B가 A의 식별 데이터를 받으면 BOLA 취약
  - anon    : 토큰 없이 접근 → 성공하면 무인증 취약

판정은 결정론적 코드가 한다(LLM 아님):
  "B/anon 응답 상태가 2xx 이고, 그 본문에 소유자 A의 식별값(이메일/번호/좌표 등)이 들어 있으면 취약."
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any

from apisec.m3.runner import Attempt, GuardedRunner

# A 소유를 가리키는 식별값(소유자 응답에서 추출) — 이 값이 B/anon 응답에 나오면 유출
OWNER_SIGNALS = ("email", "number", "latitude", "longitude", "vin", "fullName", "full_name")


@dataclass
class BolaCase:
    name: str
    method: str
    url_template: str          # {obj} 자리에 객체 id
    owner: str                 # 'a' | 'b'
    obj_id: str
    signals: list[str] = field(default_factory=list)  # 소유자 응답에서 뽑은 식별값


@dataclass
class BolaResult:
    case: str
    method: str
    url: str
    owner: str
    baseline_status: int | None
    cross_status: int | None
    anon_status: int | None
    verdict: str               # vulnerable_bola | vulnerable_no_auth | not_vulnerable | inconclusive
    leaked_signals: list[str]
    evidence: dict[str, Any]


def _extract_signals(body: str) -> dict[str, str]:
    """소유자 응답에서 식별값을 뽑는다(마스킹 없이 내부 비교용, 로그엔 안 남김)."""
    try:
        obj = json.loads(body)
    except (json.JSONDecodeError, TypeError):
        return {}
    found: dict[str, str] = {}

    def walk(o: Any) -> None:
        if isinstance(o, dict):
            for k, v in o.items():
                if k in OWNER_SIGNALS and isinstance(v, (str, int, float)) and str(v).strip():
                    found.setdefault(k, str(v))
                walk(v)
        elif isinstance(o, list):
            for v in o:
                walk(v)

    walk(obj)
    return found


def _mask(v: str) -> str:
    return v[:3] + "***" + v[-2:] if len(v) > 6 else v[0] + "***"


def verify(runner: GuardedRunner, base: str, cases: list[BolaCase]) -> list[BolaResult]:
    results = []
    other = {"a": "b", "b": "a"}
    for c in cases:
        url = base + c.url_template.replace("{obj}", c.obj_id)
        # 1) 소유자 기준선
        a_owner = runner.request(c.owner, c.method, url, note=f"BOLA baseline ({c.name})")
        owner_body = getattr(a_owner, "_body", "") or a_owner.resp_summary
        signals = _extract_signals(owner_body) if a_owner.status and a_owner.status < 300 else {}

        # 2) 다른 사용자
        b = other[c.owner]
        a_cross = runner.request(b, c.method, url, note=f"BOLA cross-access ({c.name})")
        cross_body = getattr(a_cross, "_body", "") or a_cross.resp_summary

        # 3) 비로그인
        a_anon = runner.request("anon", c.method, url, note=f"BOLA anon ({c.name})")
        anon_body = getattr(a_anon, "_body", "") or a_anon.resp_summary

        leaked = [k for k, v in signals.items() if v and v in cross_body]
        anon_leaked = [k for k, v in signals.items() if v and v in anon_body]

        if a_anon.status and a_anon.status < 300 and anon_leaked:
            verdict = "vulnerable_no_auth"
        elif a_cross.status and a_cross.status < 300 and leaked:
            verdict = "vulnerable_bola"
        elif not signals:
            verdict = "inconclusive"
        else:
            verdict = "not_vulnerable"

        results.append(BolaResult(
            case=c.name, method=c.method, url=url, owner=c.owner,
            baseline_status=a_owner.status, cross_status=a_cross.status, anon_status=a_anon.status,
            verdict=verdict,
            leaked_signals=sorted(set(leaked) | set(anon_leaked)),
            evidence={
                "owner_signals": {k: _mask(v) for k, v in signals.items()},
                "cross_actor": b,
                "cross_leaked": {k: _mask(signals[k]) for k in leaked},
                "anon_leaked": {k: _mask(signals[k]) for k in anon_leaked},
            },
        ))
    return results
