"""가드레일: 모든 요청은 보내기 전에 이 계층을 통과해야 한다.

각 가드는 독립적으로 동작하고, 통과/차단 여부와 사유를 남긴다.
차단된 요청도 감사 로그에 기록된다(재현·책임추적).

1. 스코프 화이트리스트 : config의 허용 호스트 밖은 차단
2. 행위 화이트리스트   : 허용 메서드만(기본 읽기 계열). 파괴적 행위 기본 차단
3. 레이트 리밋         : 초당 요청 상한. 초과 시 대기
4. 드라이런            : 실제 요청 없이 계획만
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit


@dataclass
class Decision:
    allowed: bool
    guard: str | None = None  # 차단한 가드 이름
    reason: str = ""


@dataclass
class Guardrails:
    allowed_hosts: set[str]
    allowed_methods: set[str]
    rate_per_sec: float = 3.0
    dry_run: bool = False
    _last: float = field(default=0.0, repr=False)

    @classmethod
    def from_config(cls, cfg: dict[str, Any], m3: dict[str, Any]) -> "Guardrails":
        return cls(
            allowed_hosts=set(cfg["scope"]["allowed_hosts"]),
            allowed_methods={m.upper() for m in m3.get("allowed_methods", ["GET"])},
            rate_per_sec=float(m3.get("rate_per_sec", 3.0)),
            dry_run=bool(m3.get("dry_run", False)),
        )

    def check(self, method: str, url: str) -> Decision:
        host = urlsplit(url).hostname or ""
        if host not in self.allowed_hosts:
            return Decision(False, "scope", f"허용 호스트 밖: {host} (허용: {sorted(self.allowed_hosts)})")
        if method.upper() not in self.allowed_methods:
            return Decision(False, "action", f"허용되지 않은 메서드: {method} (허용: {sorted(self.allowed_methods)})")
        return Decision(True, None, "통과")

    def throttle(self) -> None:
        """레이트 리밋: 간격이 부족하면 대기."""
        if self.rate_per_sec <= 0:
            return
        gap = 1.0 / self.rate_per_sec
        wait = self._last + gap - time.monotonic()
        if wait > 0:
            time.sleep(wait)
        self._last = time.monotonic()
