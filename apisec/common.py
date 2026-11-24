"""공통 유틸: 설정 로드, 경로 정규화, 패턴 매칭."""
from __future__ import annotations

import fnmatch
import re
from pathlib import Path
from typing import Any

import yaml

TOOLKIT_ROOT = Path(__file__).resolve().parent.parent
HTTP_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE")


def load_config(path: str | Path | None = None) -> dict[str, Any]:
    p = Path(path) if path else TOOLKIT_ROOT / "config.yaml"
    cfg = yaml.safe_load(p.read_text(encoding="utf-8"))
    cfg["_root"] = p.resolve().parent
    return cfg


def rel(cfg: dict[str, Any], p: str) -> Path:
    """config.yaml 기준 상대 경로를 절대 경로로."""
    return (cfg["_root"] / p).resolve()


# ---------------------------------------------------------------- 경로 정규화

_PARAM_PATTERNS = [
    (re.compile(r"\(\?P<(\w+)>[^)]*\)"), r"{\1}"),  # Django regex: (?P<id>\d+)
    (re.compile(r"<(?:\w+:)?(\w+)>"), r"{\1}"),     # Django path(): <int:id>
    (re.compile(r"(?<=/):(\w+)"), r"{\1}"),          # Express/gin: /:id
]


def strip_literal(s: str) -> str:
    """Semgrep이 넘겨준 소스 리터럴("...", r"...", '...')에서 따옴표 제거."""
    s = s.strip()
    m = re.fullmatch(r"[rRbBuU]?(['\"])(.*)\1", s, flags=re.S)
    return m.group(2) if m else s


def canon(path: str) -> str:
    """프레임워크마다 다른 경로 표기를 하나의 템플릿 형식으로: /a/{id}/b"""
    p = path.strip()
    p = p.replace("^", "").replace("$", "")
    for rx, rep in _PARAM_PATTERNS:
        p = rx.sub(rep, p)
    p = "/" + p.lstrip("/")
    p = re.sub(r"/{2,}", "/", p)
    if len(p) > 1:
        p = p.rstrip("/")
    return p


def key(method: str, path: str) -> tuple[str, str]:
    """비교용 키: 파라미터 이름은 무시 ({postID} == {id})."""
    return method.upper(), re.sub(r"\{[^}]*\}", "{}", canon(path))


def template_regex(path: str) -> re.Pattern[str]:
    """템플릿 경로 → 실제 경로 매칭용 정규식."""
    parts = re.split(r"(\{[^}]*\})", canon(path))
    body = "".join("[^/]+" if x.startswith("{") else re.escape(x) for x in parts)
    return re.compile("^" + body + "/?$")


def ant_match(pattern: str, path: str) -> bool:
    """Spring/nginx 스타일 와일드카드 매칭 (/a/** , /a/*)."""
    pat = canon(pattern.replace("/**", "/__DSTAR__"))
    rx = re.escape(pat).replace("/__DSTAR__", "(/.*)?").replace(r"\*", "[^/]*")
    return re.fullmatch(rx, canon(path)) is not None or fnmatch.fnmatch(canon(path), pattern)


def param_names(path: str) -> list[str]:
    return re.findall(r"\{([^}]*)\}", path)
