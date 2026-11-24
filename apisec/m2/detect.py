"""개인정보(PII) 탐지기 — 1차 정규식 + JSON 필드 경로 추적.

응답 본문을 받아서 어떤 '필드 경로'에 어떤 종류의 PII가 있는지 찾는다.
- 값 기반(정규식): 이메일, 전화번호, 카드번호(Luhn), 좌표, JWT 등
- 구조 기반: JSON을 평탄화해 field path(a.b[0].c)를 만들고, 값마다 탐지기를 적용
- crAPI 특성: 커뮤니티 응답은 base64(JSON)라 자동 디코딩 후 재귀 탐지
"""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field
from typing import Any

# ---------------------------------------------------------------- 값 기반 탐지기

EMAIL = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
JWT = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
# 한국 휴대폰(01x) + 일반 하이픈 번호. 너무 느슨하면 가격·수량과 충돌하므로 자리수 고정.
PHONE_KR = re.compile(r"\b01[016789][-\s]?\d{3,4}[-\s]?\d{4}\b")
VIN = re.compile(r"\b[A-HJ-NPR-Z0-9]{17}\b")  # VIN은 I,O,Q 제외 17자
CARD = re.compile(r"\b(?:\d[ -]?){13,19}\b")
SSN_KR = re.compile(r"\b\d{6}[-\s]?[1-4]\d{6}\b")  # 주민등록번호 형태


def _luhn_ok(num: str) -> bool:
    d = [int(c) for c in re.sub(r"\D", "", num)]
    if not 13 <= len(d) <= 19:
        return False
    s, alt = 0, False
    for x in reversed(d):
        if alt:
            x *= 2
            if x > 9:
                x -= 9
        s += x
        alt = not alt
    return s % 10 == 0


# 종류: (정규식, 민감도 가중치, 값 검증 함수)
VALUE_DETECTORS: list[tuple[str, re.Pattern[str], int, Any]] = [
    ("SSN_KR", SSN_KR, 10, None),
    ("CARD", CARD, 9, _luhn_ok),
    ("JWT", JWT, 7, None),
    ("EMAIL", EMAIL, 4, None),
    ("PHONE", PHONE_KR, 5, None),
    ("VIN", VIN, 4, None),
]

# ---------------------------------------------------------------- 필드명 기반 힌트
# 값만으로는 애매하지만 필드명이 PII를 강하게 시사하는 경우 (예: latitude=37.40)
FIELD_HINTS: list[tuple[str, re.Pattern[str], int]] = [
    ("GEO", re.compile(r"(^|[._])(lat|latitude|lng|lon|longitude)$", re.I), 6),
    ("NAME", re.compile(r"(full_?name|fullname|^name$|nickname)", re.I), 3),
    ("ADDRESS", re.compile(r"(address|addr|zipcode|postal)", re.I), 5),
    ("VEHICLE", re.compile(r"(^|[._])(pincode|pin)$", re.I), 4),
    ("PHONE", re.compile(r"(^|[._])(number|phone|mobile|tel)$", re.I), 5),
    ("EMAIL", re.compile(r"(^|[._])(email|mail)$", re.I), 4),
    ("VEHICLE", re.compile(r"(^|[._])(vin|carid|vehicleid|car_id)$", re.I), 4),
]


@dataclass
class Finding:
    field_path: str
    pii_type: str
    detector: str  # "regex-value" | "field-name"
    weight: int
    sample: str

    def to_dict(self) -> dict[str, Any]:
        return {"field": self.field_path, "type": self.pii_type,
                "detector": self.detector, "weight": self.weight, "sample": self.sample}


def _mask(val: str) -> str:
    """증거용 마스킹: 앞뒤 일부만 남긴다."""
    v = str(val)
    if len(v) <= 6:
        return v[0] + "***" if v else ""
    return v[:3] + "***" + v[-2:]


def _try_b64_json(s: str) -> Any | None:
    """crAPI 커뮤니티 응답처럼 base64(JSON)이면 디코딩해서 반환."""
    if not isinstance(s, str) or len(s) < 16 or not re.fullmatch(r"[A-Za-z0-9+/=_-]+", s):
        return None
    try:
        raw = base64.b64decode(s + "=" * (-len(s) % 4), validate=False)
        obj = json.loads(raw.decode("utf-8"))
        return obj if isinstance(obj, (dict, list)) else None
    except (binascii.Error, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return None


def _flatten(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    out: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            out += _flatten(v, f"{prefix}.{k}" if prefix else str(k))
    elif isinstance(obj, list):
        for i, v in enumerate(obj[:20]):  # 배열은 앞 20개만 (중복 구조)
            out += _flatten(v, f"{prefix}[{i}]")
    else:
        out.append((prefix, obj))
    return out


def scan_value(path: str, value: Any, findings: list[Finding], depth: int = 0) -> None:
    if value is None or isinstance(value, bool):
        return
    sval = str(value)

    # base64(JSON) 중첩 → 재귀
    if isinstance(value, str) and depth < 3:
        inner = _try_b64_json(value)
        if inner is not None:
            for p, v in _flatten(inner, f"{path}<b64>"):
                scan_value(p, v, findings, depth + 1)
            return

    # 값 기반
    for name, rx, w, verify in VALUE_DETECTORS:
        for m in rx.finditer(sval):
            if verify and not verify(m.group()):
                continue
            findings.append(Finding(path, name, "regex-value", w, _mask(m.group())))
            break  # 같은 필드에 같은 종류 1회만

    # 필드명 기반 (값 기반에서 안 잡힌 종류만 보강)
    got = {f.pii_type for f in findings if f.field_path == path}
    for name, rx, w in FIELD_HINTS:
        last = path.split(".")[-1]
        if rx.search(last) and name not in got and sval.strip():
            findings.append(Finding(path, name, "field-name", w, _mask(sval)))


def detect(body_text: str) -> list[dict[str, Any]]:
    """응답 본문(문자열) → PII finding 목록."""
    findings: list[Finding] = []
    obj: Any
    try:
        obj = json.loads(body_text)
    except (json.JSONDecodeError, TypeError):
        # JSON이 아니면 전체 텍스트에 값 기반만
        scan_value("<body>", body_text, findings)
        return _dedup(findings)
    for path, value in _flatten(obj):
        scan_value(path, value, findings)
    return _dedup(findings)


def _dedup(findings: list[Finding]) -> list[dict[str, Any]]:
    seen = {}
    for f in findings:
        key = (f.field_path, f.pii_type)
        if key not in seen or f.detector == "regex-value":
            seen[key] = f
    return [f.to_dict() for f in seen.values()]
