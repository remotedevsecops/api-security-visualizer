"""LLM 2차 판정 어댑터 (선택). 키가 없으면 None을 반환해 자동 비활성화.

정규식으로는 애매한 필드(필드명 힌트만 있는 것)를 LLM에 보내
"개인정보인지 / 종류 / 근거"를 JSON으로 받는다.

환경변수:
  LLM_PROVIDER = claude | openai | gemini   (기본 claude)
  ANTHROPIC_API_KEY / OPENAI_API_KEY / GEMINI_API_KEY
  LLM_MODEL (선택)
"""
from __future__ import annotations

import json
import os
import re
from typing import Any

SYSTEM = (
    "You are a data-privacy classifier for API responses. "
    "Given field paths and a sample JSON body, decide for each field whether its value is "
    "personal or sensitive information (PII). Reply ONLY with a JSON object mapping each field "
    'path to {"is_pii": bool, "category": str, "rationale": str (<=15 words, Korean)}. '
    "Categories: EMAIL, PHONE, NAME, ADDRESS, GEO, VEHICLE, FINANCIAL, HEALTH, OTHER, NONE."
)


def _prompt(method: str, path: str, fields: list[dict], body: str) -> str:
    names = [f["field"] for f in fields]
    return (f"Endpoint: {method} {path}\n"
            f"Fields to classify: {json.dumps(names, ensure_ascii=False)}\n"
            f"Sample response body (truncated):\n{body[:1500]}")


class _Base:
    def classify(self, method: str, path: str, fields: list[dict], body: str) -> dict[str, dict]:
        raise NotImplementedError

    @staticmethod
    def _parse(text: str) -> dict[str, dict]:
        m = re.search(r"\{.*\}", text, re.S)
        if not m:
            return {}
        try:
            return json.loads(m.group())
        except json.JSONDecodeError:
            return {}


class _Claude(_Base):
    def __init__(self, key: str, model: str):
        import anthropic  # noqa
        self.c = anthropic.Anthropic(api_key=key)
        self.model = model

    def classify(self, method, path, fields, body):
        r = self.c.messages.create(
            model=self.model, max_tokens=800, system=SYSTEM,
            messages=[{"role": "user", "content": _prompt(method, path, fields, body)}],
        )
        return self._parse("".join(b.text for b in r.content if b.type == "text"))


class _OpenAI(_Base):
    def __init__(self, key: str, model: str):
        import openai  # noqa
        self.c = openai.OpenAI(api_key=key)
        self.model = model

    def classify(self, method, path, fields, body):
        r = self.c.chat.completions.create(
            model=self.model, max_tokens=800,
            messages=[{"role": "system", "content": SYSTEM},
                      {"role": "user", "content": _prompt(method, path, fields, body)}],
        )
        return self._parse(r.choices[0].message.content or "")


def get_adapter(cfg: dict[str, Any]) -> _Base | None:
    provider = os.getenv("LLM_PROVIDER", "claude").lower()
    table = {
        "claude": ("ANTHROPIC_API_KEY", "claude-haiku-4-5", _Claude),
        "openai": ("OPENAI_API_KEY", "gpt-4o-mini", _OpenAI),
    }
    if provider not in table:
        print(f"[llm] 알 수 없는 provider={provider} — LLM 비활성화")
        return None
    env, default_model, cls = table[provider]
    key = os.getenv(env)
    if not key:
        print(f"[llm] {env} 없음 — LLM 2차 판정 생략 (정규식만)")
        return None
    try:
        return cls(key, os.getenv("LLM_MODEL", default_model))
    except ImportError as e:
        print(f"[llm] {provider} SDK 미설치({e.name}) — LLM 생략")
        return None
